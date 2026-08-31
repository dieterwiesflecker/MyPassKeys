using System.Text.Json.Serialization;
using System.Threading.RateLimiting;
using Microsoft.AspNetCore.Cors.Infrastructure;
using MyPassKeys;
using StackExchange.Redis;
/*using Microsoft.EntityFrameworkCore;*/
using Fido2NetLib;
using Fido2NetLib.Objects;
using Marten;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.HttpOverrides;
using Scalar.AspNetCore;

var builder = WebApplication.CreateSlimBuilder(args);

builder.Logging.AddConfiguration(builder.Configuration.GetSection("Logging"));
builder.Logging.AddConsole();

builder.Services.ConfigureHttpJsonOptions(options =>
{
  options.SerializerOptions.TypeInfoResolverChain.Insert(0, AppJsonSerializerContext.Default);
  // Portal contract: the frontend reads camelCase fields (myRole, admins, ownerDisplayName, ...).
  // Library types (Fido2NetLib WebAuthn options) carry explicit [JsonPropertyName] which wins over
  // the policy, so their wire format is unaffected.
  options.SerializerOptions.PropertyNamingPolicy = System.Text.Json.JsonNamingPolicy.CamelCase;
  options.SerializerOptions.PropertyNameCaseInsensitive = true;
});

// --- Redis ---
builder.Services.AddSingleton<IConnectionMultiplexer>(_ =>
{
  //var settings = sp.GetRequiredService<IConfiguration>();
  var connectionString = builder.Configuration.GetConnectionString("Redis");
  if (string.IsNullOrEmpty(connectionString))
    throw new InvalidOperationException("RedisConnectionString is not configured.");

  var options = ConfigurationOptions.Parse(connectionString);
  options.AbortOnConnectFail = false; // Allow retries if Redis is not ready yet
  return ConnectionMultiplexer.Connect(options);
});

// Learn more about configuring OpenAPI at https://aka.ms/aspnet/openapi
builder.Services.AddOpenApi();

/*builder.Services.AddFido2(options =>
{
  // scope of passkey
  options.ServerDomain = builder.Configuration["Fido2:ServerDomain"] ?? "localhost";
  // friendly name
  options.ServerName = "MyPassKeys";
  // frontapp url (schema + hostname + port)
  options.Origins =
    new HashSet<string>((builder.Configuration["Fido2:Origins"] ?? "http://localhost:5173,http://localhost:8080").Split(','));
  options.TimestampDriftTolerance = 300000;
});*/

/*builder.Services.AddDbContext<AppDbContext>(options =>
{
    var connectionString = builder.Configuration.GetConnectionString("Postgres");
    options.UseNpgsql(connectionString);
    //options.UseModel(MyPassKeys.CompiledModels.AppDbContextModel.Instance);
});*/

// --- Marten Configuration ---
builder.Services.AddMarten(options =>
{
  var connectionString = builder.Configuration.GetConnectionString("Postgres");
    options.Connection(connectionString!);
    options.Schema.For<Fido2AppUser>()
      .Identity(x => x.Id)
      .Index(x => new { x.TenantId, x.Username }, idx => idx.IsUnique = true)
      // Cross-tenant lookup: "my tenants" / memberships query by Username across all tenants.
      .Index(x => x.Username);
    options.Schema.For<Fido2StoredCredential>()
      .Identity(x => x.Id)
      .Index(x => new { x.TenantId, x.UserId });
    options.Schema.For<Fido2RefreshToken>()
      .Identity(x => x.Id)
      .Index(x => new { x.TenantId, x.Token })
      .Index(x => new { x.TenantId, x.UserId });
    options.Schema.For<Tenant>()
      .Identity(x => x.Id)
      .GinIndexJsonData() // enables fast @> containment queries on AllowedOrigins and Hosts arrays
      // ServerName is globally unique (case-insensitive) because it doubles as an X-Tenant-ID
      // selector — two tenants sharing a name would make ServerName-based resolution ambiguous.
      .Index(x => x.ServerName, idx =>
      {
        idx.IsUnique = true;
        idx.Casing = Marten.Schema.ComputedIndex.Casings.Lower;
      });
    options.Schema.For<TenantRole>()
      .Identity(x => x.Id)
      .Index(x => new { x.TenantId, x.Name }, idx => idx.IsUnique = true);
    options.Schema.For<TenantGroup>()
      .Identity(x => x.Id)
      .GinIndexJsonData() // enables fast @> containment queries on MemberUserIds / MemberGroupIds / Roles
      .Index(x => new { x.TenantId, x.Name }, idx => idx.IsUnique = true);
}).UseLightweightSessions();

builder.Services.AddHttpContextAccessor();

// Services for multi-tenancy support
builder.Services.AddScoped<ITenantService, TenantService>();
builder.Services.AddScoped<IFido2Factory, Fido2Factory>();

builder.Services.AddScoped<Fido2Service>();

// Register the interface. Change implementation here to swap between EF Core and Marten.
// builder.Services.AddScoped<IFido2DbService, Fido2EfCoreDbService>();
builder.Services.AddScoped<IFido2DbService, Fido2MartenDbService>();

builder.Services.AddScoped<TokenService>();

// Envelope encryption for tenant JWT signing private keys. The KEK comes from configuration
// (MyPassKeys:KeyEncryptionKey — environment / secret store, never the database), so a DB or
// Redis dump alone cannot recover signing keys and forge tokens. Validated at startup: a
// missing or malformed KEK fails fast here rather than at first token issuance.
builder.Services.AddSingleton<IKeyProtector>(sp =>
  AesGcmKeyProtector.FromConfiguration(sp.GetRequiredService<IConfiguration>()));

// HMAC integrity seals over security-critical documents (users' roles, groups, role catalog,
// credentials, refresh tokens, sensitive tenant fields). MAC keys are HKDF-derived from the
// same KEK ring, so no extra secret is provisioned. Sealing/verification is centralized in
// Fido2MartenDbService (+ TenantService for Redis cache hits); a document altered by a direct
// DB write fails verification and the request dies with DocumentTamperedException.
builder.Services.AddSingleton<IDocumentIntegrity>(sp =>
  HmacDocumentIntegrity.FromConfiguration(sp.GetRequiredService<IConfiguration>()));

// Rollback protection: each sealed write bumps the document's Version (inside the MAC) and
// anchors it in Redis; reading an older, validly-sealed copy then fails the anchor check.
// After restoring a Postgres backup, start ONCE with MyPassKeys:ResetVersionAnchors=true.
builder.Services.AddSingleton<IVersionAnchor, RedisVersionAnchor>();

builder.Services.AddHttpClient();
builder.Services.AddSingleton<EmailService>();
builder.Services.AddHostedService<BackgroundKeyManagementService>();


// --- Rate Limiting ---
// "auth": 10 requests/min per IP — covers the FIDO2 ceremony endpoints (login + registration).
// "refresh": 20 requests/min per IP — token refresh can be called more frequently by active clients.
builder.Services.AddRateLimiter(options =>
{
    options.RejectionStatusCode = StatusCodes.Status429TooManyRequests;

    options.AddPolicy("auth", httpContext =>
        RateLimitPartition.GetFixedWindowLimiter(
            partitionKey: httpContext.Connection.RemoteIpAddress?.ToString() ?? "unknown",
            factory: _ => new FixedWindowRateLimiterOptions
            {
                PermitLimit = 10,
                Window = TimeSpan.FromMinutes(1),
                QueueProcessingOrder = QueueProcessingOrder.OldestFirst,
                QueueLimit = 0
            }));

    options.AddPolicy("refresh", httpContext =>
        RateLimitPartition.GetFixedWindowLimiter(
            partitionKey: httpContext.Connection.RemoteIpAddress?.ToString() ?? "unknown",
            factory: _ => new FixedWindowRateLimiterOptions
            {
                PermitLimit = 20,
                Window = TimeSpan.FromMinutes(1),
                QueueProcessingOrder = QueueProcessingOrder.OldestFirst,
                QueueLimit = 0
            }));

    options.AddPolicy("email", httpContext =>
        RateLimitPartition.GetFixedWindowLimiter(
            partitionKey: httpContext.Connection.RemoteIpAddress?.ToString() ?? "unknown",
            factory: _ => new FixedWindowRateLimiterOptions
            {
                PermitLimit = 5,
                Window = TimeSpan.FromMinutes(1),
                QueueProcessingOrder = QueueProcessingOrder.OldestFirst,
                QueueLimit = 0
            }));

    // "tenant-create": 5 new tenants/hour per IP. Self-service tenant creation mints an ECDSA
    // key pair and seeds roles/users, so it is far more expensive than a normal request — this
    // caps spam/resource-exhaustion. Partitioned by IP because the limiter runs before auth.
    // A per-user count cap (MyPassKeys:MaxTenantsPerUser) is enforced inside the endpoint.
    options.AddPolicy("tenant-create", httpContext =>
        RateLimitPartition.GetFixedWindowLimiter(
            partitionKey: httpContext.Connection.RemoteIpAddress?.ToString() ?? "unknown",
            factory: _ => new FixedWindowRateLimiterOptions
            {
                PermitLimit = 5,
                Window = TimeSpan.FromHours(1),
                QueueProcessingOrder = QueueProcessingOrder.OldestFirst,
                QueueLimit = 0
            }));
});

builder.Services.AddAuthentication("Dpop")
    .AddScheme<AuthenticationSchemeOptions, Fido2TokenAuthenticationHandler>("Dpop", null);

builder.Services.AddAuthorization();

// 1. Add CORS services
builder.Services.AddCors(options =>
{
  options.AddPolicy("AllowFrontend",
    policy =>
    {
      // Replace with your actual frontend URL (e.g., http://localhost:5173)
      // This acts as a fallback if the TenantService doesn't return a specific policy
      policy.WithOrigins("http://localhost:5173")
        .AllowAnyHeader()
        .AllowAnyMethod()
        .AllowCredentials(); // Necessary if you are sending cookies or auth headers
    });
});

// Register custom CORS policy provider to handle tenant-specific origins dynamically
builder.Services.AddTransient<ICorsPolicyProvider, TenantCorsPolicyProvider>();

var app = builder.Build();

// --- Bootstrap + invariant: management tenant + bootstrap owner ---
// Runs every startup. On a fresh DB it seeds the management tenant; on every startup it
// guarantees that the user configured in Tenant:BootstrapOwnerEmail exists in the management
// tenant and holds the tenantadmin role — so the operator can always log into the management
// portal even if every other tenantadmin lost access.
using (var bootstrapScope = app.Services.CreateScope())
{
  var bootstrapDb = bootstrapScope.ServiceProvider.GetRequiredService<IFido2DbService>();
  var bootstrapRedis = bootstrapScope.ServiceProvider.GetRequiredService<IConnectionMultiplexer>();
  var bootstrapKeyProtector = bootstrapScope.ServiceProvider.GetRequiredService<IKeyProtector>();
  var bootstrapIntegrity = bootstrapScope.ServiceProvider.GetRequiredService<IDocumentIntegrity>();
  var bootstrapAnchors = bootstrapScope.ServiceProvider.GetRequiredService<IVersionAnchor>();
  // One-shot escape hatch for deliberate Postgres restores: skip anchor CHECKS this startup and
  // re-adopt the restored versions as the new baseline. Remove the flag again afterwards.
  var resetAnchors = app.Configuration.GetValue("MyPassKeys:ResetVersionAnchors", false);
  if (resetAnchors)
    app.Logger.LogWarning(
      "MyPassKeys:ResetVersionAnchors is set — version anchors are being re-adopted from the " +
      "database WITHOUT rollback checks. Remove this flag after this startup.");

  // --- Integrity-seal migration (MUST run before any verifying read below) ---
  // Uses the raw Marten session because IFido2DbService reads now verify seals — legacy
  // documents don't have one yet. Idempotent: seals unsealed documents (legacy, pre-integrity),
  // re-seals valid previous-KEK seals after verifying them, and deliberately SKIPS documents
  // whose seal fails verification (re-sealing would bless tampering — they keep failing at
  // read time, which is the alarm). After the very first migration the "sealed" count must
  // stay 0; a nonzero count later means something wrote to the DB behind the app's back.
  {
    var martenSession = bootstrapScope.ServiceProvider.GetRequiredService<Marten.IDocumentSession>();
    var sealedTenants = new List<Tenant>();

    var anchorQueue = new List<object>();

    async Task SealAllAsync<T>() where T : class
    {
      int sealedCount = 0, rekeyed = 0, tampered = 0, rolledBack = 0;
      foreach (var doc in await martenSession.Query<T>().ToListAsync())
      {
        bool changed;
        if (!bootstrapIntegrity.HasSeal(doc))
        {
          bootstrapIntegrity.Seal(doc);
          martenSession.Store(doc);
          sealedCount++;
          changed = true;
        }
        else
        {
          try { bootstrapIntegrity.Verify(doc); }
          catch (DocumentTamperedException ex)
          {
            tampered++;
            app.Logger.LogCritical(ex, "Integrity migration: tampered document left untouched.");
            continue;
          }

          // Anchor check: a validly-sealed document may still be a restored OLDER copy. With
          // ResetVersionAnchors set, skip the check and re-adopt (deliberate backup restore).
          if (!resetAnchors)
          {
            try { await bootstrapAnchors.CheckAsync(doc); }
            catch (DocumentTamperedException ex)
            {
              rolledBack++;
              app.Logger.LogCritical(ex, "Integrity migration: rolled-back document left untouched.");
              continue;
            }
          }

          changed = !bootstrapIntegrity.IsSealedWithCurrentKey(doc);
          if (changed)
          {
            bootstrapIntegrity.Seal(doc);
            martenSession.Store(doc);
            rekeyed++;
          }
        }
        // Anchors are recorded after SaveChanges — never anchor a version that wasn't persisted.
        anchorQueue.Add(doc);
        if (changed && doc is Tenant t)
          sealedTenants.Add(t);
      }
      if (sealedCount > 0)
        app.Logger.LogWarning("Integrity migration: sealed {Count} previously-unsealed {Type} document(s).", sealedCount, typeof(T).Name);
      if (rekeyed > 0)
        app.Logger.LogInformation("Integrity migration: re-sealed {Count} {Type} document(s) under the current key.", rekeyed, typeof(T).Name);
      if (tampered > 0)
        app.Logger.LogCritical("Integrity migration: {Count} {Type} document(s) FAILED verification — investigate immediately.", tampered, typeof(T).Name);
      if (rolledBack > 0)
        app.Logger.LogCritical("Integrity migration: {Count} {Type} document(s) FAILED the rollback check — investigate immediately.", rolledBack, typeof(T).Name);
    }

    await SealAllAsync<Tenant>();
    await SealAllAsync<Fido2AppUser>();
    await SealAllAsync<Fido2StoredCredential>();
    await SealAllAsync<TenantRole>();
    await SealAllAsync<TenantGroup>();
    await SealAllAsync<Fido2RefreshToken>();
    await martenSession.SaveChangesAsync();

    foreach (var doc in anchorQueue)
      await bootstrapAnchors.RecordAsync(doc);

    // Drop cached copies of re-sealed tenants so no unsealed copy outlives the migration.
    foreach (var t in sealedTenants)
      await TenantEndpoints.InvalidateTenantCacheAsync(bootstrapRedis, t);
  }
  var deploymentHosts = app.Configuration.GetSection("MyPassKeys:DeploymentHosts").Get<string[]>() ?? [];

  if (deploymentHosts.Length == 0)
    throw new InvalidOperationException(
      "MyPassKeys:DeploymentHosts must be configured with at least one hostname (e.g. ['auth.example.com', 'localhost:5205']).");

  var management = await bootstrapDb.GetManagementTenantAsync();
  if (management is null)
  {
    var bootstrapOrigins = (app.Configuration.GetSection("MyPassKeys:BootstrapManagementOrigins").Get<string[]>() ?? [])
      .Where(o => !string.IsNullOrWhiteSpace(o))
      .Select(o => o.TrimEnd('/'))
      .Distinct(StringComparer.OrdinalIgnoreCase)
      .ToArray();
    management = new Tenant
    {
      IsManagementTenant = true,
      Hosts = [],
      ServerName = "MyPassKeys Management",
      AllowedOrigins = bootstrapOrigins,
      // Env vars set to an empty string (e.g. ${BOOTSTRAP_MANAGEMENT_AUDIENCE:-} in compose.prod.yaml)
      // read back as "" rather than null, so treat blank as "not set" and fall back to the derived default.
      JwtIssuer = app.Configuration["MyPassKeys:BootstrapManagementIssuer"] is { } issuer && !string.IsNullOrWhiteSpace(issuer)
                  ? issuer
                  : $"https://{deploymentHosts[0]}",
      JwtAudience = app.Configuration["MyPassKeys:BootstrapManagementAudience"] is { } audience && !string.IsNullOrWhiteSpace(audience)
                    ? audience
                    : $"api://{deploymentHosts[0]}",
      JwtKeys = [TenantEndpoints.CreateKeyEntry(bootstrapKeyProtector)]
    };
    await bootstrapDb.UpsertTenantAsync(management);
    foreach (var role in TenantRoleModel.BuiltInRoles())
      await bootstrapDb.UpsertRoleForTenantAsync(management.Id, role);
    await bootstrapRedis.GetDatabase().KeyDeleteAsync("Tenant:management");

    app.Logger.LogInformation(
      "Seeded management tenant {TenantId}. Reachable via {Origins}.",
      management.Id,
      bootstrapOrigins.Length == 0 ? "(no origins configured — set MyPassKeys:BootstrapManagementOrigins)" : string.Join(", ", bootstrapOrigins));
  }

  // Backfill: every existing tenant gets the built-in role catalog (idempotent, no-op on a
  // freshly-created tenant since we just seeded its roles above). For a built-in role that
  // already exists we reconcile its permission set — union in any newly-introduced canonical
  // permissions (e.g. adding 'roles:read' to useradmin) without removing extras an admin added.
  foreach (var t in await bootstrapDb.GetAllTenantsAsync())
  {
    var existingRoles = (await bootstrapDb.GetRolesForTenantAsync(t.Id)).ToDictionary(r => r.Name);
    foreach (var role in TenantRoleModel.BuiltInRoles())
    {
      if (!existingRoles.TryGetValue(role.Name, out var existing))
      {
        await bootstrapDb.UpsertRoleForTenantAsync(t.Id, role);
        continue;
      }

      var missing = role.Permissions.Except(existing.Permissions).ToList();
      if (missing.Count > 0)
      {
        existing.Permissions = existing.Permissions.Concat(missing).ToList();
        existing.UpdatedAt = DateTime.UtcNow;
        await bootstrapDb.UpsertRoleForTenantAsync(t.Id, existing);
      }
    }
  }

  // Encrypt-at-rest migration (idempotent, runs every startup): re-encrypt any signing key
  // stored as plaintext (pre-encryption deployments) or under a previous KEK
  // (MyPassKeys:PreviousKeyEncryptionKeys during KEK rotation) with the current KEK. The Redis
  // tenant cache is invalidated so no plaintext copy outlives the migration by more than a read.
  foreach (var t in await bootstrapDb.GetAllTenantsAsync())
  {
    var reEncrypted = 0;
    foreach (var entry in t.JwtKeys)
    {
      if (bootstrapKeyProtector.IsProtectedWithCurrentKey(entry.PrivateKey)) continue;
      entry.PrivateKey = bootstrapKeyProtector.Protect(
        bootstrapKeyProtector.Unprotect(entry.PrivateKey, entry.Kid), entry.Kid);
      reEncrypted++;
    }
    if (reEncrypted > 0)
    {
      await bootstrapDb.UpsertTenantAsync(t);
      await TenantEndpoints.InvalidateTenantCacheAsync(bootstrapRedis, t);
      app.Logger.LogInformation(
        "Encrypted {Count} signing key(s) at rest for tenant {TenantId}.", reEncrypted, t.Id);
    }
  }

  // Invariant: the configured bootstrap owner is a tenantadmin in the management tenant. The
  // user record may not exist yet (they haven't registered a passkey) — we create a stub so the
  // FIDO2 registration flow finds an invite-style record on first login. Without this, a fresh
  // deployment has no way back in after a misconfiguration.
  var bootstrapEmail = app.Configuration["Tenant:BootstrapOwnerEmail"]?.NormalizeUsername();
  if (!string.IsNullOrEmpty(bootstrapEmail))
  {
    var existing = await bootstrapDb.GetUserByUsernameForTenantAsync(management.Id, bootstrapEmail);
    if (existing == null)
    {
      await bootstrapDb.UpsertUserForTenantAsync(management.Id, new Fido2AppUser
      {
        Username = bootstrapEmail,
        DisplayName = bootstrapEmail,
        Roles = [BuiltInTenantRoles.TenantAdmin]
      });
      app.Logger.LogInformation(
        "Bootstrap: seeded tenantadmin user {Email} in management tenant {TenantId}.",
        bootstrapEmail, management.Id);
    }
    else if (!TenantRoleModel.IsTenantAdmin(existing.Roles))
    {
      existing.Roles.Add(BuiltInTenantRoles.TenantAdmin);
      await bootstrapDb.UpsertUserForTenantAsync(management.Id, existing);
      app.Logger.LogInformation(
        "Bootstrap: promoted existing user {Email} to tenantadmin in management tenant {TenantId}.",
        bootstrapEmail, management.Id);
    }
  }
}

//app.UseSession();

/*if (app.Environment.IsDevelopment())
{
  DbInitializer.EnsureDatabase(app);
  Console.WriteLine("Success: Db schema initialized for Development!");
}*/

// Forward headers from reverse proxies (Cloudflare, etc.) so RemoteIpAddress
// reflects the real client IP for rate limiting, not the proxy's IP.
//
// SECURITY: Only proxies in ForwardedHeaders:KnownNetworks (CIDR) and
// ForwardedHeaders:KnownProxies (single IPs) are trusted to set X-Forwarded-*.
// If these are unset we fall back to loopback only, which means direct callers
// CANNOT spoof X-Forwarded-For to bypass IP-based rate limiting.
var forwardedHeadersOptions = new ForwardedHeadersOptions
{
  ForwardedHeaders = ForwardedHeaders.XForwardedFor | ForwardedHeaders.XForwardedProto | ForwardedHeaders.XForwardedHost,
  // Allow longer chains (Cloudflare -> Caddy -> app) to be parsed.
  ForwardLimit = builder.Configuration.GetValue("ForwardedHeaders:ForwardLimit", 2)
};

var knownNetworks = builder.Configuration.GetSection("ForwardedHeaders:KnownNetworks").Get<string[]>() ?? [];
var knownProxies = builder.Configuration.GetSection("ForwardedHeaders:KnownProxies").Get<string[]>() ?? [];

if (knownNetworks.Length > 0 || knownProxies.Length > 0)
{
  forwardedHeadersOptions.KnownIPNetworks.Clear();
  forwardedHeadersOptions.KnownProxies.Clear();

  foreach (var cidr in knownNetworks)
  {
    if (System.Net.IPNetwork.TryParse(cidr, out var network))
      forwardedHeadersOptions.KnownIPNetworks.Add(network);
    else
      throw new InvalidOperationException($"Invalid CIDR in ForwardedHeaders:KnownNetworks: '{cidr}'");
  }

  foreach (var ip in knownProxies)
  {
    if (System.Net.IPAddress.TryParse(ip, out var parsed))
      forwardedHeadersOptions.KnownProxies.Add(parsed);
    else
      throw new InvalidOperationException($"Invalid IP in ForwardedHeaders:KnownProxies: '{ip}'");
  }
}
// else: defaults to loopback only — safe out of the box.

app.UseForwardedHeaders(forwardedHeadersOptions);

// Ambiguous-tenant gate: tenant resolution throws AmbiguousTenantException when an Origin maps
// to more than one tenant and no X-Tenant-ID disambiguates it. Convert that to a clean 409 so
// clients learn they must send X-Tenant-ID (plain text to stay AOT-serialization-safe).
app.Use(async (context, next) =>
{
  try
  {
    await next();
  }
  catch (AmbiguousTenantException ex)
  {
    if (!context.Response.HasStarted)
    {
      context.Response.Clear();
      context.Response.StatusCode = StatusCodes.Status409Conflict;
      context.Response.ContentType = "text/plain";
      await context.Response.WriteAsync(ex.Message);
    }
  }
});

// Host gate: reject requests whose Host is neither a deployment host (from config) nor a
// per-tenant custom subdomain (Tenant.Hosts). Protects against Host-header spoofing and
// catches misconfigured DNS early with a clear 404.
var deploymentHostSet = (builder.Configuration.GetSection("MyPassKeys:DeploymentHosts").Get<string[]>() ?? [])
  .Select(h => h.ToLowerInvariant())
  .ToHashSet();
app.Use(async (context, next) =>
{
  var host = context.Request.Host.Value?.ToLowerInvariant();
  if (string.IsNullOrEmpty(host))
  {
    context.Response.StatusCode = StatusCodes.Status400BadRequest;
    return;
  }

  if (deploymentHostSet.Contains(host))
  {
    await next();
    return;
  }

  // Not a deployment host — must match a per-tenant Tenant.Hosts entry.
  var dbService = context.RequestServices.GetRequiredService<IFido2DbService>();
  var tenantByHost = await dbService.GetTenantByHostAsync(host);
  if (tenantByHost is null)
  {
    context.Response.StatusCode = StatusCodes.Status404NotFound;
    return;
  }

  await next();
});

// 2. Use CORS middleware (Must be placed between UseRouting and UseEndpoints/UseAuthorization)
app.UseCors("AllowFrontend");

app.UseRateLimiter();
app.UseAuthentication();
app.UseAuthorization();


if (app.Environment.IsDevelopment())
{
  app.MapOpenApi();
  app.MapScalarApiReference(); // -> http://localhost:5205/scalar/v1
}

app.MapTenantEndpoints();
app.MapPortalEndpoints();
app.MapUserEndpoints();
app.MapRoleEndpoints();
app.MapGroupEndpoints();
app.MapAdminEndpoints();
app.MapFido2Endpoints();
app.MapEmailVerificationEndpoints();

// Debug endpoints decode arbitrary tokens without authentication — never expose them in production.
if (app.Environment.IsDevelopment())
    app.MapDebugEndpoints();

// Related Origin Requests — allows cross-origin WebAuthn ceremonies.
// Browsers fetch this when the rpId differs from the page origin, to check if the origin is allowed.
// See: https://w3c.github.io/webauthn/#sctn-related-origins
app.MapGet("/.well-known/webauthn", async (ITenantService tenantService) =>
{
    var tenant = await tenantService.GetCurrentTenantAsync();
    if (tenant == null)
        return Results.NotFound();

    return Results.Json(new WebAuthnOriginsResponse(tenant.AllowedOrigins));
});

// JWKS endpoint — exposes all of the current tenant's public keys so external backends can verify JWTs.
// Includes both active and retired keys to allow validation of tokens signed before a key rotation.
app.MapGet("/.well-known/jwks.json", async (ITenantService tenantService) =>
{
    var tenant = await tenantService.GetCurrentTenantAsync();
    if (tenant == null || tenant.JwtKeys.Count == 0)
        return Results.NotFound();

    var jwks = new JwksResponse(tenant.JwtKeys.Select(k => (object)k.PublicKey));
    return Results.Json(jwks, contentType: "application/json");
});


// --- VERIFICATION CHECK ---
/*using (var scope = app.Services.CreateScope())
{
    var db = scope.ServiceProvider.GetRequiredService<AppDbContext>();
    // This will throw immediately if the Model is missing or AOT fails
    var model = db.Model; 
    Console.WriteLine("✅ SUCCESS: Compiled Model Loaded Successfully!");
    Console.WriteLine($"   Entity Count: {model.GetEntityTypes().Count()}");
}*/
// --------------------------

app.Run();

/*
public record Todo(int Id, string? Title, DateOnly? DueBy = null, bool IsComplete = false);
*/

// AOT-safe records for well-known endpoints
public record WebAuthnOriginsResponse(IEnumerable<string> origins);

// Note: For strict AOT compatibility, replace 'object' with the exact 
// class/record type of your PublicKey (e.g., JsonWebKey or your custom class).
public record JwksResponse(IEnumerable<object> keys);

/*[JsonSerializable(typeof(Todo[]))]*/
[JsonSerializable(typeof(Fido2Endpoints.AssertionOptionsRequest))]
[JsonSerializable(typeof(Fido2Endpoints.LoginResponse))]
[JsonSerializable(typeof(Fido2Endpoints.ErrorResponse))]
[JsonSerializable(typeof(CredentialCreateOptions))]
[JsonSerializable(typeof(RegisteredPublicKeyCredential))]
[JsonSerializable(typeof(AssertionOptions))]
[JsonSerializable(typeof(AuthenticatorAttestationRawResponse))]
[JsonSerializable(typeof(AuthenticatorAssertionRawResponse))]
[JsonSerializable(typeof(Fido2AppUser))]
[JsonSerializable(typeof(List<Fido2AppUser>))]
[JsonSerializable(typeof(UserEndpoints.UpsertUserRequest))]
[JsonSerializable(typeof(UserEndpoints.UpdateUserRequest))]
[JsonSerializable(typeof(UserEndpoints.UpdateUserRolesRequest))]
[JsonSerializable(typeof(TenantEndpoints.UpdateTenantRequest))]
[JsonSerializable(typeof(TenantEndpoints.CreateTenantRequest))]
[JsonSerializable(typeof(TenantEndpoints.TenantView))]
[JsonSerializable(typeof(List<TenantEndpoints.TenantView>))]
[JsonSerializable(typeof(UserEndpoints.UserRolesResponse))]
[JsonSerializable(typeof(UserEndpoints.MeResponse))]
[JsonSerializable(typeof(UserEndpoints.RevokeSessionsResponse))]
[JsonSerializable(typeof(TenantRole))]
[JsonSerializable(typeof(List<TenantRole>))]
[JsonSerializable(typeof(RoleEndpoints.CreateRoleRequest))]
[JsonSerializable(typeof(RoleEndpoints.UpdateRoleRequest))]
[JsonSerializable(typeof(TenantGroup))]
[JsonSerializable(typeof(List<TenantGroup>))]
[JsonSerializable(typeof(GroupEndpoints.CreateGroupRequest))]
[JsonSerializable(typeof(GroupEndpoints.UpdateGroupRequest))]
[JsonSerializable(typeof(GroupEndpoints.GroupMembersResponse))]
[JsonSerializable(typeof(GroupEndpoints.MembershipCheckResponse))]
[JsonSerializable(typeof(Fido2RefreshToken))]
[JsonSerializable(typeof(Fido2Endpoints.RefreshTokenRequest))]
[JsonSerializable(typeof(Fido2Endpoints.ExchangeTokenRequest))]
[JsonSerializable(typeof(EmailVerificationEndpoints.EmailVerificationRequest))]
[JsonSerializable(typeof(EmailVerificationEndpoints.VerifyCodeRequest))]
[JsonSerializable(typeof(WebAuthnOriginsResponse))]
[JsonSerializable(typeof(JwksResponse))]
[JsonSerializable(typeof(AdminEndpoints.RekeyResponse))]
[JsonSourceGenerationOptions(PropertyNamingPolicy = JsonKnownNamingPolicy.CamelCase)]
internal partial class AppJsonSerializerContext : JsonSerializerContext
{
}
