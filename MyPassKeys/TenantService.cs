using StackExchange.Redis;

namespace MyPassKeys;

/// <summary>
/// Thrown when an incoming Origin matches more than one tenant and the request carried no
/// X-Tenant-ID to disambiguate. This is expected for path-separated apps that share a domain
/// (e.g. abc.com/a-app and abc.com/b-app) — the client MUST send X-Tenant-ID. Converted to a
/// 409 by the ambiguous-tenant middleware in Program.cs. Surfacing it (rather than silently
/// picking one) is a security boundary: with open self-service, a tenant claiming another
/// tenant's origin must not be able to win origin-based resolution.
/// </summary>
public sealed class AmbiguousTenantException(string origin)
    : Exception($"Origin '{origin}' is shared by multiple tenants. Send an X-Tenant-ID header to select one.")
{
    public string Origin { get; } = origin;
}

public class TenantService(
  IHttpContextAccessor httpContextAccessor,
  IServiceProvider serviceProvider,
  IConnectionMultiplexer redis,
  IConfiguration configuration,
  ILogger<TenantService> logger,
  IDocumentIntegrity integrity,
  IVersionAnchor anchors
  ) : ITenantService
{
  private static readonly TimeSpan CacheTtl = TimeSpan.FromMinutes(5);

  /// <summary>
  /// Verifies the tenant's integrity seal and version anchor before handing it to callers. The
  /// DB path is already verified inside Fido2MartenDbService, but resolution results round-trip
  /// through the Redis cache — this closes the cache-poisoning path (a Redis writer injecting a
  /// tampered tenant) and catches a stale cached copy of a rolled-back tenant.
  /// </summary>
  private async Task<Tenant?> VerifiedAsync(Tenant? tenant)
  {
    if (tenant == null) return null;
    integrity.Verify(tenant);
    await anchors.CheckAsync(tenant);
    return tenant;
  }

  public async Task<Tenant?> GetCurrentTenantAsync()
  {
    var request = httpContextAccessor.HttpContext?.Request;
    var host = request?.Host.Value?.ToLowerInvariant();
    var origin = request?.Headers.Origin.FirstOrDefault()?.TrimEnd('/');

    if (string.IsNullOrEmpty(host)) return null;

    var db = redis.GetDatabase();

    // 0. Explicit X-Tenant-ID header — resolves the shared-origin ambiguity when multiple
    //    apps live under the same domain (e.g. example.com/app1, example.com/app2).
    //    Accepts either a tenant UUID ("019eacc6-...") or a ServerName ("My App").
    //    UUID-shaped values only attempt ID lookup; other strings only attempt ServerName lookup.
    //    The CORS preflight (OPTIONS) doesn't carry this header, but AllowAnyHeader() covers it.
    //
    //    STRICT: when the header is present, its resolution is authoritative — if it does NOT
    //    match a tenant we return null (caller 404s) rather than falling through to Host/Origin.
    //    Silent fallback would mask a bad header and could mis-route a request to a different
    //    tenant than the client intended.
    var explicitId = request?.Headers["X-Tenant-ID"].FirstOrDefault();
    if (!string.IsNullOrWhiteSpace(explicitId))
    {
      Tenant? tenant;
      if (Guid.TryParse(explicitId, out var explicitTenantId))
      {
        tenant = await db.GetOrCreateAsync($"Tenant:id:{explicitTenantId}", async () =>
        {
          var svc = serviceProvider.GetRequiredService<IFido2DbService>();
          var t = await svc.GetTenantByIdAsync(explicitTenantId);
          if (t is not null)
            logger.LogInformation("Cache miss: resolved tenant {TenantId} by X-Tenant-ID (UUID)", t.Id);
          else
            logger.LogWarning("Cache miss: no tenant found for X-Tenant-ID UUID '{TenantId}'", explicitTenantId);
          return t;
        }, CacheTtl);
      }
      else
      {
        var nameKey = $"Tenant:name:{explicitId.Trim().ToLower()}";
        tenant = await db.GetOrCreateAsync(nameKey, async () =>
        {
          var svc = serviceProvider.GetRequiredService<IFido2DbService>();
          var t = await svc.GetTenantByServerNameAsync(explicitId);
          if (t is not null)
            logger.LogInformation("Cache miss: resolved tenant {TenantId} by X-Tenant-ID ServerName '{Name}'", t.Id, explicitId);
          else
            logger.LogWarning("Cache miss: no tenant found for X-Tenant-ID ServerName '{Name}'", explicitId);
          return t;
        }, CacheTtl);
      }

      // Authoritative: do not fall through to Host/Origin resolution. A present-but-unresolved
      // X-Tenant-ID is a client error, not a hint to guess.
      return await VerifiedAsync(tenant);
    }

    // 1. If the incoming Host is a per-tenant custom subdomain (Tenant.Hosts),
    //    that wins — it short-circuits to that specific tenant.
    if (!IsDeploymentHost(host))
    {
      var tenant = await db.GetOrCreateAsync($"Tenant:host:{host}", async () =>
      {
        var fido2DbService = serviceProvider.GetRequiredService<IFido2DbService>();
        var t = await fido2DbService.GetTenantByHostAsync(host);
        if (t is not null)
          logger.LogInformation("Cache miss: resolved tenant {TenantId} by Host '{Host}'", t.Id, host);
        else
          logger.LogWarning("Cache miss: no tenant matched Host '{Host}' (and host is not a deployment host)", host);
        return t;
      }, CacheTtl);

      if (tenant is not null) return await VerifiedAsync(tenant);
      return null; // unknown host, not a deployment host — caller should 404
    }

    // 2. Host is a deployment host (auth.example.com, localhost:5205, ...).
    //    Resolve tenant by Origin against Tenant.AllowedOrigins.
    if (string.IsNullOrEmpty(origin))
    {
      // No Origin on a shared deployment host — cannot tell which tenant. Backends fetching
      // /.well-known/jwks.json from a deployment host must either send Origin or use a
      // custom-subdomain entry in Tenant.Hosts.
      return null;
    }

    return await VerifiedAsync(await db.GetOrCreateAsync($"Tenant:origin:{origin}", async () =>
    {
      var fido2DbService = serviceProvider.GetRequiredService<IFido2DbService>();
      var matches = await fido2DbService.GetTenantsByOriginAsync(origin);

      // The management tenant always wins a shared origin — it cannot be impersonated (the
      // IsManagementTenant flag is never settable via the API), so this tie-break is safe and
      // keeps the admin portal reachable when it shares a dev origin with a customer app.
      var management = matches.FirstOrDefault(t => t.IsManagementTenant);
      if (management is not null)
      {
        logger.LogInformation("Cache miss: resolved management tenant {TenantId} by Origin '{Origin}'", management.Id, origin);
        return management;
      }

      // Two or more non-management tenants share this origin (legitimate for path-separated
      // apps). We cannot pick one safely without X-Tenant-ID, which was absent (step 0 would
      // have resolved it). Surface the ambiguity instead of guessing.
      if (matches.Count > 1)
      {
        logger.LogWarning("Origin '{Origin}' is shared by {Count} tenants and no X-Tenant-ID was sent", origin, matches.Count);
        throw new AmbiguousTenantException(origin);
      }

      var t = matches.FirstOrDefault();
      if (t is not null)
        logger.LogInformation("Cache miss: resolved tenant {TenantId} by Origin '{Origin}'", t.Id, origin);
      else
        logger.LogWarning("Cache miss: no tenant matched Origin '{Origin}' on deployment host '{Host}'", origin, host);
      return t;
    }, CacheTtl));
  }

  private bool IsDeploymentHost(string host)
  {
    var deploymentHosts = configuration.GetSection("MyPassKeys:DeploymentHosts").Get<string[]>() ?? [];
    foreach (var h in deploymentHosts)
    {
      if (string.Equals(h, host, StringComparison.OrdinalIgnoreCase)) return true;
    }
    return false;
  }
}
