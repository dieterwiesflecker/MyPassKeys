using System.Security.Claims;
using System.Security.Cryptography;
using System.Text.Json;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using StackExchange.Redis;

namespace MyPassKeys;

public static class TenantEndpoints
{
    /// <summary>
    /// Request body for editing an existing tenant. Every field is optional — only the
    /// supplied fields are applied. JWT signing keys are NOT editable here; use the
    /// rotate-key/cleanup-keys endpoints for keys. <c>IsManagementTenant</c> is also not
    /// editable here (the management flag is set once at bootstrap).
    /// </summary>
    public record UpdateTenantRequest(
        string? ServerName,
        string[]? Hosts,
        Dictionary<string, string>? ServerDomains,
        string? ServerIcon,
        string[]? AllowedOrigins,
        string? JwtIssuer,
        string? JwtAudience,
        int? KeyRotationIntervalInDays,
        int? AccessTokenLifetimeInMinutes,
        int? RefreshTokenLifetimeInHours,
        string? RegistrationMode,
        string[]? AllowedEmailDomains,
        string[]? DefaultRoles,
        Dictionary<string, string[]>? DomainRoles,
        Guid[]? TrustedCredentialTenantIds);

    /// <summary>
    /// Request body for creating a new tenant. JwtAudience is required. JwtIssuer is IGNORED
    /// if supplied — it is auto-derived as <c>{IssuerBaseUrl}/t/{tenantId}</c> so every tenant's
    /// issuer is globally unique by construction, independent of shared deployment hostnames.
    /// </summary>
    public record CreateTenantRequest(
        string ServerName,
        string? JwtIssuer,
        string JwtAudience,
        string[]? Hosts,
        Dictionary<string, string>? ServerDomains,
        string? ServerIcon,
        string[]? AllowedOrigins,
        int? KeyRotationIntervalInDays,
        int? AccessTokenLifetimeInMinutes,
        int? RefreshTokenLifetimeInHours,
        string? RegistrationMode,
        string[]? AllowedEmailDomains,
        string[]? DefaultRoles,
        Dictionary<string, string[]>? DomainRoles,
        Guid[]? TrustedCredentialTenantIds);

    /// <summary>
    /// Public tenant projection for the portal. Extends the safe tenant fields with the new
    /// role-model fields the frontend reads: the caller's <c>myRole</c> and the tenant's
    /// <c>admins</c>. Serialized camelCase.
    /// </summary>
    public record TenantView(
        Guid Id,
        string[] Hosts,
        bool IsManagementTenant,
        string ServerName,
        Dictionary<string, string> ServerDomains,
        string ServerIcon,
        string[] AllowedOrigins,
        string[] Admins,
        string MyRole,
        string JwtIssuer,
        string JwtAudience,
        IEnumerable<object> JwtKeys,
        int KeyRotationIntervalInDays,
        int AccessTokenLifetimeInMinutes,
        int RefreshTokenLifetimeInHours,
        DateTime SessionsValidFrom,
        string RegistrationMode,
        string[] AllowedEmailDomains,
        string[] DefaultRoles,
        Dictionary<string, string[]> DomainRoles,
        Guid[] TrustedCredentialTenantIds);

    /// <summary>
    /// Builds a <see cref="TenantView"/>: resolves the tenant's admins and the caller's role from
    /// the tenant's membership records (Fido2AppUser). <paramref name="callerEmail"/> must be
    /// normalized.
    /// </summary>
    private static async Task<TenantView> BuildViewAsync(
        Tenant tenant, string callerEmail, IFido2DbService db)
    {
        var members = await db.GetUsersForTenantAsync(tenant.Id);
        var admins = members
            .Where(u => TenantRoleModel.IsTenantAdmin(u.Roles))
            .Select(u => string.IsNullOrWhiteSpace(u.DisplayName) ? u.Username : u.DisplayName)
            .ToArray();
        var myMembership = string.IsNullOrEmpty(callerEmail)
            ? null
            : members.FirstOrDefault(u => u.Username == callerEmail);
        var myRole = myMembership != null ? TenantRoleModel.MyRole(myMembership.Roles) : "";

        return new TenantView(
            tenant.Id, tenant.Hosts, tenant.IsManagementTenant, tenant.ServerName, tenant.ServerDomains,
            tenant.ServerIcon, tenant.AllowedOrigins,
            admins, myRole, tenant.JwtIssuer, tenant.JwtAudience,
            tenant.JwtKeys.Select(k => (object)k.ToPublicView()),
            tenant.KeyRotationIntervalInDays, tenant.AccessTokenLifetimeInMinutes,
            tenant.RefreshTokenLifetimeInHours, tenant.SessionsValidFrom, tenant.RegistrationMode,
            tenant.AllowedEmailDomains, tenant.DefaultRoles, tenant.DomainRoles,
            tenant.TrustedCredentialTenantIds);
    }

    /// <summary>
    /// Loads the target tenant and resolves the caller's membership in it. Returns the membership
    /// (or null), so callers can decide whether tenantadmin is required.
    /// </summary>
    private static async Task<(Tenant? Tenant, Fido2AppUser? Membership)> LookupAsync(
        Guid id, ClaimsPrincipal principal, IFido2DbService db)
    {
        var tenant = await db.GetTenantByIdAsync(id);
        if (tenant == null) return (null, null);

        var email = (principal.Identity?.Name ?? "").NormalizeUsername();
        var membership = string.IsNullOrEmpty(email) ? null : await db.GetUserByUsernameForTenantAsync(id, email);
        return (tenant, membership);
    }

    /// <summary>
    /// Gate for tenant-admin operations. Returns null when authorized, otherwise the error result:
    /// 404 when the tenant is absent or the caller has no membership at all (existence hidden),
    /// 403 when the caller is a useradmin-only member.
    /// </summary>
    private static IResult? RequireTenantAdmin(Tenant? tenant, Fido2AppUser? membership)
    {
        if (tenant == null) return Results.NotFound();
        if (membership == null || !TenantRoleModel.IsUserAdminOrAbove(membership.Roles)) return Results.NotFound();
        if (!TenantRoleModel.IsTenantAdmin(membership.Roles)) return Results.Forbid();
        return null;
    }

    /// <summary>
    /// Derives a tenant's JWT issuer as <c>{base}/t/{tenantId}</c>, guaranteeing global uniqueness
    /// per tenant. The base is <c>MyPassKeys:IssuerBaseUrl</c> if configured, otherwise
    /// <c>https://{firstDeploymentHost}</c> — matching the management tenant's bootstrap issuer base.
    /// Resource servers reconstruct the same value from the token's <c>tenant_id</c> claim.
    /// </summary>
    private static string DeriveIssuer(IConfiguration configuration, Guid tenantId)
    {
        var deploymentHosts = configuration.GetSection("MyPassKeys:DeploymentHosts").Get<string[]>() ?? [];
        var baseUrl = (configuration["MyPassKeys:IssuerBaseUrl"]
                       ?? (deploymentHosts.Length > 0 ? $"https://{deploymentHosts[0]}" : "https://localhost"))
                      .TrimEnd('/');
        return $"{baseUrl}/t/{tenantId}";
    }

    /// <summary>
    /// Normalizes a requested trust-link list (see <see cref="Tenant.TrustedCredentialTenantIds"/>):
    /// de-duplicates, rejects a self-reference and any id that doesn't resolve to an existing
    /// tenant. Returns the normalized ids, or an error result to return as-is.
    /// </summary>
    private static async Task<(Guid[] Ids, IResult? Error)> NormalizeTrustedTenantsAsync(
        Guid[] requested, Guid selfTenantId, IFido2DbService dbService)
    {
        var ids = requested.Distinct().ToArray();
        if (ids.Contains(selfTenantId))
            return ([], Results.BadRequest("TrustedCredentialTenantIds must not contain the tenant itself."));
        var found = (await dbService.GetTenantsByIdsAsync(ids)).Select(t => t.Id).ToHashSet();
        var unknown = ids.Where(id => !found.Contains(id)).ToList();
        if (unknown.Count > 0)
            return ([], Results.BadRequest(
                $"Unknown TrustedCredentialTenantIds: {string.Join(", ", unknown)}."));
        return (ids, null);
    }

    public static void MapTenantEndpoints(this IEndpointRouteBuilder app)
    {
        var group = app.MapGroup("tenants").RequireAuthorization();

        // List the tenants where the caller has a tenantadmin or useradmin membership.
        group.MapGet("/", GetMyTenants);
        group.MapGet("/{id:guid}", GetTenantById);

        // Create a tenant — rate-limited (per IP) because each creation mints a key pair.
        group.MapPost("/", UpsertTenant).RequireRateLimiting("tenant-create");

        // Update an existing tenant's settings
        group.MapPut("/{id:guid}", UpdateTenant);

        // Permanently delete a tenant and all its data (tenantadmin of that tenant only).
        group.MapDelete("/{id:guid}", DeleteTenant);

        // Rotate the signing key for a tenant
        group.MapPost("/{id:guid}/rotate-key", RotateKey);

        // Remove expired retired keys
        group.MapPost("/{id:guid}/cleanup-keys", CleanupKeys);

        // Force every user of the tenant to authenticate again
        group.MapPost("/{id:guid}/revoke-sessions", RevokeSessions);
    }

    private static async Task<IResult> GetMyTenants(
        ClaimsPrincipal userPrincipal,
        IFido2DbService dbService)
    {
        if (!Guid.TryParse(userPrincipal.FindFirst(ClaimTypes.NameIdentifier)?.Value, out _))
            return Results.Unauthorized();

        var email = (userPrincipal.Identity?.Name ?? "").NormalizeUsername();

        // Tenants where the caller is tenantadmin or useradmin. End users registering passkeys
        // against a customer RP carry no role at all and don't appear here; portal admins do.
        var memberships = string.IsNullOrEmpty(email)
            ? new List<Fido2AppUser>()
            : await dbService.GetMembershipsByUsernameAsync(email);
        var ids = memberships
            .Where(m => TenantRoleModel.IsUserAdminOrAbove(m.Roles))
            .Select(m => m.TenantId)
            .ToHashSet();
        var tenants = await dbService.GetTenantsByIdsAsync(ids);

        var views = new List<TenantView>(tenants.Count);
        foreach (var tenant in tenants)
            views.Add(await BuildViewAsync(tenant, email, dbService));
        return Results.Ok(views);
    }

    private static async Task<IResult> GetTenantById(
        Guid id,
        ClaimsPrincipal userPrincipal,
        IFido2DbService dbService)
    {
        if (!Guid.TryParse(userPrincipal.FindFirst(ClaimTypes.NameIdentifier)?.Value, out _))
            return Results.Unauthorized();

        var (tenant, membership) = await LookupAsync(id, userPrincipal, dbService);
        if (tenant == null || membership == null || !TenantRoleModel.IsUserAdminOrAbove(membership.Roles))
            return Results.NotFound();

        var email = (userPrincipal.Identity?.Name ?? "").NormalizeUsername();
        var view = await BuildViewAsync(tenant, email, dbService);
        return Results.Ok(view);
    }

    private static async Task<IResult> UpsertTenant(
        [FromBody] CreateTenantRequest request,
        ClaimsPrincipal userPrincipal,
        IFido2DbService dbService,
        IConfiguration configuration,
        IConnectionMultiplexer redis,
        IKeyProtector keyProtector)
    {
        if (!Guid.TryParse(userPrincipal.FindFirst(ClaimTypes.NameIdentifier)?.Value, out _))
            return Results.Unauthorized();

        // New tenants can only be created on the management portal. Verified via the 'tenant_id'
        // JWT claim (not Origin) so that shared origins in local dev don't cause ambiguity.
        var callerTenantIdStr = userPrincipal.FindFirst("tenant_id")?.Value;
        if (!Guid.TryParse(callerTenantIdStr, out var callerTenantId))
            return Results.Problem("New tenants can only be created via the management portal.", statusCode: 403);
        var currentTenant = await dbService.GetTenantByIdAsync(callerTenantId);
        if (currentTenant is not { IsManagementTenant: true })
            return Results.Problem("New tenants can only be created via the management portal.", statusCode: 403);

        var creatorEmail = (userPrincipal.Identity?.Name ?? "").NormalizeUsername();
        var creatorMembership = string.IsNullOrEmpty(creatorEmail)
            ? null
            : await dbService.GetUserByUsernameForTenantAsync(currentTenant.Id, creatorEmail);
        if (creatorMembership == null || !TenantRoleModel.IsUserAdminOrAbove(creatorMembership.Roles))
            return Results.Forbid();

        // Per-user quota: cap how many tenants one identity can administer (anti-abuse for open
        // self-service). A tenant the creator administers is one where they hold tenantadmin.
        // 0 or negative disables the cap. The management tenant membership is excluded from the
        // count since it is not a self-created tenant.
        var maxTenantsPerUser = configuration.GetValue<int>("MyPassKeys:MaxTenantsPerUser", 10);
        if (maxTenantsPerUser > 0)
        {
            var memberships = await dbService.GetMembershipsByUsernameAsync(creatorEmail);
            var ownedCount = memberships.Count(m =>
                m.TenantId != currentTenant.Id && TenantRoleModel.IsTenantAdmin(m.Roles));
            if (ownedCount >= maxTenantsPerUser)
                return Results.Problem(
                    $"Tenant creation limit reached ({maxTenantsPerUser} per user).",
                    statusCode: StatusCodes.Status429TooManyRequests);
        }

        // Basic validation
        if (string.IsNullOrWhiteSpace(request.ServerName))
            return Results.BadRequest("ServerName is required.");
        if (string.IsNullOrWhiteSpace(request.JwtAudience))
            return Results.BadRequest("JwtAudience is required.");

        // ServerName is globally unique (case-insensitive) — it doubles as an X-Tenant-ID selector.
        var serverName = request.ServerName.Trim();
        var nameCollision = await dbService.GetTenantByServerNameAsync(serverName);
        if (nameCollision != null)
            return Results.Conflict($"ServerName '{serverName}' is already in use by another tenant.");

        var registrationMode = (request.RegistrationMode ?? RegistrationModes.Open).Trim().ToLowerInvariant();
        if (!RegistrationModes.All.Contains(registrationMode))
            return Results.BadRequest(
                $"RegistrationMode must be one of: {string.Join(", ", RegistrationModes.All)}.");
        var (allowedEmailDomains, invalidDomainEntries) = RegistrationPolicy.NormalizeDomains(request.AllowedEmailDomains);
        if (invalidDomainEntries.Length > 0)
            return Results.BadRequest(
                $"Invalid AllowedEmailDomains entries: {string.Join(", ", invalidDomainEntries)}. " +
                "Use 'example.com' for an exact match or '*.example.com' for subdomains.");
        if (registrationMode == RegistrationModes.DomainAllowlist && allowedEmailDomains.Length == 0)
            return Results.BadRequest(
                "AllowedEmailDomains is required when RegistrationMode is 'domain-allowlist'.");

        var normalizedHosts = (request.Hosts ?? []).Select(h => h.ToLowerInvariant()).ToArray();
        var serverDomains = request.ServerDomains ?? new Dictionary<string, string>();
        var allowedOrigins = (request.AllowedOrigins ?? []).Select(o => o.TrimEnd('/')).ToArray();

        // Guard 1: Hosts must not collide with deployment hostnames in config.
        var deploymentHosts = (configuration.GetSection("MyPassKeys:DeploymentHosts").Get<string[]>() ?? [])
            .Select(h => h.ToLowerInvariant())
            .ToHashSet();
        var collidingDeployment = normalizedHosts.Where(h => deploymentHosts.Contains(h)).ToList();
        if (collidingDeployment.Count > 0)
            return Results.Conflict(
                $"Host(s) collide with deployment hostnames and cannot be claimed by a tenant: {string.Join(", ", collidingDeployment)}");

        // ServerDomains keys must reference an entry in Hosts to prevent rpId overrides for unowned domains
        var invalidDomainKeys = serverDomains.Keys
            .Where(k => !normalizedHosts.Contains(k.ToLowerInvariant()))
            .ToList();
        if (invalidDomainKeys.Count > 0)
        {
            return Results.BadRequest($"ServerDomains keys must match entries in Hosts. Invalid: {string.Join(", ", invalidDomainKeys)}");
        }

        // Guard 2: Hosts already claimed by another tenant.
        foreach (var host in normalizedHosts)
        {
            var existing = await dbService.GetTenantByHostAsync(host);
            if (existing != null)
                return Results.Conflict($"Host '{host}' is already claimed by another tenant.");
        }

        var tenantId = Guid.CreateVersion7();

        // The issuer is auto-derived from the tenant id, never caller-supplied, so it is globally
        // unique by construction. The uniqueness guard below is a defensive belt-and-suspenders
        // check that also catches collisions with the management tenant's bootstrap issuer or any
        // legacy tenant created before auto-derivation.
        var derivedIssuer = DeriveIssuer(configuration, tenantId);
        var issuerCollision = await dbService.GetTenantByIssuerAsync(derivedIssuer);
        if (issuerCollision != null)
            return Results.Conflict($"JwtIssuer '{derivedIssuer}' is already in use by another tenant.");

        var (trustedTenantIds, trustError) =
            await NormalizeTrustedTenantsAsync(request.TrustedCredentialTenantIds ?? [], tenantId, dbService);
        if (trustError != null) return trustError;

        var tenant = new Tenant
        {
            Id = tenantId,
            Hosts = normalizedHosts,
            IsManagementTenant = false,
            ServerName = serverName,
            ServerDomains = serverDomains,
            ServerIcon = request.ServerIcon ?? "",
            AllowedOrigins = allowedOrigins,
            JwtIssuer = derivedIssuer,
            JwtAudience = request.JwtAudience,
            JwtKeys = [CreateKeyEntry(keyProtector)],
            KeyRotationIntervalInDays = request.KeyRotationIntervalInDays ?? 0,
            AccessTokenLifetimeInMinutes = request.AccessTokenLifetimeInMinutes ?? 60,
            RefreshTokenLifetimeInHours = request.RefreshTokenLifetimeInHours ?? 720,
            RegistrationMode = registrationMode,
            AllowedEmailDomains = allowedEmailDomains,
            DefaultRoles = RegistrationPolicy.NormalizeRoles(request.DefaultRoles),
            DomainRoles = RegistrationPolicy.NormalizeDomainRoles(request.DomainRoles, allowedEmailDomains),
            TrustedCredentialTenantIds = trustedTenantIds
        };

        await dbService.UpsertTenantAsync(tenant);

        // Seed the built-in role catalog (tenantadmin / useradmin). Any further "standard" roles
        // (admin/editor/writer, the app-scoped app.<serverName> role, etc.) are an application
        // concern and are created by the client after creation — the backend stays generic.
        foreach (var role in TenantRoleModel.BuiltInRoles())
            await dbService.UpsertRoleForTenantAsync(tenant.Id, role);

        // The creator becomes a tenantadmin member of the new tenant — this membership (a
        // Fido2AppUser linked by email) is what makes the tenant show up in their "my tenants".
        var creatorDisplay = userPrincipal.FindFirst("preferred_username")?.Value;
        await dbService.UpsertUserForTenantAsync(tenant.Id, new Fido2AppUser
        {
            Username = creatorEmail,
            DisplayName = string.IsNullOrWhiteSpace(creatorDisplay) ? creatorEmail : creatorDisplay,
            Roles = [BuiltInTenantRoles.TenantAdmin]
        });

        await InvalidateTenantCacheAsync(redis, tenant);

        var view = await BuildViewAsync(tenant, creatorEmail, dbService);
        return Results.Ok(view);
    }

    private static async Task<IResult> UpdateTenant(
        Guid id,
        [FromBody] UpdateTenantRequest request,
        ClaimsPrincipal userPrincipal,
        IFido2DbService dbService,
        IConfiguration configuration,
        IConnectionMultiplexer redis)
    {
        var (tenantNullable, membership) = await LookupAsync(id, userPrincipal, dbService);
        var authzError = RequireTenantAdmin(tenantNullable, membership);
        if (authzError != null) return authzError;
        var tenant = tenantNullable!;

        // Capture old keys for cache invalidation before mutating.
        var oldHosts = tenant.Hosts.ToArray();
        var oldOrigins = tenant.AllowedOrigins.ToArray();

        var normalizedHosts = request.Hosts is null
            ? tenant.Hosts
            : request.Hosts.Select(h => h.ToLowerInvariant()).ToArray();

        // Guard 1: Hosts must not collide with deployment hostnames.
        if (request.Hosts is not null)
        {
            var deploymentHosts = (configuration.GetSection("MyPassKeys:DeploymentHosts").Get<string[]>() ?? [])
                .Select(h => h.ToLowerInvariant())
                .ToHashSet();
            var collidingDeployment = normalizedHosts.Where(h => deploymentHosts.Contains(h)).ToList();
            if (collidingDeployment.Count > 0)
                return Results.Conflict(
                    $"Host(s) collide with deployment hostnames and cannot be claimed by a tenant: {string.Join(", ", collidingDeployment)}");

            // Guard 2: Hosts already claimed by another tenant.
            foreach (var host in normalizedHosts)
            {
                var existing = await dbService.GetTenantByHostAsync(host);
                if (existing != null && existing.Id != tenant.Id)
                    return Results.Conflict($"Host '{host}' is already claimed by another tenant.");
            }
        }

        // ServerDomains keys must reference an entry in the (possibly updated) Hosts list.
        if (request.ServerDomains != null)
        {
            var invalidKeys = request.ServerDomains.Keys
                .Where(k => !normalizedHosts.Contains(k.ToLowerInvariant()))
                .ToList();
            if (invalidKeys.Count > 0)
                return Results.BadRequest(
                    $"ServerDomains keys must match entries in Hosts. Invalid: {string.Join(", ", invalidKeys)}");
        }

        // Decide the effective post-update registration mode + allowlist so we can validate the
        // pair atomically (e.g. switching to 'domain-allowlist' requires at least one domain).
        var effectiveMode = request.RegistrationMode == null
            ? tenant.RegistrationMode
            : request.RegistrationMode.Trim().ToLowerInvariant();
        if (request.RegistrationMode != null && !RegistrationModes.All.Contains(effectiveMode))
            return Results.BadRequest(
                $"RegistrationMode must be one of: {string.Join(", ", RegistrationModes.All)}.");
        string[] effectiveDomains;
        if (request.AllowedEmailDomains == null)
        {
            effectiveDomains = tenant.AllowedEmailDomains;
        }
        else
        {
            var (normalized, invalid) = RegistrationPolicy.NormalizeDomains(request.AllowedEmailDomains);
            if (invalid.Length > 0)
                return Results.BadRequest(
                    $"Invalid AllowedEmailDomains entries: {string.Join(", ", invalid)}. " +
                    "Use 'example.com' for an exact match or '*.example.com' for subdomains.");
            effectiveDomains = normalized;
        }
        if (effectiveMode == RegistrationModes.DomainAllowlist && effectiveDomains.Length == 0)
            return Results.BadRequest(
                "AllowedEmailDomains must contain at least one entry when RegistrationMode is 'domain-allowlist'.");

        // ServerName is globally unique (case-insensitive) and doubles as an X-Tenant-ID selector.
        string? newServerName = null;
        if (request.ServerName != null)
        {
            newServerName = request.ServerName.Trim();
            if (string.IsNullOrWhiteSpace(newServerName))
                return Results.BadRequest("ServerName cannot be blank.");
            if (!string.Equals(newServerName, tenant.ServerName, StringComparison.OrdinalIgnoreCase))
            {
                var nameCollision = await dbService.GetTenantByServerNameAsync(newServerName);
                if (nameCollision != null && nameCollision.Id != tenant.Id)
                    return Results.Conflict($"ServerName '{newServerName}' is already in use by another tenant.");
            }
        }

        // Apply only the fields that were supplied.
        if (newServerName != null) tenant.ServerName = newServerName;
        if (request.Hosts != null) tenant.Hosts = normalizedHosts;
        if (request.ServerDomains != null) tenant.ServerDomains = request.ServerDomains;
        if (request.ServerIcon != null) tenant.ServerIcon = request.ServerIcon;
        if (request.AllowedOrigins != null)
            tenant.AllowedOrigins = request.AllowedOrigins.Select(o => o.TrimEnd('/')).ToArray();
        // JwtIssuer is immutable: it is derived from the tenant id at creation and must stay stable
        // so resource servers (which derive the expected issuer from tenant_id) keep validating.
        if (!string.IsNullOrWhiteSpace(request.JwtAudience)) tenant.JwtAudience = request.JwtAudience;
        if (request.KeyRotationIntervalInDays.HasValue) tenant.KeyRotationIntervalInDays = request.KeyRotationIntervalInDays.Value;
        if (request.AccessTokenLifetimeInMinutes.HasValue) tenant.AccessTokenLifetimeInMinutes = request.AccessTokenLifetimeInMinutes.Value;
        if (request.RefreshTokenLifetimeInHours.HasValue) tenant.RefreshTokenLifetimeInHours = request.RefreshTokenLifetimeInHours.Value;
        tenant.RegistrationMode = effectiveMode;
        tenant.AllowedEmailDomains = effectiveDomains;
        if (request.DefaultRoles != null)
            tenant.DefaultRoles = RegistrationPolicy.NormalizeRoles(request.DefaultRoles);
        // Re-prune the per-domain role map against the effective domain set whenever either the
        // map or the domain list changed, so removing a domain also drops its role mapping.
        if (request.DomainRoles != null)
            tenant.DomainRoles = RegistrationPolicy.NormalizeDomainRoles(request.DomainRoles, effectiveDomains);
        else if (request.AllowedEmailDomains != null)
            tenant.DomainRoles = RegistrationPolicy.NormalizeDomainRoles(tenant.DomainRoles, effectiveDomains);
        if (request.TrustedCredentialTenantIds != null)
        {
            var (trustedTenantIds, trustError) =
                await NormalizeTrustedTenantsAsync(request.TrustedCredentialTenantIds, tenant.Id, dbService);
            if (trustError != null) return trustError;
            tenant.TrustedCredentialTenantIds = trustedTenantIds;
        }

        await dbService.UpsertTenantAsync(tenant);
        await InvalidateTenantCacheAsync(redis, tenant, oldHosts, oldOrigins);

        var email = (userPrincipal.Identity?.Name ?? "").NormalizeUsername();
        var view = await BuildViewAsync(tenant, email, dbService);
        return Results.Ok(view);
    }

    private static async Task<IResult> DeleteTenant(
        Guid id,
        ClaimsPrincipal userPrincipal,
        IFido2DbService dbService,
        IConnectionMultiplexer redis)
    {
        var (tenantNullable, membership) = await LookupAsync(id, userPrincipal, dbService);
        var authzError = RequireTenantAdmin(tenantNullable, membership);
        if (authzError != null) return authzError;
        var tenant = tenantNullable!;

        // The management tenant is the portal's own root of trust — deleting it would orphan
        // every other tenant's admin access. Never allow it.
        if (tenant.IsManagementTenant)
            return Results.Problem("The management tenant cannot be deleted.", statusCode: StatusCodes.Status403Forbidden);

        // Capture routing keys before the row is gone so the cache can be cleared.
        var oldHosts = tenant.Hosts.ToArray();
        var oldOrigins = tenant.AllowedOrigins.ToArray();

        // Revoke refresh tokens first (the cascade deletes them too, but this closes the window
        // where an in-flight session could mint new access tokens during teardown), then drop the
        // tenant and all its scoped data (users, credentials, refresh tokens, roles).
        await dbService.RevokeAllRefreshTokensAsync(id);
        await dbService.DeleteTenantAsync(id);
        await InvalidateTenantCacheAsync(redis, tenant, oldHosts, oldOrigins);

        return Results.NoContent();
    }

    private static async Task<IResult> RotateKey(
        Guid id,
        ClaimsPrincipal userPrincipal,
        IFido2DbService dbService,
        IConnectionMultiplexer redis,
        IKeyProtector keyProtector)
    {
        var (tenantNullable, membership) = await LookupAsync(id, userPrincipal, dbService);
        var authzError = RequireTenantAdmin(tenantNullable, membership);
        if (authzError != null) return authzError;
        var tenant = tenantNullable!;

        // Retire all currently active keys
        foreach (var key in tenant.JwtKeys)
            key.IsActive = false;

        // Add new active key
        tenant.JwtKeys.Add(CreateKeyEntry(keyProtector));

        await dbService.UpsertTenantAsync(tenant);
        await InvalidateTenantCacheAsync(redis, tenant);

        return Results.Ok(tenant.ToPublicView());
    }

    private static async Task<IResult> CleanupKeys(
        Guid id,
        ClaimsPrincipal userPrincipal,
        IFido2DbService dbService,
        IConnectionMultiplexer redis)
    {
        var (tenantNullable, membership) = await LookupAsync(id, userPrincipal, dbService);
        var authzError = RequireTenantAdmin(tenantNullable, membership);
        if (authzError != null) return authzError;
        var tenant = tenantNullable!;

        // A retired key is safe to remove once all tokens it could have signed have expired.
        // The longest-lived token is the refresh token, so we use that as the cutoff.
        var cutoff = DateTime.UtcNow.AddHours(-tenant.RefreshTokenLifetimeInHours);

        var expiredKeys = tenant.JwtKeys
            .Where(k => !k.IsActive && k.CreatedAt < cutoff)
            .ToList();

        if (expiredKeys.Count == 0)
            return Results.Ok(new { message = "No expired keys to remove.", keys = tenant.JwtKeys.Select(k => k.ToPublicView()) });

        foreach (var key in expiredKeys)
            tenant.JwtKeys.Remove(key);

        await dbService.UpsertTenantAsync(tenant);
        await InvalidateTenantCacheAsync(redis, tenant);

        return Results.Ok(new
        {
            message = $"Removed {expiredKeys.Count} expired key(s).",
            removed = expiredKeys.Select(k => k.Kid),
            keys = tenant.JwtKeys.Select(k => k.ToPublicView())
        });
    }

    private static async Task<IResult> RevokeSessions(
        Guid id,
        ClaimsPrincipal userPrincipal,
        IFido2DbService dbService,
        IConnectionMultiplexer redis)
    {
        var (tenantNullable, membership) = await LookupAsync(id, userPrincipal, dbService);
        var authzError = RequireTenantAdmin(tenantNullable, membership);
        if (authzError != null) return authzError;
        var tenant = tenantNullable!;

        // 1. Set the cutoff — every access token issued before now is rejected on validation.
        //    NOTE: this also logs out the caller; the owner must authenticate again too.
        tenant.SessionsValidFrom = DateTime.UtcNow;
        await dbService.UpsertTenantAsync(tenant);
        await InvalidateTenantCacheAsync(redis, tenant);

        // 2. Revoke all refresh tokens so no new access tokens can be minted.
        await dbService.RevokeAllRefreshTokensAsync(id);

        return Results.Ok(tenant.ToPublicView());
    }

    /// <summary>
    /// Drops the cached tenant for every host AND every allowed origin (current + any prior
    /// values supplied) so resolution changes apply immediately. TenantService otherwise
    /// serves a stale tenant from Redis for up to 5 minutes.
    /// </summary>
    internal static async Task InvalidateTenantCacheAsync(
        IConnectionMultiplexer redis,
        Tenant tenant,
        string[]? oldHosts = null,
        string[]? oldOrigins = null)
    {
        var db = redis.GetDatabase();

        var hosts = (oldHosts ?? []).Concat(tenant.Hosts).Distinct(StringComparer.OrdinalIgnoreCase);
        foreach (var host in hosts)
            await db.KeyDeleteAsync($"Tenant:host:{host.ToLowerInvariant()}");

        var origins = (oldOrigins ?? []).Concat(tenant.AllowedOrigins).Distinct(StringComparer.OrdinalIgnoreCase);
        foreach (var origin in origins)
            await db.KeyDeleteAsync($"Tenant:origin:{origin.TrimEnd('/')}");

        await db.KeyDeleteAsync($"Tenant:id:{tenant.Id}");

        if (!string.IsNullOrWhiteSpace(tenant.ServerName))
            await db.KeyDeleteAsync($"Tenant:name:{tenant.ServerName.Trim().ToLower()}");

        if (tenant.IsManagementTenant)
            await db.KeyDeleteAsync("Tenant:management");
    }

    public static JwtKeyEntry CreateKeyEntry(IKeyProtector keyProtector)
    {
        using var ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var kid = Guid.NewGuid().ToString("N");
        var securityKey = new ECDsaSecurityKey(ecdsa) { KeyId = kid };
        var jwk = JsonWebKeyConverter.ConvertFromECDsaSecurityKey(securityKey);

        return new JwtKeyEntry
        {
            Kid = kid,
            // Encrypted at rest: only the KEK holder (the app) can recover the signing key,
            // so a DB/Redis dump alone cannot forge tokens.
            PrivateKey = keyProtector.Protect(JsonSerializer.SerializeToElement(new
            {
                kty = jwk.Kty, crv = jwk.Crv, x = jwk.X, y = jwk.Y, d = jwk.D, kid
            }), kid),
            PublicKey = JsonSerializer.SerializeToElement(new
            {
                kty = jwk.Kty, crv = jwk.Crv, x = jwk.X, y = jwk.Y, kid
            }),
            CreatedAt = DateTime.UtcNow,
            IsActive = true
        };
    }

}