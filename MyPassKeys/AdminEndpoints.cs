using System.Security.Claims;
using Marten;
using StackExchange.Redis;

namespace MyPassKeys;

/// <summary>
/// Installation-wide maintenance operations. Unlike the per-tenant admin endpoints, these act
/// across every tenant, so they are restricted to a <c>tenantadmin</c> of the MANAGEMENT tenant
/// (verified via the token's <c>tenant_id</c> claim, mirroring <see cref="PortalEndpoints"/>).
/// </summary>
public static class AdminEndpoints
{
    public static void MapAdminEndpoints(this IEndpointRouteBuilder app)
    {
        var group = app.MapGroup("admin").RequireAuthorization();

        // Force-walk every security-critical document + signing key and re-encrypt/re-seal any that
        // is still on a previous KEK. Run this after a KEK rotation and confirm the response shows
        // everything on the current key before retiring the old KEK. See CLAUDE.md → "Rotating the
        // key-encryption key (KEK)".
        group.MapPost("rekey", Rekey);
    }

    /// <summary>Result of <c>POST /admin/rekey</c>. When <see cref="FullyOnCurrentKey"/> is true the
    /// previous KEK can be safely removed from <c>MyPassKeys:PreviousKeyEncryptionKeys</c>.</summary>
    public record RekeyResponse(
        int SigningKeysReEncrypted,
        int DocumentsReSealed,
        int TenantsReSealed,
        int UsersReSealed,
        int CredentialsReSealed,
        int RolesReSealed,
        int GroupsReSealed,
        int RefreshTokensReSealed,
        bool FullyOnCurrentKey,
        string Message);

    private static async Task<IResult> Rekey(
        ClaimsPrincipal userPrincipal,
        IFido2DbService dbService,
        IDocumentSession session,
        IConnectionMultiplexer redis,
        IKeyProtector keyProtector,
        IDocumentIntegrity integrity,
        IVersionAnchor anchors,
        ILoggerFactory loggerFactory)
    {
        var error = await RequireManagementTenantAdminAsync(userPrincipal, dbService);
        if (error != null) return error;

        var result = await KeyRotationMaintenance.RekeyAllUnderCurrentKeyAsync(
            session, redis, keyProtector, integrity, anchors, loggerFactory.CreateLogger("Rekey"));

        var message = result.FullyOnCurrentKey
            ? "All documents and signing keys are on the current KEK. It is safe to retire any previous KEK."
            : "Re-encrypted/re-sealed stragglers onto the current KEK. Re-run to confirm a clean pass before retiring a previous KEK.";

        return Results.Ok(new RekeyResponse(
            result.SigningKeysReEncrypted,
            result.TotalReSealed,
            result.TenantsReSealed,
            result.UsersReSealed,
            result.CredentialsReSealed,
            result.RolesReSealed,
            result.GroupsReSealed,
            result.RefreshTokensReSealed,
            result.FullyOnCurrentKey,
            message));
    }

    /// <summary>
    /// Passes only for a <c>tenantadmin</c> of the management tenant. The caller's token must have
    /// been issued by the management tenant (checked via the <c>tenant_id</c> claim, not Origin, so
    /// shared dev origins don't cause ambiguity), and the caller must hold <c>tenantadmin</c> there.
    /// Returns null on success, or the IResult to short-circuit with.
    /// </summary>
    private static async Task<IResult?> RequireManagementTenantAdminAsync(
        ClaimsPrincipal userPrincipal,
        IFido2DbService dbService)
    {
        if (!Guid.TryParse(userPrincipal.FindFirst(ClaimTypes.NameIdentifier)?.Value, out _))
            return Results.Unauthorized();

        var callerTenantIdStr = userPrincipal.FindFirst("tenant_id")?.Value;
        if (!Guid.TryParse(callerTenantIdStr, out var callerTenantId))
            return Results.Problem("This operation is only available on the management portal.", statusCode: 403);

        var callerTenant = await dbService.GetTenantByIdAsync(callerTenantId);
        if (callerTenant is not { IsManagementTenant: true })
            return Results.Problem("This operation is only available on the management portal.", statusCode: 403);

        var email = (userPrincipal.Identity?.Name ?? "").NormalizeUsername();
        var membership = string.IsNullOrEmpty(email)
            ? null
            : await dbService.GetUserByUsernameForTenantAsync(callerTenant.Id, email);
        if (membership == null || !TenantRoleModel.IsTenantAdmin(membership.Roles))
            return Results.Forbid();

        return null;
    }
}
