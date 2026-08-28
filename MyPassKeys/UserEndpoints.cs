using System.Security.Claims;
using Microsoft.AspNetCore.Mvc;
using StackExchange.Redis;

namespace MyPassKeys;

public static class UserEndpoints
{
    public record UpsertUserRequest(string Username, string DisplayName, List<string>? Roles);
    public record UpdateUserRolesRequest(List<string> Roles);

    /// <summary>
    /// Request body for editing an existing user. Both fields are optional — only the
    /// supplied fields are applied. Username is the user's stable identity and is not editable.
    /// </summary>
    public record UpdateUserRequest(string? DisplayName, List<string>? Roles);

    /// <summary>A user's effective roles plus the permissions those roles grant.</summary>
    public record UserRolesResponse(Guid UserId, List<string> Roles, List<string> Permissions);

    /// <summary>The current user's profile plus the permissions granted by their roles.</summary>
    public record MeResponse(Fido2AppUser User, List<string> Permissions);

    /// <summary>Result of a session-revocation request.</summary>
    public record RevokeSessionsResponse(string Message);

    public static void MapUserEndpoints(this IEndpointRouteBuilder app)
    {
        var group = app.MapGroup("users").RequireAuthorization();

        // Directory reads — any authenticated tenant member (people pickers are a plain-member
        // feature; see AuthorizeAuthenticatedAsync).
        group.MapGet("/", GetUsers);
        // The authenticated caller's own profile + effective permissions (any authenticated user).
        group.MapGet("/me", GetMe);
        group.MapGet("/{id:guid}", GetUserById);
        // Create a user account (upsert by username) — 'users:write' (tenantadmin or useradmin).
        group.MapPost("/", UpsertUser);
        // Edit an existing user account — 'users:write' (tenantadmin or useradmin).
        group.MapPut("/{id:guid}", UpdateUser);

        // The groups the user belongs to — recursive (direct + via nesting) by default,
        // ?recursive=false for direct memberships only. Directory read.
        group.MapGet("/{id:guid}/groups", GetUserGroups);

        // --- Role assignment ('users:write'; privileged-role changes need 'roles:manage') ---
        group.MapGet("/{id:guid}/roles", GetUserRoles);
        // Replace the user's entire role set
        group.MapPatch("/{id:guid}/roles", UpdateUserRoles);
        // Assign / unassign a single role
        group.MapPost("/{id:guid}/roles/{roleName}", AddUserRole);
        group.MapDelete("/{id:guid}/roles/{roleName}", RemoveUserRole);

        // Force this user to re-authenticate ('roles:manage' holders).
        group.MapPost("/{id:guid}/revoke-sessions", RevokeUserSessions);

        // Delete a user account — 'users:delete'; cannot delete an admin user without 'roles:manage'.
        group.MapDelete("/{id:guid}", DeleteUser);
    }


    /// <summary>
    /// Verifies the caller carries the <see cref="RoleEndpoints.ManagePermission"/> permission,
    /// which the built-in tenantadmin role grants. Custom roles may also carry it to delegate role
    /// administration. The permission is read from the caller's access token, so a freshly granted
    /// (or revoked) 'roles:manage' permission only takes effect on the caller's next token issuance.
    /// Returns (userId, tenant) on success or an error IResult.
    /// </summary>
    internal static Task<(Guid UserId, Tenant Tenant, IResult? Error)> AuthorizeRoleManagerAsync(
        ClaimsPrincipal userPrincipal,
        ITenantService tenantService) =>
        AuthorizePermissionAsync(userPrincipal, tenantService, RoleEndpoints.ManagePermission);

    /// <summary>
    /// Verifies the caller is authenticated, resolves the current tenant, and checks that the
    /// caller's access token carries <paramref name="requiredPermission"/> (read from the
    /// space-delimited 'scp' claim). Because permissions are read from the token, a freshly
    /// granted or revoked permission only takes effect on the caller's next token issuance.
    /// Returns (userId, tenant) on success or an error IResult.
    /// </summary>
    internal static async Task<(Guid UserId, Tenant Tenant, IResult? Error)> AuthorizePermissionAsync(
        ClaimsPrincipal userPrincipal,
        ITenantService tenantService,
        string requiredPermission)
    {
        var userIdString = userPrincipal.FindFirst(ClaimTypes.NameIdentifier)?.Value;
        if (!Guid.TryParse(userIdString, out var userId))
            return (default, default!, Results.Unauthorized());

        var tenant = await tenantService.GetCurrentTenantAsync();
        if (tenant == null)
            return (default, default!, Results.NotFound("Tenant not found."));

        var scp = userPrincipal.FindFirst("scp")?.Value ?? "";
        if (!scp.Split(' ').Contains(requiredPermission))
            return (default, default!, Results.Forbid());

        return (userId, tenant, null);
    }

    /// <summary>
    /// Verifies the caller is authenticated for the current tenant — no permission required.
    /// Gates the tenant's <b>directory reads</b> (user list, role catalog): like the Azure AD /
    /// SharePoint model, every signed-in member may enumerate who exists and which roles exist,
    /// because people/role pickers (e.g. an ACL editor granting a colleague access) are a
    /// plain-member feature, not an admin one. Directory data is limited to id, username,
    /// display name and role names — credentials/tokens are separate documents and are never
    /// exposed here. Writes keep their 'users:write'/'roles:write' scopes.
    /// </summary>
    internal static async Task<(Guid UserId, Tenant Tenant, IResult? Error)> AuthorizeAuthenticatedAsync(
        ClaimsPrincipal userPrincipal,
        ITenantService tenantService)
    {
        var userIdString = userPrincipal.FindFirst(ClaimTypes.NameIdentifier)?.Value;
        if (!Guid.TryParse(userIdString, out var userId))
            return (default, default!, Results.Unauthorized());

        var tenant = await tenantService.GetCurrentTenantAsync();
        if (tenant == null)
            return (default, default!, Results.NotFound("Tenant not found."));

        return (userId, tenant, null);
    }

    /// <summary>
    /// Authorizes a caller to assign or revoke a user's roles. Either a <c>roles:manage</c> holder
    /// (tenantadmin — full role administration) or a <c>users:write</c> holder (useradmin) may manage
    /// assignments. The returned <c>CanManagePrivileged</c> flag is true only for <c>roles:manage</c>
    /// holders; callers without it must not grant or revoke privileged roles (see
    /// <see cref="GuardPrivilegedRoleChangeAsync"/>) — this stops a useradmin from escalating a user
    /// (or themselves) to tenantadmin. Returns (canManagePrivileged, tenant) on success or an error.
    /// </summary>
    internal static async Task<(bool CanManagePrivileged, Tenant Tenant, IResult? Error)> AuthorizeRoleAssignerAsync(
        ClaimsPrincipal userPrincipal,
        ITenantService tenantService)
    {
        if (!Guid.TryParse(userPrincipal.FindFirst(ClaimTypes.NameIdentifier)?.Value, out _))
            return (false, default!, Results.Unauthorized());

        var tenant = await tenantService.GetCurrentTenantAsync();
        if (tenant == null)
            return (false, default!, Results.NotFound("Tenant not found."));

        var scp = (userPrincipal.FindFirst("scp")?.Value ?? "").Split(' ');
        var canManagePrivileged = scp.Contains(RoleEndpoints.ManagePermission);
        if (!canManagePrivileged && !scp.Contains(Permissions.UsersWrite))
            return (false, tenant, Results.Forbid());

        return (canManagePrivileged, tenant, null);
    }

    /// <summary>
    /// Guards against privilege escalation when a non-<c>roles:manage</c> caller changes a user's
    /// roles. A "privileged" role is one whose permission set carries <c>roles:manage</c> (the
    /// built-in tenantadmin or any custom admin-equivalent). Such a caller may not change the user's
    /// privileged-role membership at all — neither grant nor revoke — so the set of privileged roles
    /// must be identical before and after. Returns a 403 IResult on violation, else null.
    /// </summary>
    private static async Task<IResult?> GuardPrivilegedRoleChangeAsync(
        bool canManagePrivileged,
        IEnumerable<string> before,
        IEnumerable<string> after,
        IFido2DbService dbService)
    {
        if (canManagePrivileged) return null;

        var privileged = await GetPrivilegedRoleNamesAsync(dbService);
        var beforePriv = before.Where(privileged.Contains).ToHashSet();
        var afterPriv = after.Where(privileged.Contains).ToHashSet();
        return beforePriv.SetEquals(afterPriv)
            ? null
            : Results.Problem("You are not permitted to grant or revoke administrative roles.", statusCode: StatusCodes.Status403Forbidden);
    }

    /// <summary>True if the caller's token carries <c>roles:manage</c> (full role/admin authority).</summary>
    internal static bool HasRoleManage(ClaimsPrincipal userPrincipal) =>
        (userPrincipal.FindFirst("scp")?.Value ?? "").Split(' ').Contains(RoleEndpoints.ManagePermission);

    /// <summary>
    /// The names of every catalog role that is "privileged" — i.e. whose permission set carries
    /// <c>roles:manage</c> (the built-in tenantadmin or any custom admin-equivalent role).
    /// </summary>
    internal static async Task<HashSet<string>> GetPrivilegedRoleNamesAsync(IFido2DbService dbService)
    {
        var catalog = await dbService.GetRolesAsync();
        return catalog
            .Where(r => r.Permissions.Contains(RoleEndpoints.ManagePermission))
            .Select(r => r.Name)
            .ToHashSet();
    }

    /// <summary>
    /// Normalizes a requested role list and verifies every entry exists in the tenant's role catalog.
    /// Returns the normalized list, or an error IResult if any role is unknown.
    /// </summary>
    internal static async Task<(List<string> Roles, IResult? Error)> ValidateRolesAsync(
        List<string> requested,
        IFido2DbService dbService)
    {
        var normalized = requested
            .Select(r => r.Trim().ToLowerInvariant())
            .Where(r => r.Length > 0)
            .Distinct()
            .ToList();

        if (normalized.Count == 0)
            return (normalized, null);

        var catalog = await dbService.GetRolesAsync();
        var known = catalog.Select(r => r.Name).ToHashSet();
        var unknown = normalized.Where(r => !known.Contains(r)).ToList();

        if (unknown.Count > 0)
            return (normalized, Results.BadRequest(
                $"Unknown role(s): {string.Join(", ", unknown)}. Create them via POST /roles first."));

        return (normalized, null);
    }

    /// <summary>Resolves the union of permissions granted by a set of role names.</summary>
    private static async Task<List<string>> ResolvePermissionsAsync(
        List<string> roleNames,
        IFido2DbService dbService)
    {
        if (roleNames.Count == 0)
            return [];

        var catalog = await dbService.GetRolesAsync();
        return catalog
            .Where(r => roleNames.Contains(r.Name))
            .SelectMany(r => r.Permissions)
            .Distinct()
            .ToList();
    }

    /// <summary>
    /// A user's effective role names: their direct roles plus roles inherited from group
    /// membership (direct and via nested groups) — the same set token issuance emits. The
    /// Roles fields in responses stay direct-only (that's the editable state); permissions
    /// are resolved from this effective set so they match what the user's tokens carry.
    /// </summary>
    private static async Task<List<string>> ResolveEffectiveRolesAsync(
        Fido2AppUser user,
        IFido2DbService dbService)
    {
        var groups = await dbService.GetGroupsAsync();
        return user.Roles
            .Concat(TenantGroupModel.RoleNamesForUser(groups, user.Id))
            .Distinct(StringComparer.Ordinal)
            .ToList();
    }

    private static async Task<IResult> GetUsers(
        ClaimsPrincipal userPrincipal,
        IFido2DbService dbService,
        ITenantService tenantService)
    {
        // Directory read — any authenticated tenant member (see AuthorizeAuthenticatedAsync).
        var (_, _, error) = await AuthorizeAuthenticatedAsync(userPrincipal, tenantService);
        if (error != null) return error;

        var users = await dbService.GetUsersAsync();
        return Results.Ok(users);
    }

    private static async Task<IResult> GetMe(
        ClaimsPrincipal userPrincipal,
        IFido2DbService dbService)
    {
        var userIdString = userPrincipal.FindFirst(ClaimTypes.NameIdentifier)?.Value;
        if (!Guid.TryParse(userIdString, out var userId))
            return Results.Unauthorized();

        var user = await dbService.GetUserByIdAsync(userId);
        if (user == null) return Results.NotFound();

        var permissions = await ResolvePermissionsAsync(await ResolveEffectiveRolesAsync(user, dbService), dbService);
        return Results.Ok(new MeResponse(user, permissions));
    }

    private static async Task<IResult> GetUserById(
        Guid id,
        ClaimsPrincipal userPrincipal,
        IFido2DbService dbService,
        ITenantService tenantService)
    {
        // Directory read — any authenticated tenant member (see AuthorizeAuthenticatedAsync).
        var (_, _, error) = await AuthorizeAuthenticatedAsync(userPrincipal, tenantService);
        if (error != null) return error;

        var user = await dbService.GetUserByIdAsync(id);
        return user == null ? Results.NotFound() : Results.Ok(user);
    }

    private static async Task<IResult> UpsertUser(
        [FromBody] UpsertUserRequest request,
        ClaimsPrincipal userPrincipal,
        IFido2DbService dbService,
        ITenantService tenantService)
    {
        var (canManagePrivileged, _, error) = await AuthorizeRoleAssignerAsync(userPrincipal, tenantService);
        if (error != null) return error;

        if (string.IsNullOrWhiteSpace(request.Username))
            return Results.BadRequest("Username is required.");

        var existing = await dbService.GetUserByUsernameAsync(request.Username);

        // Roles, when supplied, must all exist in the tenant's role catalog.
        List<string> roles;
        if (request.Roles != null)
        {
            var (validatedRoles, roleError) = await ValidateRolesAsync(request.Roles, dbService);
            if (roleError != null) return roleError;
            roles = validatedRoles;
        }
        else
        {
            roles = existing?.Roles ?? [];
        }

        // A useradmin (no roles:manage) may create/edit users but must not set a privileged role
        // via the Roles field — same escalation guard as the role-assignment endpoints.
        var escalationError = await GuardPrivilegedRoleChangeAsync(canManagePrivileged, existing?.Roles ?? [], roles, dbService);
        if (escalationError != null) return escalationError;

        var user = new Fido2AppUser
        {
            Id = existing?.Id ?? Guid.CreateVersion7(),
            Username = request.Username,
            DisplayName = request.DisplayName,
            Roles = roles,
            CreatedAt = existing?.CreatedAt ?? DateTime.UtcNow
        };

        await dbService.UpsertUserAsync(user);
        return existing == null ? Results.Created($"/users/{user.Id}", user) : Results.Ok(user);
    }

    private static async Task<IResult> UpdateUser(
        Guid id,
        [FromBody] UpdateUserRequest request,
        ClaimsPrincipal userPrincipal,
        IFido2DbService dbService,
        ITenantService tenantService)
    {
        var (canManagePrivileged, _, error) = await AuthorizeRoleAssignerAsync(userPrincipal, tenantService);
        if (error != null) return error;

        var existing = await dbService.GetUserByIdAsync(id);
        if (existing == null) return Results.NotFound();

        // Roles, when supplied, must all exist in the tenant's role catalog.
        var roles = existing.Roles;
        if (request.Roles != null)
        {
            var (validatedRoles, roleError) = await ValidateRolesAsync(request.Roles, dbService);
            if (roleError != null) return roleError;
            roles = validatedRoles;
        }

        // A useradmin (no roles:manage) may edit users but must not add/remove a privileged role
        // via the Roles field — same escalation guard as the role-assignment endpoints.
        var escalationError = await GuardPrivilegedRoleChangeAsync(canManagePrivileged, existing.Roles, roles, dbService);
        if (escalationError != null) return escalationError;

        // Username is the user's stable identity (WebAuthn handle) and cannot be changed here.
        var updated = new Fido2AppUser
        {
            Id = existing.Id,
            TenantId = existing.TenantId,
            Username = existing.Username,
            DisplayName = request.DisplayName ?? existing.DisplayName,
            Roles = roles,
            CreatedAt = existing.CreatedAt
        };

        await dbService.UpsertUserAsync(updated);
        return Results.Ok(updated);
    }

    private static async Task<IResult> GetUserGroups(
        Guid id,
        ClaimsPrincipal userPrincipal,
        IFido2DbService dbService,
        ITenantService tenantService,
        bool recursive = true)
    {
        // Directory read — any authenticated tenant member (see AuthorizeAuthenticatedAsync).
        var (_, _, error) = await AuthorizeAuthenticatedAsync(userPrincipal, tenantService);
        if (error != null) return error;

        var user = await dbService.GetUserByIdAsync(id);
        if (user == null) return Results.NotFound();

        var allGroups = await dbService.GetGroupsAsync();
        var groups = recursive
            ? TenantGroupModel.GroupsForUser(allGroups, id)
            : allGroups.Where(g => g.MemberUserIds.Contains(id)).ToList();
        return Results.Ok(groups);
    }

    private static async Task<IResult> GetUserRoles(
        Guid id,
        ClaimsPrincipal userPrincipal,
        IFido2DbService dbService,
        ITenantService tenantService)
    {
        // Directory read — any authenticated tenant member (see AuthorizeAuthenticatedAsync).
        var (_, _, error) = await AuthorizeAuthenticatedAsync(userPrincipal, tenantService);
        if (error != null) return error;

        var user = await dbService.GetUserByIdAsync(id);
        if (user == null) return Results.NotFound();

        var permissions = await ResolvePermissionsAsync(await ResolveEffectiveRolesAsync(user, dbService), dbService);
        return Results.Ok(new UserRolesResponse(user.Id, user.Roles, permissions));
    }

    private static async Task<IResult> UpdateUserRoles(
        Guid id,
        [FromBody] UpdateUserRolesRequest request,
        ClaimsPrincipal userPrincipal,
        IFido2DbService dbService,
        ITenantService tenantService)
    {
        var (canManagePrivileged, _, error) = await AuthorizeRoleAssignerAsync(userPrincipal, tenantService);
        if (error != null) return error;

        var existing = await dbService.GetUserByIdAsync(id);
        if (existing == null) return Results.NotFound();

        var (roles, roleError) = await ValidateRolesAsync(request.Roles, dbService);
        if (roleError != null) return roleError;

        var escalationError = await GuardPrivilegedRoleChangeAsync(canManagePrivileged, existing.Roles, roles, dbService);
        if (escalationError != null) return escalationError;

        var updated = new Fido2AppUser
        {
            Id = existing.Id,
            TenantId = existing.TenantId,
            Username = existing.Username,
            DisplayName = existing.DisplayName,
            Roles = roles,
            CreatedAt = existing.CreatedAt
        };

        await dbService.UpsertUserAsync(updated);

        var permissions = await ResolvePermissionsAsync(await ResolveEffectiveRolesAsync(updated, dbService), dbService);
        return Results.Ok(new UserRolesResponse(updated.Id, updated.Roles, permissions));
    }

    private static async Task<IResult> AddUserRole(
        Guid id,
        string roleName,
        ClaimsPrincipal userPrincipal,
        IFido2DbService dbService,
        ITenantService tenantService)
    {
        var (canManagePrivileged, _, error) = await AuthorizeRoleAssignerAsync(userPrincipal, tenantService);
        if (error != null) return error;

        var user = await dbService.GetUserByIdAsync(id);
        if (user == null) return Results.NotFound();

        var normalized = roleName.Trim().ToLowerInvariant();
        var role = await dbService.GetRoleByNameAsync(normalized);
        if (role == null)
            return Results.BadRequest($"Unknown role '{normalized}'. Create it via POST /roles first.");

        // Privilege-escalation guard: a caller without roles:manage (e.g. a useradmin) may not
        // grant a role that itself carries roles:manage (tenantadmin or a custom admin role).
        if (!canManagePrivileged && role.Permissions.Contains(RoleEndpoints.ManagePermission))
            return Results.Problem("You are not permitted to grant administrative roles.", statusCode: StatusCodes.Status403Forbidden);

        if (!user.Roles.Contains(normalized))
            user.Roles.Add(normalized);

        await dbService.UpsertUserAsync(user);

        var permissions = await ResolvePermissionsAsync(await ResolveEffectiveRolesAsync(user, dbService), dbService);
        return Results.Ok(new UserRolesResponse(user.Id, user.Roles, permissions));
    }

    private static async Task<IResult> RemoveUserRole(
        Guid id,
        string roleName,
        ClaimsPrincipal userPrincipal,
        IFido2DbService dbService,
        ITenantService tenantService)
    {
        var (canManagePrivileged, _, error) = await AuthorizeRoleAssignerAsync(userPrincipal, tenantService);
        if (error != null) return error;

        var user = await dbService.GetUserByIdAsync(id);
        if (user == null) return Results.NotFound();

        var normalized = roleName.Trim().ToLowerInvariant();

        // Privilege-escalation guard: a caller without roles:manage (e.g. a useradmin) may not
        // revoke a privileged role either — lower tiers don't manage admin membership at all. A
        // role missing from the catalog (already deleted) carries no permissions, so removing that
        // stale name is harmless cleanup and is allowed.
        if (!canManagePrivileged)
        {
            var role = await dbService.GetRoleByNameAsync(normalized);
            if (role != null && role.Permissions.Contains(RoleEndpoints.ManagePermission))
                return Results.Problem("You are not permitted to revoke administrative roles.", statusCode: StatusCodes.Status403Forbidden);
        }

        user.Roles.Remove(normalized);

        await dbService.UpsertUserAsync(user);

        var permissions = await ResolvePermissionsAsync(await ResolveEffectiveRolesAsync(user, dbService), dbService);
        return Results.Ok(new UserRolesResponse(user.Id, user.Roles, permissions));
    }

    private static async Task<IResult> RevokeUserSessions(
        Guid id,
        ClaimsPrincipal userPrincipal,
        IFido2DbService dbService,
        ITenantService tenantService,
        IConnectionMultiplexer redis)
    {
        var (_, tenant, error) = await AuthorizeRoleManagerAsync(userPrincipal, tenantService);
        if (error != null) return error;

        var user = await dbService.GetUserByIdAsync(id);
        if (user == null) return Results.NotFound();

        // 1. Revoke the user's refresh tokens so they cannot mint new access tokens.
        await dbService.RevokeUserRefreshTokensAsync(id);

        // 2. Write a per-user cutoff to Redis so existing access tokens are rejected
        //    immediately. The key's TTL equals the access-token lifetime — once that elapses
        //    every pre-revocation token has expired on its own and the cutoff is moot.
        var db = redis.GetDatabase();
        await db.StringSetAsync(
            $"user-sessions-revoked:{tenant.Id}:{id}",
            DateTimeOffset.UtcNow.ToUnixTimeSeconds(),
            TimeSpan.FromMinutes(tenant.AccessTokenLifetimeInMinutes));

        return Results.Ok(new RevokeSessionsResponse(
            $"All sessions revoked for user {id}. The user must authenticate again."));
    }

    private static async Task<IResult> DeleteUser(
        Guid id,
        ClaimsPrincipal userPrincipal,
        IFido2DbService dbService,
        ITenantService tenantService)
    {
        var (userId, _, error) = await AuthorizePermissionAsync(userPrincipal, tenantService, Permissions.UsersDelete);
        if (error != null) return error;

        // Prevent deleting your own account.
        if (id == userId)
            return Results.Problem("Cannot delete your own account.", statusCode: 400);

        var existing = await dbService.GetUserByIdAsync(id);
        if (existing == null) return Results.NotFound();

        // Privilege-escalation guard: a caller without roles:manage (e.g. a useradmin) may delete
        // users but not one holding a privileged (tenantadmin-equivalent) role.
        if (!HasRoleManage(userPrincipal))
        {
            var privileged = await GetPrivilegedRoleNamesAsync(dbService);
            if (existing.Roles.Any(privileged.Contains))
                return Results.Problem("You are not permitted to delete administrative users.", statusCode: StatusCodes.Status403Forbidden);
        }

        await dbService.DeleteUserAsync(id);
        return Results.NoContent();
    }
}
