using System.Security.Claims;
using Microsoft.AspNetCore.Mvc;
using StackExchange.Redis;

namespace MyPassKeys;

/// <summary>
/// Self-service portal endpoints. A portal user manages the users and roles of the tenants they
/// have a membership role in, from a single management-tenant login. Access is authorized purely
/// by the caller's membership role in the target tenant.
///
/// These exist because a portal access token is signed with the management tenant's keys and only
/// validates against the management origin — it cannot be presented against a customer tenant's
/// own origin (see <see cref="TokenService.ValidateTokenAsync"/>). So portal management is done on
/// the management origin via these endpoints, using the explicit-tenantId data methods.
/// </summary>
public static class PortalEndpoints
{
    public static void MapPortalEndpoints(this IEndpointRouteBuilder app)
    {
        var group = app.MapGroup("tenants/{tenantId:guid}").RequireAuthorization();

        // --- Users of a tenant the caller administers ---
        group.MapGet("users", GetUsers);
        group.MapGet("users/{userId:guid}", GetUserById);
        group.MapPost("users", UpsertUser);
        group.MapPut("users/{userId:guid}", UpdateUser);
        group.MapDelete("users/{userId:guid}", DeleteUser);

        // --- Role assignment (grant/revoke admin to members of the tenant) ---
        group.MapPatch("users/{userId:guid}/roles", UpdateUserRoles);
        group.MapPost("users/{userId:guid}/roles/{roleName}", AddUserRole);
        group.MapDelete("users/{userId:guid}/roles/{roleName}", RemoveUserRole);
        group.MapPost("users/{userId:guid}/revoke-sessions", RevokeUserSessions);

        // --- Role catalog of a tenant the caller administers ---
        group.MapGet("roles", GetRoles);
        group.MapGet("roles/{roleId:guid}", GetRoleById);
        group.MapPost("roles", CreateRole);
        group.MapPut("roles/{roleId:guid}", UpdateRole);
        group.MapDelete("roles/{roleId:guid}", DeleteRole);

        // --- Groups of a tenant the caller administers (see GroupEndpoints for the
        //     same-tenant variants). Writes are tenantadmin-only, so the finer-grained
        //     privilege-escalation guards of GroupEndpoints don't apply here — a tenant
        //     admin of the target tenant may touch any of its groups.
        group.MapGet("groups", GetGroups);
        group.MapGet("groups/{groupId:guid}", GetGroupById);
        group.MapPost("groups", CreateGroup);
        group.MapPut("groups/{groupId:guid}", UpdateGroup);
        group.MapDelete("groups/{groupId:guid}", DeleteGroup);
        group.MapPost("groups/{groupId:guid}/members/users/{userId:guid}", AddGroupUserMember);
        group.MapDelete("groups/{groupId:guid}/members/users/{userId:guid}", RemoveGroupUserMember);
        group.MapPost("groups/{groupId:guid}/members/groups/{childGroupId:guid}", AddGroupGroupMember);
        group.MapDelete("groups/{groupId:guid}/members/groups/{childGroupId:guid}", RemoveGroupGroupMember);
    }

    /// <summary>
    /// Authorizes a portal request against a target tenant. The caller's token must have been
    /// issued by the management tenant (verified via the 'tid' claim, not the request Origin — so
    /// shared origins in local dev don't cause ambiguity). Non-members get 404 (existence hidden);
    /// useradmin-only members on a tenantadmin-required endpoint get 403. Returns (callerId,
    /// target) on success.
    /// </summary>
    internal static async Task<(Guid CallerId, Tenant Target, IResult? Error)> AuthorizeTenantAsync(
        Guid tenantId,
        ClaimsPrincipal userPrincipal,
        IFido2DbService dbService,
        bool tenantAdminRequired)
    {
        var userIdString = userPrincipal.FindFirst(ClaimTypes.NameIdentifier)?.Value;
        if (!Guid.TryParse(userIdString, out var userId))
            return (default, default!, Results.Unauthorized());

        // Verify via the 'tenant_id' JWT claim (not Origin) that the token was issued by the
        // management tenant. Using Origin is ambiguous when multiple tenants share an origin.
        // NOTE: we use "tenant_id" (not "tid") because JwtSecurityTokenHandler maps "tid" to
        // the long-form Microsoft URI in DefaultInboundClaimTypeMap, making FindFirst("tid") fail.
        var callerTenantIdStr = userPrincipal.FindFirst("tenant_id")?.Value;
        if (!Guid.TryParse(callerTenantIdStr, out var callerTenantId))
            return (default, default!, Results.Problem(
                "Portal endpoints are only available on the management portal.", statusCode: 403));
        var callerTenant = await dbService.GetTenantByIdAsync(callerTenantId);
        if (callerTenant is not { IsManagementTenant: true })
            return (default, default!, Results.Problem(
                "Portal endpoints are only available on the management portal.", statusCode: 403));

        var target = await dbService.GetTenantByIdAsync(tenantId);
        if (target == null)
            return (default, default!, Results.NotFound());

        var email = (userPrincipal.Identity?.Name ?? "").NormalizeUsername();
        var membership = string.IsNullOrEmpty(email)
            ? null
            : await dbService.GetUserByUsernameForTenantAsync(tenantId, email);

        if (membership == null || !TenantRoleModel.IsUserAdminOrAbove(membership.Roles))
            return (default, default!, Results.NotFound()); // hide existence from non-members
        if (tenantAdminRequired && !TenantRoleModel.IsTenantAdmin(membership.Roles))
            return (default, default!, Results.Forbid());

        return (userId, target, null);
    }

    /// <summary>
    /// Normalizes a requested role list and verifies every entry exists in the target tenant's
    /// role catalog. Returns the normalized list, or an error IResult if any role is unknown.
    /// </summary>
    private static async Task<(List<string> Roles, IResult? Error)> ValidateRolesForTenantAsync(
        Guid tenantId,
        List<string> requested,
        IFido2DbService dbService)
    {
        var normalized = requested
            .Select(RoleEndpoints.NormalizeRoleName)
            .Where(r => r.Length > 0)
            .Distinct()
            .ToList();

        if (normalized.Count == 0)
            return (normalized, null);

        var catalog = await dbService.GetRolesForTenantAsync(tenantId);
        var known = catalog.Select(r => r.Name).ToHashSet();
        var unknown = normalized.Where(r => !known.Contains(r)).ToList();

        if (unknown.Count > 0)
            return (normalized, Results.BadRequest(
                $"Unknown role(s): {string.Join(", ", unknown)}. Create them first."));

        return (normalized, null);
    }

    /// <summary>Resolves the union of permissions granted by a set of role names in a tenant.</summary>
    private static async Task<List<string>> ResolvePermissionsForTenantAsync(
        Guid tenantId,
        List<string> roleNames,
        IFido2DbService dbService)
    {
        if (roleNames.Count == 0)
            return [];

        var catalog = await dbService.GetRolesForTenantAsync(tenantId);
        return catalog
            .Where(r => roleNames.Contains(r.Name))
            .SelectMany(r => r.Permissions)
            .Distinct()
            .ToList();
    }

    // ----------------------------------------------------------------------------- Users

    private static async Task<IResult> GetUsers(
        Guid tenantId,
        ClaimsPrincipal userPrincipal,
        IFido2DbService dbService)
    {
        var (_, _, error) = await AuthorizeTenantAsync(tenantId, userPrincipal, dbService, tenantAdminRequired: false);
        if (error != null) return error;

        var users = await dbService.GetUsersForTenantAsync(tenantId);
        return Results.Ok(users);
    }

    private static async Task<IResult> GetUserById(
        Guid tenantId,
        Guid userId,
        ClaimsPrincipal userPrincipal,
        IFido2DbService dbService)
    {
        var (_, _, error) = await AuthorizeTenantAsync(tenantId, userPrincipal, dbService, tenantAdminRequired: false);
        if (error != null) return error;

        var user = await dbService.GetUserByIdForTenantAsync(tenantId, userId);
        return user == null ? Results.NotFound() : Results.Ok(user);
    }

    private static async Task<IResult> UpsertUser(
        Guid tenantId,
        [FromBody] UserEndpoints.UpsertUserRequest request,
        ClaimsPrincipal userPrincipal,
        IFido2DbService dbService)
    {
        var (_, _, error) = await AuthorizeTenantAsync(tenantId, userPrincipal, dbService, tenantAdminRequired: false);
        if (error != null) return error;

        if (string.IsNullOrWhiteSpace(request.Username))
            return Results.BadRequest("Username is required.");

        var username = request.Username.NormalizeUsername();
        var existing = await dbService.GetUserByUsernameForTenantAsync(tenantId, username);

        List<string> roles;
        if (request.Roles != null)
        {
            var (validatedRoles, roleError) = await ValidateRolesForTenantAsync(tenantId, request.Roles, dbService);
            if (roleError != null) return roleError;
            roles = validatedRoles;
        }
        else
        {
            roles = existing?.Roles ?? [];
        }

        var user = new Fido2AppUser
        {
            Id = existing?.Id ?? Guid.CreateVersion7(),
            Username = username,
            DisplayName = request.DisplayName,
            Roles = roles,
            CreatedAt = existing?.CreatedAt ?? DateTime.UtcNow
        };

        await dbService.UpsertUserForTenantAsync(tenantId, user);
        return existing == null
            ? Results.Created($"/tenants/{tenantId}/users/{user.Id}", user)
            : Results.Ok(user);
    }

    private static async Task<IResult> UpdateUser(
        Guid tenantId,
        Guid userId,
        [FromBody] UserEndpoints.UpdateUserRequest request,
        ClaimsPrincipal userPrincipal,
        IFido2DbService dbService)
    {
        var (_, _, error) = await AuthorizeTenantAsync(tenantId, userPrincipal, dbService, tenantAdminRequired: false);
        if (error != null) return error;

        var existing = await dbService.GetUserByIdForTenantAsync(tenantId, userId);
        if (existing == null) return Results.NotFound();

        var roles = existing.Roles;
        if (request.Roles != null)
        {
            var (validatedRoles, roleError) = await ValidateRolesForTenantAsync(tenantId, request.Roles, dbService);
            if (roleError != null) return roleError;
            roles = validatedRoles;
        }

        var updated = new Fido2AppUser
        {
            Id = existing.Id,
            TenantId = existing.TenantId,
            Username = existing.Username,
            DisplayName = request.DisplayName ?? existing.DisplayName,
            Roles = roles,
            CreatedAt = existing.CreatedAt
        };

        await dbService.UpsertUserForTenantAsync(tenantId, updated);
        return Results.Ok(updated);
    }

    private static async Task<IResult> DeleteUser(
        Guid tenantId,
        Guid userId,
        ClaimsPrincipal userPrincipal,
        IFido2DbService dbService)
    {
        var (_, _, error) = await AuthorizeTenantAsync(tenantId, userPrincipal, dbService, tenantAdminRequired: true);
        if (error != null) return error;

        var existing = await dbService.GetUserByIdForTenantAsync(tenantId, userId);
        if (existing == null) return Results.NotFound();

        await dbService.DeleteUserForTenantAsync(tenantId, userId);
        return Results.NoContent();
    }

    private static async Task<IResult> UpdateUserRoles(
        Guid tenantId,
        Guid userId,
        [FromBody] UserEndpoints.UpdateUserRolesRequest request,
        ClaimsPrincipal userPrincipal,
        IFido2DbService dbService)
    {
        var (_, _, error) = await AuthorizeTenantAsync(tenantId, userPrincipal, dbService, tenantAdminRequired: true);
        if (error != null) return error;

        var existing = await dbService.GetUserByIdForTenantAsync(tenantId, userId);
        if (existing == null) return Results.NotFound();

        var (roles, roleError) = await ValidateRolesForTenantAsync(tenantId, request.Roles, dbService);
        if (roleError != null) return roleError;

        var updated = new Fido2AppUser
        {
            Id = existing.Id,
            TenantId = existing.TenantId,
            Username = existing.Username,
            DisplayName = existing.DisplayName,
            Roles = roles,
            CreatedAt = existing.CreatedAt
        };

        await dbService.UpsertUserForTenantAsync(tenantId, updated);

        var permissions = await ResolvePermissionsForTenantAsync(tenantId, updated.Roles, dbService);
        return Results.Ok(new UserEndpoints.UserRolesResponse(updated.Id, updated.Roles, permissions));
    }

    private static async Task<IResult> AddUserRole(
        Guid tenantId,
        Guid userId,
        string roleName,
        ClaimsPrincipal userPrincipal,
        IFido2DbService dbService)
    {
        var (_, _, error) = await AuthorizeTenantAsync(tenantId, userPrincipal, dbService, tenantAdminRequired: true);
        if (error != null) return error;

        var user = await dbService.GetUserByIdForTenantAsync(tenantId, userId);
        if (user == null) return Results.NotFound();

        var normalized = RoleEndpoints.NormalizeRoleName(roleName);
        var role = await dbService.GetRoleByNameForTenantAsync(tenantId, normalized);
        if (role == null)
            return Results.BadRequest($"Unknown role '{normalized}'. Create it first.");

        if (!user.Roles.Contains(normalized))
            user.Roles.Add(normalized);

        await dbService.UpsertUserForTenantAsync(tenantId, user);

        var permissions = await ResolvePermissionsForTenantAsync(tenantId, user.Roles, dbService);
        return Results.Ok(new UserEndpoints.UserRolesResponse(user.Id, user.Roles, permissions));
    }

    private static async Task<IResult> RemoveUserRole(
        Guid tenantId,
        Guid userId,
        string roleName,
        ClaimsPrincipal userPrincipal,
        IFido2DbService dbService)
    {
        var (_, _, error) = await AuthorizeTenantAsync(tenantId, userPrincipal, dbService, tenantAdminRequired: true);
        if (error != null) return error;

        var user = await dbService.GetUserByIdForTenantAsync(tenantId, userId);
        if (user == null) return Results.NotFound();

        var normalized = RoleEndpoints.NormalizeRoleName(roleName);
        user.Roles.Remove(normalized);

        await dbService.UpsertUserForTenantAsync(tenantId, user);

        var permissions = await ResolvePermissionsForTenantAsync(tenantId, user.Roles, dbService);
        return Results.Ok(new UserEndpoints.UserRolesResponse(user.Id, user.Roles, permissions));
    }

    private static async Task<IResult> RevokeUserSessions(
        Guid tenantId,
        Guid userId,
        ClaimsPrincipal userPrincipal,
        IFido2DbService dbService,
        IConnectionMultiplexer redis)
    {
        var (_, target, error) = await AuthorizeTenantAsync(tenantId, userPrincipal, dbService, tenantAdminRequired: true);
        if (error != null) return error;

        var user = await dbService.GetUserByIdForTenantAsync(tenantId, userId);
        if (user == null) return Results.NotFound();

        // Revoke refresh tokens, then write a per-user access-token cutoff (same scheme as
        // UserEndpoints) so existing access tokens for this user die immediately.
        await dbService.RevokeUserRefreshTokensForTenantAsync(tenantId, userId);

        var db = redis.GetDatabase();
        await db.StringSetAsync(
            $"user-sessions-revoked:{tenantId}:{userId}",
            DateTimeOffset.UtcNow.ToUnixTimeSeconds(),
            TimeSpan.FromMinutes(target.AccessTokenLifetimeInMinutes));

        return Results.Ok(new UserEndpoints.RevokeSessionsResponse(
            $"All sessions revoked for user {userId}. The user must authenticate again."));
    }

    // ----------------------------------------------------------------------------- Roles

    private static async Task<IResult> GetRoles(
        Guid tenantId,
        ClaimsPrincipal userPrincipal,
        IFido2DbService dbService)
    {
        var (_, _, error) = await AuthorizeTenantAsync(tenantId, userPrincipal, dbService, tenantAdminRequired: false);
        if (error != null) return error;

        var roles = await dbService.GetRolesForTenantAsync(tenantId);
        return Results.Ok(roles);
    }

    private static async Task<IResult> GetRoleById(
        Guid tenantId,
        Guid roleId,
        ClaimsPrincipal userPrincipal,
        IFido2DbService dbService)
    {
        var (_, _, error) = await AuthorizeTenantAsync(tenantId, userPrincipal, dbService, tenantAdminRequired: false);
        if (error != null) return error;

        var role = await dbService.GetRoleByIdForTenantAsync(tenantId, roleId);
        return role == null ? Results.NotFound() : Results.Ok(role);
    }

    private static async Task<IResult> CreateRole(
        Guid tenantId,
        [FromBody] RoleEndpoints.CreateRoleRequest request,
        ClaimsPrincipal userPrincipal,
        IFido2DbService dbService)
    {
        var (_, _, error) = await AuthorizeTenantAsync(tenantId, userPrincipal, dbService, tenantAdminRequired: true);
        if (error != null) return error;

        var name = RoleEndpoints.NormalizeRoleName(request.Name);
        if (string.IsNullOrWhiteSpace(name))
            return Results.BadRequest("Role name is required.");
        if (name.Length > 64)
            return Results.BadRequest("Role name must be 64 characters or fewer.");

        var existing = await dbService.GetRoleByNameForTenantAsync(tenantId, name);
        if (existing != null)
            return Results.Conflict($"A role named '{name}' already exists.");

        var role = new TenantRole
        {
            Name = name,
            DisplayName = string.IsNullOrWhiteSpace(request.DisplayName) ? name : request.DisplayName.Trim(),
            Description = request.Description?.Trim() ?? string.Empty,
            Permissions = RoleEndpoints.NormalizePermissions(request.Permissions),
            CreatedAt = DateTime.UtcNow,
            UpdatedAt = DateTime.UtcNow
        };

        await dbService.UpsertRoleForTenantAsync(tenantId, role);
        return Results.Created($"/tenants/{tenantId}/roles/{role.Id}", role);
    }

    private static async Task<IResult> UpdateRole(
        Guid tenantId,
        Guid roleId,
        [FromBody] RoleEndpoints.UpdateRoleRequest request,
        ClaimsPrincipal userPrincipal,
        IFido2DbService dbService)
    {
        var (_, _, error) = await AuthorizeTenantAsync(tenantId, userPrincipal, dbService, tenantAdminRequired: true);
        if (error != null) return error;

        var role = await dbService.GetRoleByIdForTenantAsync(tenantId, roleId);
        if (role == null) return Results.NotFound();

        // Name is immutable — only descriptive fields and permissions can change.
        if (!string.IsNullOrWhiteSpace(request.DisplayName))
            role.DisplayName = request.DisplayName.Trim();
        if (request.Description != null)
            role.Description = request.Description.Trim();
        if (request.Permissions != null)
            role.Permissions = RoleEndpoints.NormalizePermissions(request.Permissions);
        role.UpdatedAt = DateTime.UtcNow;

        await dbService.UpsertRoleForTenantAsync(tenantId, role);
        return Results.Ok(role);
    }

    private static async Task<IResult> DeleteRole(
        Guid tenantId,
        Guid roleId,
        ClaimsPrincipal userPrincipal,
        IFido2DbService dbService)
    {
        var (_, _, error) = await AuthorizeTenantAsync(tenantId, userPrincipal, dbService, tenantAdminRequired: true);
        if (error != null) return error;

        var role = await dbService.GetRoleByIdForTenantAsync(tenantId, roleId);
        if (role == null) return Results.NotFound();

        // Cascade: strip the role from every user and group that holds it, then delete the catalog entry.
        await dbService.RemoveRoleFromAllUsersForTenantAsync(tenantId, role.Name);
        await dbService.RemoveRoleFromAllGroupsForTenantAsync(tenantId, role.Name);
        await dbService.DeleteRoleForTenantAsync(tenantId, roleId);
        return Results.NoContent();
    }

    // ----------------------------------------------------------------------------- Groups

    private static async Task<IResult> GetGroups(
        Guid tenantId,
        ClaimsPrincipal userPrincipal,
        IFido2DbService dbService)
    {
        var (_, _, error) = await AuthorizeTenantAsync(tenantId, userPrincipal, dbService, tenantAdminRequired: false);
        if (error != null) return error;

        var groups = await dbService.GetGroupsForTenantAsync(tenantId);
        return Results.Ok(groups);
    }

    private static async Task<IResult> GetGroupById(
        Guid tenantId,
        Guid groupId,
        ClaimsPrincipal userPrincipal,
        IFido2DbService dbService)
    {
        var (_, _, error) = await AuthorizeTenantAsync(tenantId, userPrincipal, dbService, tenantAdminRequired: false);
        if (error != null) return error;

        var group = await dbService.GetGroupByIdForTenantAsync(tenantId, groupId);
        return group == null ? Results.NotFound() : Results.Ok(group);
    }

    private static async Task<IResult> CreateGroup(
        Guid tenantId,
        [FromBody] GroupEndpoints.CreateGroupRequest request,
        ClaimsPrincipal userPrincipal,
        IFido2DbService dbService)
    {
        var (_, _, error) = await AuthorizeTenantAsync(tenantId, userPrincipal, dbService, tenantAdminRequired: true);
        if (error != null) return error;

        var name = RoleEndpoints.NormalizeRoleName(request.Name);
        if (string.IsNullOrWhiteSpace(name))
            return Results.BadRequest("Group name is required.");
        if (name.Length > 64)
            return Results.BadRequest("Group name must be 64 characters or fewer.");

        var existing = await dbService.GetGroupByNameForTenantAsync(tenantId, name);
        if (existing != null)
            return Results.Conflict($"A group named '{name}' already exists.");

        // Attached roles must all exist in the target tenant's role catalog.
        var (roles, roleError) = await ValidateRolesForTenantAsync(tenantId, request.Roles ?? [], dbService);
        if (roleError != null) return roleError;

        var group = new TenantGroup
        {
            Name = name,
            DisplayName = string.IsNullOrWhiteSpace(request.DisplayName) ? name : request.DisplayName.Trim(),
            Description = request.Description?.Trim() ?? string.Empty,
            Roles = roles,
            CreatedAt = DateTime.UtcNow,
            UpdatedAt = DateTime.UtcNow
        };

        await dbService.UpsertGroupForTenantAsync(tenantId, group);
        return Results.Created($"/tenants/{tenantId}/groups/{group.Id}", group);
    }

    private static async Task<IResult> UpdateGroup(
        Guid tenantId,
        Guid groupId,
        [FromBody] GroupEndpoints.UpdateGroupRequest request,
        ClaimsPrincipal userPrincipal,
        IFido2DbService dbService)
    {
        var (_, _, error) = await AuthorizeTenantAsync(tenantId, userPrincipal, dbService, tenantAdminRequired: true);
        if (error != null) return error;

        var group = await dbService.GetGroupByIdForTenantAsync(tenantId, groupId);
        if (group == null) return Results.NotFound();

        var roles = group.Roles;
        if (request.Roles != null)
        {
            var (validatedRoles, roleError) = await ValidateRolesForTenantAsync(tenantId, request.Roles, dbService);
            if (roleError != null) return roleError;
            roles = validatedRoles;
        }

        // Name is immutable — only the descriptive fields and attached roles can change.
        if (!string.IsNullOrWhiteSpace(request.DisplayName))
            group.DisplayName = request.DisplayName.Trim();
        if (request.Description != null)
            group.Description = request.Description.Trim();
        group.Roles = roles;
        group.UpdatedAt = DateTime.UtcNow;

        await dbService.UpsertGroupForTenantAsync(tenantId, group);
        return Results.Ok(group);
    }

    private static async Task<IResult> DeleteGroup(
        Guid tenantId,
        Guid groupId,
        ClaimsPrincipal userPrincipal,
        IFido2DbService dbService)
    {
        var (_, _, error) = await AuthorizeTenantAsync(tenantId, userPrincipal, dbService, tenantAdminRequired: true);
        if (error != null) return error;

        var group = await dbService.GetGroupByIdForTenantAsync(tenantId, groupId);
        if (group == null) return Results.NotFound();

        // Cascade (unlinking from nesting groups) happens inside DeleteGroupForTenantAsync.
        // Members keep any roles they hold directly; group-derived roles stop being conferred.
        await dbService.DeleteGroupForTenantAsync(tenantId, groupId);
        return Results.NoContent();
    }

    private static async Task<IResult> AddGroupUserMember(
        Guid tenantId,
        Guid groupId,
        Guid userId,
        ClaimsPrincipal userPrincipal,
        IFido2DbService dbService)
    {
        var (_, _, error) = await AuthorizeTenantAsync(tenantId, userPrincipal, dbService, tenantAdminRequired: true);
        if (error != null) return error;

        var group = await dbService.GetGroupByIdForTenantAsync(tenantId, groupId);
        if (group == null) return Results.NotFound();

        var user = await dbService.GetUserByIdForTenantAsync(tenantId, userId);
        if (user == null) return Results.NotFound("User not found.");

        if (!group.MemberUserIds.Contains(userId))
        {
            group.MemberUserIds.Add(userId);
            group.UpdatedAt = DateTime.UtcNow;
            await dbService.UpsertGroupForTenantAsync(tenantId, group);
        }
        return Results.Ok(group);
    }

    private static async Task<IResult> RemoveGroupUserMember(
        Guid tenantId,
        Guid groupId,
        Guid userId,
        ClaimsPrincipal userPrincipal,
        IFido2DbService dbService)
    {
        var (_, _, error) = await AuthorizeTenantAsync(tenantId, userPrincipal, dbService, tenantAdminRequired: true);
        if (error != null) return error;

        var group = await dbService.GetGroupByIdForTenantAsync(tenantId, groupId);
        if (group == null) return Results.NotFound();

        if (group.MemberUserIds.Remove(userId))
        {
            group.UpdatedAt = DateTime.UtcNow;
            await dbService.UpsertGroupForTenantAsync(tenantId, group);
        }
        return Results.Ok(group);
    }

    private static async Task<IResult> AddGroupGroupMember(
        Guid tenantId,
        Guid groupId,
        Guid childGroupId,
        ClaimsPrincipal userPrincipal,
        IFido2DbService dbService)
    {
        var (_, _, error) = await AuthorizeTenantAsync(tenantId, userPrincipal, dbService, tenantAdminRequired: true);
        if (error != null) return error;

        var allGroups = await dbService.GetGroupsForTenantAsync(tenantId);
        var group = allGroups.FirstOrDefault(g => g.Id == groupId);
        if (group == null) return Results.NotFound();

        var child = allGroups.FirstOrDefault(g => g.Id == childGroupId);
        if (child == null) return Results.NotFound("Member group not found.");

        if (TenantGroupModel.WouldCreateCycle(allGroups, parentGroupId: groupId, childGroupId: childGroupId))
            return Results.BadRequest(
                $"Adding group '{child.Name}' to '{group.Name}' would create a membership cycle.");

        if (!group.MemberGroupIds.Contains(childGroupId))
        {
            group.MemberGroupIds.Add(childGroupId);
            group.UpdatedAt = DateTime.UtcNow;
            await dbService.UpsertGroupForTenantAsync(tenantId, group);
        }
        return Results.Ok(group);
    }

    private static async Task<IResult> RemoveGroupGroupMember(
        Guid tenantId,
        Guid groupId,
        Guid childGroupId,
        ClaimsPrincipal userPrincipal,
        IFido2DbService dbService)
    {
        var (_, _, error) = await AuthorizeTenantAsync(tenantId, userPrincipal, dbService, tenantAdminRequired: true);
        if (error != null) return error;

        var group = await dbService.GetGroupByIdForTenantAsync(tenantId, groupId);
        if (group == null) return Results.NotFound();

        if (group.MemberGroupIds.Remove(childGroupId))
        {
            group.UpdatedAt = DateTime.UtcNow;
            await dbService.UpsertGroupForTenantAsync(tenantId, group);
        }
        return Results.Ok(group);
    }
}
