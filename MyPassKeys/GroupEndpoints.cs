using System.Security.Claims;
using Microsoft.AspNetCore.Mvc;

namespace MyPassKeys;

/// <summary>
/// Endpoints for managing a tenant's AD-style groups (see <see cref="TenantGroup"/>). Groups
/// collect users and other groups (nesting) and carry catalog role names that every direct and
/// transitive member inherits at token issuance. Reads are <b>directory reads</b> — any
/// authenticated tenant member may list groups (group pickers are a plain-member feature).
/// Catalog writes require <c>groups:write</c>/<c>groups:delete</c>; membership changes require
/// <c>groups:members</c> (the built-in groupadmin and tenantadmin roles carry all of these).
/// Because group membership confers roles, every write is subject to the same
/// privilege-escalation guards as role assignment: a caller without <c>roles:manage</c> may not
/// touch a group that confers an admin-equivalent role, nor attach/detach one.
/// </summary>
public static class GroupEndpoints
{
    /// <summary>Request body for creating a group. Members are added via the /members endpoints.</summary>
    public record CreateGroupRequest(string Name, string? DisplayName, string? Description, List<string>? Roles);

    /// <summary>Request body for updating a group. Name is immutable and cannot be changed.</summary>
    public record UpdateGroupRequest(string? DisplayName, string? Description, List<string>? Roles);

    /// <summary>A lightweight group reference used in member listings.</summary>
    public record GroupSummary(Guid Id, string Name, string DisplayName);

    /// <summary>
    /// A group's members. With <c>recursive=true</c>, Users contains every user reachable through
    /// nested groups and Groups contains every transitively nested group.
    /// </summary>
    public record GroupMembersResponse(Guid GroupId, bool Recursive, List<Fido2AppUser> Users, List<GroupSummary> Groups);

    /// <summary>Result of a recursive membership check.</summary>
    public record MembershipCheckResponse(Guid GroupId, Guid UserId, bool IsMember, bool IsDirectMember);

    public static void MapGroupEndpoints(this IEndpointRouteBuilder app)
    {
        var group = app.MapGroup("groups").RequireAuthorization();

        // Directory reads — any authenticated tenant member.
        group.MapGet("/", GetGroups);
        group.MapGet("/{id:guid}", GetGroupById);
        group.MapGet("/{id:guid}/members", GetGroupMembers);
        // Recursive membership check: is the user a member, directly or via nested groups?
        group.MapGet("/{id:guid}/is-member/{userId:guid}", CheckMembership);

        // Catalog writes — 'groups:write' / 'groups:delete' (groupadmin or tenantadmin).
        group.MapPost("/", CreateGroup);
        group.MapPut("/{id:guid}", UpdateGroup);
        group.MapDelete("/{id:guid}", DeleteGroup);

        // Membership writes — 'groups:members' (groupadmin or tenantadmin).
        group.MapPost("/{id:guid}/members/users/{userId:guid}", AddUserMember);
        group.MapDelete("/{id:guid}/members/users/{userId:guid}", RemoveUserMember);
        group.MapPost("/{id:guid}/members/groups/{childGroupId:guid}", AddGroupMember);
        group.MapDelete("/{id:guid}/members/groups/{childGroupId:guid}", RemoveGroupMember);
    }

    private static async Task<IResult> GetGroups(
        ClaimsPrincipal userPrincipal,
        IFido2DbService dbService,
        ITenantService tenantService)
    {
        // Directory read — any authenticated tenant member (see AuthorizeAuthenticatedAsync).
        var (_, _, error) = await UserEndpoints.AuthorizeAuthenticatedAsync(userPrincipal, tenantService);
        if (error != null) return error;

        var groups = await dbService.GetGroupsAsync();
        return Results.Ok(groups);
    }

    private static async Task<IResult> GetGroupById(
        Guid id,
        ClaimsPrincipal userPrincipal,
        IFido2DbService dbService,
        ITenantService tenantService)
    {
        // Directory read — any authenticated tenant member (see AuthorizeAuthenticatedAsync).
        var (_, _, error) = await UserEndpoints.AuthorizeAuthenticatedAsync(userPrincipal, tenantService);
        if (error != null) return error;

        var group = await dbService.GetGroupByIdAsync(id);
        return group == null ? Results.NotFound() : Results.Ok(group);
    }

    private static async Task<IResult> GetGroupMembers(
        Guid id,
        ClaimsPrincipal userPrincipal,
        IFido2DbService dbService,
        ITenantService tenantService,
        bool recursive = false)
    {
        // Directory read — any authenticated tenant member (see AuthorizeAuthenticatedAsync).
        var (_, _, error) = await UserEndpoints.AuthorizeAuthenticatedAsync(userPrincipal, tenantService);
        if (error != null) return error;

        var allGroups = await dbService.GetGroupsAsync();
        var group = allGroups.FirstOrDefault(g => g.Id == id);
        if (group == null) return Results.NotFound();

        List<TenantGroup> memberGroups;
        HashSet<Guid> memberUserIds;
        if (recursive)
        {
            memberGroups = TenantGroupModel.DescendantGroups(allGroups, id);
            memberUserIds = TenantGroupModel.RecursiveMemberUserIds(allGroups, id);
        }
        else
        {
            memberGroups = allGroups.Where(g => group.MemberGroupIds.Contains(g.Id)).ToList();
            memberUserIds = group.MemberUserIds.ToHashSet();
        }

        var users = (await dbService.GetUsersAsync()).Where(u => memberUserIds.Contains(u.Id)).ToList();
        var summaries = memberGroups.Select(g => new GroupSummary(g.Id, g.Name, g.DisplayName)).ToList();
        return Results.Ok(new GroupMembersResponse(id, recursive, users, summaries));
    }

    private static async Task<IResult> CheckMembership(
        Guid id,
        Guid userId,
        ClaimsPrincipal userPrincipal,
        IFido2DbService dbService,
        ITenantService tenantService)
    {
        // Directory read — any authenticated tenant member (see AuthorizeAuthenticatedAsync).
        var (_, _, error) = await UserEndpoints.AuthorizeAuthenticatedAsync(userPrincipal, tenantService);
        if (error != null) return error;

        var allGroups = await dbService.GetGroupsAsync();
        var group = allGroups.FirstOrDefault(g => g.Id == id);
        if (group == null) return Results.NotFound();

        var isDirect = group.MemberUserIds.Contains(userId);
        var isMember = isDirect || TenantGroupModel.IsUserMember(allGroups, id, userId);
        return Results.Ok(new MembershipCheckResponse(id, userId, isMember, isDirect));
    }

    private static async Task<IResult> CreateGroup(
        [FromBody] CreateGroupRequest request,
        ClaimsPrincipal userPrincipal,
        IFido2DbService dbService,
        ITenantService tenantService)
    {
        var (_, _, error) = await UserEndpoints.AuthorizePermissionAsync(userPrincipal, tenantService, Permissions.GroupsWrite);
        if (error != null) return error;

        var name = RoleEndpoints.NormalizeRoleName(request.Name);
        if (string.IsNullOrWhiteSpace(name))
            return Results.BadRequest("Group name is required.");
        if (name.Length > 64)
            return Results.BadRequest("Group name must be 64 characters or fewer.");

        var existing = await dbService.GetGroupByNameAsync(name);
        if (existing != null)
            return Results.Conflict($"A group named '{name}' already exists.");

        // Attached roles must all exist in the tenant's role catalog.
        var (roles, roleError) = await UserEndpoints.ValidateRolesAsync(request.Roles ?? [], dbService);
        if (roleError != null) return roleError;

        var escalationError = await GuardAttachedRoleChangeAsync(userPrincipal, before: [], after: roles, dbService);
        if (escalationError != null) return escalationError;

        var group = new TenantGroup
        {
            Name = name,
            DisplayName = string.IsNullOrWhiteSpace(request.DisplayName) ? name : request.DisplayName.Trim(),
            Description = request.Description?.Trim() ?? string.Empty,
            Roles = roles,
            CreatedAt = DateTime.UtcNow,
            UpdatedAt = DateTime.UtcNow
        };

        await dbService.UpsertGroupAsync(group);
        return Results.Created($"/groups/{group.Id}", group);
    }

    private static async Task<IResult> UpdateGroup(
        Guid id,
        [FromBody] UpdateGroupRequest request,
        ClaimsPrincipal userPrincipal,
        IFido2DbService dbService,
        ITenantService tenantService)
    {
        var (_, _, error) = await UserEndpoints.AuthorizePermissionAsync(userPrincipal, tenantService, Permissions.GroupsWrite);
        if (error != null) return error;

        var allGroups = await dbService.GetGroupsAsync();
        var group = allGroups.FirstOrDefault(g => g.Id == id);
        if (group == null) return Results.NotFound();

        var touchError = await GuardPrivilegedGroupTouchAsync(userPrincipal, allGroups, group, dbService);
        if (touchError != null) return touchError;

        var roles = group.Roles;
        if (request.Roles != null)
        {
            var (validatedRoles, roleError) = await UserEndpoints.ValidateRolesAsync(request.Roles, dbService);
            if (roleError != null) return roleError;
            roles = validatedRoles;
        }

        var escalationError = await GuardAttachedRoleChangeAsync(userPrincipal, before: group.Roles, after: roles, dbService);
        if (escalationError != null) return escalationError;

        // Name is immutable — only the descriptive fields and attached roles can change.
        if (!string.IsNullOrWhiteSpace(request.DisplayName))
            group.DisplayName = request.DisplayName.Trim();
        if (request.Description != null)
            group.Description = request.Description.Trim();
        group.Roles = roles;
        group.UpdatedAt = DateTime.UtcNow;

        await dbService.UpsertGroupAsync(group);
        return Results.Ok(group);
    }

    private static async Task<IResult> DeleteGroup(
        Guid id,
        ClaimsPrincipal userPrincipal,
        IFido2DbService dbService,
        ITenantService tenantService)
    {
        var (_, _, error) = await UserEndpoints.AuthorizePermissionAsync(userPrincipal, tenantService, Permissions.GroupsDelete);
        if (error != null) return error;

        var allGroups = await dbService.GetGroupsAsync();
        var group = allGroups.FirstOrDefault(g => g.Id == id);
        if (group == null) return Results.NotFound();

        var touchError = await GuardPrivilegedGroupTouchAsync(userPrincipal, allGroups, group, dbService);
        if (touchError != null) return touchError;

        // Cascade (unlinking from nesting groups) happens inside DeleteGroupAsync. Members keep
        // any roles they hold directly; group-derived roles simply stop being conferred.
        await dbService.DeleteGroupAsync(id);
        return Results.NoContent();
    }

    private static async Task<IResult> AddUserMember(
        Guid id,
        Guid userId,
        ClaimsPrincipal userPrincipal,
        IFido2DbService dbService,
        ITenantService tenantService)
    {
        var (group, _, error) = await AuthorizeMembershipWriteAsync(id, userPrincipal, dbService, tenantService);
        if (error != null) return error;

        var user = await dbService.GetUserByIdAsync(userId);
        if (user == null) return Results.NotFound("User not found.");

        if (!group!.MemberUserIds.Contains(userId))
        {
            group.MemberUserIds.Add(userId);
            group.UpdatedAt = DateTime.UtcNow;
            await dbService.UpsertGroupAsync(group);
        }
        return Results.Ok(group);
    }

    private static async Task<IResult> RemoveUserMember(
        Guid id,
        Guid userId,
        ClaimsPrincipal userPrincipal,
        IFido2DbService dbService,
        ITenantService tenantService)
    {
        var (group, _, error) = await AuthorizeMembershipWriteAsync(id, userPrincipal, dbService, tenantService);
        if (error != null) return error;

        if (group!.MemberUserIds.Remove(userId))
        {
            group.UpdatedAt = DateTime.UtcNow;
            await dbService.UpsertGroupAsync(group);
        }
        return Results.Ok(group);
    }

    private static async Task<IResult> AddGroupMember(
        Guid id,
        Guid childGroupId,
        ClaimsPrincipal userPrincipal,
        IFido2DbService dbService,
        ITenantService tenantService)
    {
        var (group, allGroups, error) = await AuthorizeMembershipWriteAsync(id, userPrincipal, dbService, tenantService);
        if (error != null) return error;

        var child = allGroups!.FirstOrDefault(g => g.Id == childGroupId);
        if (child == null) return Results.NotFound("Member group not found.");

        if (TenantGroupModel.WouldCreateCycle(allGroups!, parentGroupId: id, childGroupId: childGroupId))
            return Results.BadRequest(
                $"Adding group '{child.Name}' to '{group!.Name}' would create a membership cycle.");

        if (!group!.MemberGroupIds.Contains(childGroupId))
        {
            group.MemberGroupIds.Add(childGroupId);
            group.UpdatedAt = DateTime.UtcNow;
            await dbService.UpsertGroupAsync(group);
        }
        return Results.Ok(group);
    }

    private static async Task<IResult> RemoveGroupMember(
        Guid id,
        Guid childGroupId,
        ClaimsPrincipal userPrincipal,
        IFido2DbService dbService,
        ITenantService tenantService)
    {
        var (group, _, error) = await AuthorizeMembershipWriteAsync(id, userPrincipal, dbService, tenantService);
        if (error != null) return error;

        if (group!.MemberGroupIds.Remove(childGroupId))
        {
            group.UpdatedAt = DateTime.UtcNow;
            await dbService.UpsertGroupAsync(group);
        }
        return Results.Ok(group);
    }

    /// <summary>
    /// Shared gate for the four membership endpoints: requires <c>groups:members</c>, loads the
    /// tenant's groups, resolves the target group (404 if absent) and applies the
    /// privileged-group guard. Returns the group and the full group list on success.
    /// </summary>
    private static async Task<(TenantGroup? Group, List<TenantGroup>? AllGroups, IResult? Error)> AuthorizeMembershipWriteAsync(
        Guid groupId,
        ClaimsPrincipal userPrincipal,
        IFido2DbService dbService,
        ITenantService tenantService)
    {
        var (_, _, error) = await UserEndpoints.AuthorizePermissionAsync(userPrincipal, tenantService, Permissions.GroupsMembers);
        if (error != null) return (null, null, error);

        var allGroups = await dbService.GetGroupsAsync();
        var group = allGroups.FirstOrDefault(g => g.Id == groupId);
        if (group == null) return (null, null, Results.NotFound());

        var touchError = await GuardPrivilegedGroupTouchAsync(userPrincipal, allGroups, group, dbService);
        if (touchError != null) return (null, null, touchError);

        return (group, allGroups, null);
    }

    /// <summary>
    /// Privilege-escalation guard for any write to an existing group by a caller lacking
    /// <c>roles:manage</c>. Because membership confers the group's roles — including roles
    /// inherited from groups this group is nested in — such a caller may not modify, delete or
    /// change the membership of a group whose effective role set contains a privileged
    /// (<c>roles:manage</c>-carrying) role. Otherwise, adding themselves to an admin group would
    /// be a straight escalation. <c>roles:manage</c> holders bypass this.
    /// Returns a 403 IResult on violation, else null.
    /// </summary>
    private static async Task<IResult?> GuardPrivilegedGroupTouchAsync(
        ClaimsPrincipal userPrincipal,
        List<TenantGroup> allGroups,
        TenantGroup group,
        IFido2DbService dbService)
    {
        if (UserEndpoints.HasRoleManage(userPrincipal)) return null;

        var privileged = await UserEndpoints.GetPrivilegedRoleNamesAsync(dbService);
        return TenantGroupModel.EffectiveRoleNames(allGroups, group).Any(privileged.Contains)
            ? Results.Problem("You are not permitted to modify a group that confers administrative roles.", statusCode: StatusCodes.Status403Forbidden)
            : null;
    }

    /// <summary>
    /// Privilege-escalation guard for changing a group's attached roles by a caller lacking
    /// <c>roles:manage</c>: mirroring user-role assignment, they may not attach or detach a
    /// privileged (<c>roles:manage</c>-carrying) role — the privileged subset must be identical
    /// before and after. Returns a 403 IResult on violation, else null.
    /// </summary>
    private static async Task<IResult?> GuardAttachedRoleChangeAsync(
        ClaimsPrincipal userPrincipal,
        IEnumerable<string> before,
        IEnumerable<string> after,
        IFido2DbService dbService)
    {
        if (UserEndpoints.HasRoleManage(userPrincipal)) return null;

        var privileged = await UserEndpoints.GetPrivilegedRoleNamesAsync(dbService);
        var beforePriv = before.Where(privileged.Contains).ToHashSet();
        var afterPriv = after.Where(privileged.Contains).ToHashSet();
        return beforePriv.SetEquals(afterPriv)
            ? null
            : Results.Problem("You are not permitted to attach or detach administrative roles on a group.", statusCode: StatusCodes.Status403Forbidden);
    }
}
