using System.Security.Claims;
using Microsoft.AspNetCore.Mvc;

namespace MyPassKeys;

/// <summary>
/// Endpoints for managing a tenant's role catalog. Roles are tenant-scoped (shared across
/// all of the tenant's hostnames). Reads are <b>directory reads</b> — any authenticated tenant
/// member may list the catalog (role pickers are a plain-member feature); writes require
/// <c>roles:write</c>, but a caller lacking <see cref="ManagePermission"/> is subject to
/// <see cref="GuardRoleWrite"/> — it cannot mint/modify a role more powerful than itself, nor
/// touch an admin-equivalent role. User-to-role assignment lives in <see cref="UserEndpoints"/>
/// under /users/{id}/roles.
/// </summary>
public static class RoleEndpoints
{
    /// <summary>
    /// The permission string that gates role-catalog management and role assignment. The built-in
    /// tenantadmin role carries it implicitly; custom roles may also carry it to delegate role
    /// administration without the rest of tenantadmin.
    /// </summary>
    public const string ManagePermission = "roles:manage";

    /// <summary>Request body for creating a role.</summary>
    public record CreateRoleRequest(string Name, string? DisplayName, string? Description, List<string>? Permissions);

    /// <summary>Request body for updating a role. Name is immutable and cannot be changed.</summary>
    public record UpdateRoleRequest(string? DisplayName, string? Description, List<string>? Permissions);

    public static void MapRoleEndpoints(this IEndpointRouteBuilder app)
    {
        var group = app.MapGroup("roles").RequireAuthorization();

        group.MapGet("/", GetRoles);
        group.MapGet("/{id:guid}", GetRoleById);
        group.MapPost("/", CreateRole);
        group.MapPut("/{id:guid}", UpdateRole);
        group.MapDelete("/{id:guid}", DeleteRole);
    }

    private static async Task<IResult> GetRoles(
        ClaimsPrincipal userPrincipal,
        IFido2DbService dbService,
        ITenantService tenantService)
    {
        // Directory read — any authenticated tenant member (see AuthorizeAuthenticatedAsync).
        var (_, _, error) = await UserEndpoints.AuthorizeAuthenticatedAsync(userPrincipal, tenantService);
        if (error != null) return error;

        var roles = await dbService.GetRolesAsync();
        return Results.Ok(roles);
    }

    private static async Task<IResult> GetRoleById(
        Guid id,
        ClaimsPrincipal userPrincipal,
        IFido2DbService dbService,
        ITenantService tenantService)
    {
        // Directory read — any authenticated tenant member (see AuthorizeAuthenticatedAsync).
        var (_, _, error) = await UserEndpoints.AuthorizeAuthenticatedAsync(userPrincipal, tenantService);
        if (error != null) return error;

        var role = await dbService.GetRoleByIdAsync(id);
        return role == null ? Results.NotFound() : Results.Ok(role);
    }

    private static async Task<IResult> CreateRole(
        [FromBody] CreateRoleRequest request,
        ClaimsPrincipal userPrincipal,
        IFido2DbService dbService,
        ITenantService tenantService)
    {
        var (_, _, error) = await UserEndpoints.AuthorizePermissionAsync(userPrincipal, tenantService, Permissions.RolesWrite);
        if (error != null) return error;

        var name = NormalizeRoleName(request.Name);
        if (string.IsNullOrWhiteSpace(name))
            return Results.BadRequest("Role name is required.");
        if (name.Length > 64)
            return Results.BadRequest("Role name must be 64 characters or fewer.");

        var existing = await dbService.GetRoleByNameAsync(name);
        if (existing != null)
            return Results.Conflict($"A role named '{name}' already exists.");

        var permissions = NormalizePermissions(request.Permissions);
        var escalationError = GuardRoleWrite(userPrincipal, existingPermissions: null, resultingPermissions: permissions);
        if (escalationError != null) return escalationError;

        var role = new TenantRole
        {
            Name = name,
            DisplayName = string.IsNullOrWhiteSpace(request.DisplayName) ? name : request.DisplayName.Trim(),
            Description = request.Description?.Trim() ?? string.Empty,
            Permissions = permissions,
            CreatedAt = DateTime.UtcNow,
            UpdatedAt = DateTime.UtcNow
        };

        await dbService.UpsertRoleAsync(role);
        return Results.Created($"/roles/{role.Id}", role);
    }

    private static async Task<IResult> UpdateRole(
        Guid id,
        [FromBody] UpdateRoleRequest request,
        ClaimsPrincipal userPrincipal,
        IFido2DbService dbService,
        ITenantService tenantService)
    {
        var (_, _, error) = await UserEndpoints.AuthorizePermissionAsync(userPrincipal, tenantService, Permissions.RolesWrite);
        if (error != null) return error;

        var role = await dbService.GetRoleByIdAsync(id);
        if (role == null) return Results.NotFound();

        var resultingPermissions = request.Permissions != null ? NormalizePermissions(request.Permissions) : role.Permissions;
        var escalationError = GuardRoleWrite(userPrincipal, existingPermissions: role.Permissions, resultingPermissions: resultingPermissions);
        if (escalationError != null) return escalationError;

        // Name is immutable — only the descriptive fields and permissions can change.
        if (!string.IsNullOrWhiteSpace(request.DisplayName))
            role.DisplayName = request.DisplayName.Trim();
        if (request.Description != null)
            role.Description = request.Description.Trim();
        if (request.Permissions != null)
            role.Permissions = resultingPermissions;
        role.UpdatedAt = DateTime.UtcNow;

        await dbService.UpsertRoleAsync(role);
        return Results.Ok(role);
    }

    private static async Task<IResult> DeleteRole(
        Guid id,
        ClaimsPrincipal userPrincipal,
        IFido2DbService dbService,
        ITenantService tenantService)
    {
        var (_, _, error) = await UserEndpoints.AuthorizePermissionAsync(userPrincipal, tenantService, Permissions.RolesDelete);
        if (error != null) return error;

        var role = await dbService.GetRoleByIdAsync(id);
        if (role == null) return Results.NotFound();

        var escalationError = GuardRoleWrite(userPrincipal, existingPermissions: role.Permissions, resultingPermissions: null);
        if (escalationError != null) return escalationError;

        // Cascade: strip the role from every user and group that holds it, then delete the
        // catalog entry. Note: already-issued access tokens keep the role until they expire.
        await dbService.RemoveRoleFromAllUsersAsync(role.Name);
        await dbService.RemoveRoleFromAllGroupsAsync(role.Name);
        await dbService.DeleteRoleAsync(id);
        return Results.NoContent();
    }

    /// <summary>
    /// Privilege-escalation guard for role-catalog writes by a caller lacking <c>roles:manage</c>
    /// (e.g. a useradmin using <c>roles:write</c>). Such a caller:
    ///  (a) may not create or modify a role whose resulting permission set contains any permission
    ///      they do not themselves hold — so they cannot mint a role more powerful than themselves
    ///      (blocks adding <c>roles:manage</c>, <c>tenant:settings:*</c>, etc.); and
    ///  (b) may not modify or delete a role that already carries <c>roles:manage</c> (the built-in
    ///      tenantadmin or any custom admin-equivalent role).
    /// <c>roles:manage</c> holders bypass all of this. Pass <paramref name="resultingPermissions"/>
    /// null for a delete. Returns a 403 IResult on violation, else null.
    /// </summary>
    private static IResult? GuardRoleWrite(
        ClaimsPrincipal userPrincipal,
        List<string>? existingPermissions,
        List<string>? resultingPermissions)
    {
        if (UserEndpoints.HasRoleManage(userPrincipal)) return null;

        // (b) don't let a non-admin caller touch an existing admin-equivalent role.
        if (existingPermissions != null && existingPermissions.Contains(ManagePermission))
            return Results.Problem("You are not permitted to modify or delete a role that grants 'roles:manage'.", statusCode: StatusCodes.Status403Forbidden);

        // (a) can't grant permissions you don't hold yourself.
        if (resultingPermissions != null)
        {
            var callerPerms = (userPrincipal.FindFirst("scp")?.Value ?? "")
                .Split(' ', StringSplitOptions.RemoveEmptyEntries).ToHashSet();
            var escalating = resultingPermissions.Where(p => !callerPerms.Contains(p)).ToList();
            if (escalating.Count > 0)
                return Results.Problem($"You cannot grant permissions you do not hold: {string.Join(", ", escalating)}.", statusCode: StatusCodes.Status403Forbidden);
        }

        return null;
    }

    /// <summary>Trims and lower-cases a role name to its canonical, tenant-unique form.</summary>
    internal static string NormalizeRoleName(string? name) => name?.Trim().ToLowerInvariant() ?? string.Empty;

    /// <summary>
    /// Trims, lower-cases, de-duplicates and drops empty entries from a permission list.
    /// </summary>
    internal static List<string> NormalizePermissions(List<string>? permissions) =>
        (permissions ?? [])
            .Select(p => p.Trim().ToLowerInvariant())
            .Where(p => p.Length > 0)
            .Distinct()
            .ToList();
}
