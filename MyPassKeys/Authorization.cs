namespace MyPassKeys;

/// <summary>
/// Built-in per-tenant role names, seeded into every tenant's role catalog on creation. Stored
/// normalized (lower-case); the canonical display form used by the frontend's <c>myRole</c>
/// field comes from <see cref="TenantRoleModel.MyRole"/>.
/// </summary>
public static class BuiltInTenantRoles
{
    public const string TenantAdmin = "tenantadmin";
    public const string UserAdmin = "useradmin";

    /// <summary>
    /// Delegated group administration: manage the tenant's group catalog and group membership
    /// (users and nested groups), plus read-only visibility into users and roles so members and
    /// roles can be picked. Bounded by the same escalation guards as useradmin — it cannot touch
    /// a group that confers an admin-equivalent (<c>roles:manage</c>) role.
    /// </summary>
    public const string GroupAdmin = "groupadmin";

    /// <summary>
    /// Baseline role for ordinary members of the tenant's application. Grants read-only visibility
    /// into the tenant's users and role catalog (<c>users:read</c> + <c>roles:read</c>) and nothing
    /// else — assign it to end users who should be able to list users/roles without any admin power.
    /// </summary>
    public const string App = "app";
}

/// <summary>Fine-grained permission strings granted by roles and emitted as <c>permissions</c> claims.</summary>
public static class Permissions
{
    public const string UsersRead = "users:read";
    public const string UsersWrite = "users:write";
    public const string UsersDelete = "users:delete";
    public const string RolesRead = "roles:read";
    public const string RolesWrite = "roles:write";
    public const string RolesDelete = "roles:delete";
    public const string GroupsRead = "groups:read";
    public const string GroupsWrite = "groups:write";
    public const string GroupsDelete = "groups:delete";
    /// <summary>Manage group membership: add/remove user members and nested group members.</summary>
    public const string GroupsMembers = "groups:members";
    public const string SettingsRead = "tenant:settings:read";
    public const string SettingsWrite = "tenant:settings:write";
}

public static class TenantRoleModel
{
    /// <summary>
    /// The built-in role catalog for a specific tenant. Identical to <see cref="BuiltInRoles()"/>
    /// except that for the management tenant the baseline <c>app</c> role is namespaced to
    /// <c>app.&lt;slug(ServerName)&gt;</c> via <see cref="AppRoleName"/> — regular tenants get their
    /// app-scoped role created by the client after tenant creation, but the management tenant is
    /// bootstrapped server-side with no client, so it seeds the namespaced role directly.
    /// </summary>
    public static IEnumerable<TenantRole> BuiltInRoles(Tenant tenant)
    {
        foreach (var role in BuiltInRoles())
        {
            if (tenant.IsManagementTenant && role.Name == BuiltInTenantRoles.App)
                role.Name = AppRoleName(tenant.ServerName);
            yield return role;
        }
    }

    /// <summary>
    /// The app-scoped baseline role name for a tenant: <c>app.&lt;slug&gt;</c>, where slug is the
    /// <paramref name="serverName"/> lower-cased with all non-alphanumeric characters stripped.
    /// Namespacing the app role by tenant keeps it distinct from other apps' roles sharing a domain.
    /// Falls back to the bare <c>app</c> name when the ServerName has no alphanumeric characters.
    /// </summary>
    public static string AppRoleName(string serverName)
    {
        var slug = new string((serverName ?? "").Where(char.IsLetterOrDigit).ToArray()).ToLowerInvariant();
        return slug.Length == 0 ? BuiltInTenantRoles.App : $"{BuiltInTenantRoles.App}.{slug}";
    }

    /// <summary>The built-in roles seeded into a new tenant's catalog.</summary>
    public static IEnumerable<TenantRole> BuiltInRoles()
    {
        yield return new TenantRole
        {
            Name = BuiltInTenantRoles.TenantAdmin,
            DisplayName = "Tenant Admin",
            Description = "Full administration of this tenant: users, roles, and settings.",
            Permissions =
            [
                Permissions.UsersRead, Permissions.UsersWrite, Permissions.UsersDelete,
                Permissions.RolesRead, Permissions.RolesWrite, Permissions.RolesDelete,
                Permissions.GroupsRead, Permissions.GroupsWrite, Permissions.GroupsDelete, Permissions.GroupsMembers,
                Permissions.SettingsRead, Permissions.SettingsWrite,
                // The /users and /roles delegation endpoints authorize on this permission, so
                // tenant admins implicitly have it. Custom roles can also carry it to delegate
                // role administration without granting full tenantadmin.
                RoleEndpoints.ManagePermission
            ]
        };
        yield return new TenantRole
        {
            Name = BuiltInTenantRoles.UserAdmin,
            DisplayName = "User Admin",
            Description = "Manage users and the role catalog for this tenant (no admin-role management).",
            Permissions = [Permissions.UsersRead, Permissions.UsersWrite, Permissions.UsersDelete, Permissions.RolesRead, Permissions.RolesWrite, Permissions.RolesDelete, Permissions.GroupsRead]
        };
        yield return new TenantRole
        {
            Name = BuiltInTenantRoles.GroupAdmin,
            DisplayName = "Group Admin",
            Description = "Manage this tenant's groups and group membership (no user/role administration).",
            Permissions =
            [
                Permissions.GroupsRead, Permissions.GroupsWrite, Permissions.GroupsDelete, Permissions.GroupsMembers,
                // Read-only directory access so a group admin can pick users to add and roles to attach.
                Permissions.UsersRead, Permissions.RolesRead
            ]
        };
        yield return new TenantRole
        {
            Name = BuiltInTenantRoles.App,
            DisplayName = "App User",
            Description = "Baseline app member: read-only access to this tenant's users, roles and groups.",
            Permissions = [Permissions.UsersRead, Permissions.RolesRead, Permissions.GroupsRead]
        };
    }

    /// <summary>True when the supplied role list grants tenant-admin (case-insensitive).</summary>
    public static bool IsTenantAdmin(IEnumerable<string> roleNames) =>
        Normalize(roleNames).Contains(BuiltInTenantRoles.TenantAdmin);

    /// <summary>True when the role list grants at least useradmin (i.e. tenantadmin OR useradmin).</summary>
    public static bool IsUserAdminOrAbove(IEnumerable<string> roleNames)
    {
        var roles = Normalize(roleNames);
        return roles.Contains(BuiltInTenantRoles.TenantAdmin) || roles.Contains(BuiltInTenantRoles.UserAdmin);
    }

    /// <summary>The canonical camelCase <c>myRole</c> value the frontend reads, or "" for no role.</summary>
    public static string MyRole(IEnumerable<string> roleNames)
    {
        var roles = Normalize(roleNames);
        if (roles.Contains(BuiltInTenantRoles.TenantAdmin)) return "TenantAdmin";
        if (roles.Contains(BuiltInTenantRoles.UserAdmin)) return "UserAdmin";
        if (roles.Contains(BuiltInTenantRoles.GroupAdmin)) return "GroupAdmin";
        if (roles.Contains(BuiltInTenantRoles.App)) return "App";
        return "";
    }

    private static HashSet<string> Normalize(IEnumerable<string> roleNames) =>
        roleNames.Select(r => r.Trim().ToLowerInvariant()).ToHashSet();
}
