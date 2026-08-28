using FluentAssertions;
using Xunit;

namespace MyPassKeys.Tests;

// ---------------------------------------------------------------------------
// Role model: myRole mapping and built-in role catalog.
// The frontend reads `myRole` by exact camelCase value ("TenantAdmin" | "UserAdmin" | "").
// Role names are stored normalized (lower-case).
// ---------------------------------------------------------------------------

public class RoleModelTests
{
    [Theory]
    [InlineData(BuiltInTenantRoles.TenantAdmin, "TenantAdmin")]
    [InlineData(BuiltInTenantRoles.UserAdmin, "UserAdmin")]
    [InlineData("customer", "")]                                 // non-built-in role
    public void MyRole_MapsRoleToCanonicalDisplay(string role, string expected)
    {
        TenantRoleModel.MyRole([role]).Should().Be(expected);
    }

    [Fact]
    public void MyRole_EmptyForNoRoles()
    {
        TenantRoleModel.MyRole([]).Should().Be("");
    }

    [Fact]
    public void MyRole_IsCaseInsensitive()
    {
        TenantRoleModel.MyRole(["TENANTADMIN"]).Should().Be("TenantAdmin");
    }

    [Fact]
    public void MyRole_PicksTenantAdminOverUserAdmin()
    {
        TenantRoleModel.MyRole([BuiltInTenantRoles.UserAdmin, BuiltInTenantRoles.TenantAdmin])
            .Should().Be("TenantAdmin");
    }

    [Fact]
    public void IsTenantAdmin_RequiresTenantAdminRole()
    {
        TenantRoleModel.IsTenantAdmin([BuiltInTenantRoles.TenantAdmin]).Should().BeTrue();
        TenantRoleModel.IsTenantAdmin([BuiltInTenantRoles.UserAdmin]).Should().BeFalse();
        TenantRoleModel.IsTenantAdmin([]).Should().BeFalse();
    }

    [Fact]
    public void IsUserAdminOrAbove_IncludesBothBuiltIns()
    {
        TenantRoleModel.IsUserAdminOrAbove([BuiltInTenantRoles.TenantAdmin]).Should().BeTrue();
        TenantRoleModel.IsUserAdminOrAbove([BuiltInTenantRoles.UserAdmin]).Should().BeTrue();
        TenantRoleModel.IsUserAdminOrAbove(["customer"]).Should().BeFalse();
        TenantRoleModel.IsUserAdminOrAbove([]).Should().BeFalse();
    }

    [Fact]
    public void BuiltInRoles_SeedTheFourTiers()
    {
        var names = TenantRoleModel.BuiltInRoles().Select(r => r.Name).ToList();
        names.Should().BeEquivalentTo([BuiltInTenantRoles.TenantAdmin, BuiltInTenantRoles.UserAdmin, BuiltInTenantRoles.GroupAdmin, BuiltInTenantRoles.App]);
    }

    [Fact]
    public void BuiltInTenantAdmin_CarriesRoleManagementPermission()
    {
        var tenantAdmin = TenantRoleModel.BuiltInRoles().Single(r => r.Name == BuiltInTenantRoles.TenantAdmin);
        tenantAdmin.Permissions.Should().Contain(Permissions.UsersWrite);
        tenantAdmin.Permissions.Should().Contain(Permissions.SettingsWrite);
        // Tenantadmin holds roles:manage so /users and /roles delegation endpoints accept it.
        tenantAdmin.Permissions.Should().Contain(RoleEndpoints.ManagePermission);
    }

    [Fact]
    public void BuiltInUserAdmin_ManagesUsersAndRolesButNotRoleManage()
    {
        var userAdmin = TenantRoleModel.BuiltInRoles().Single(r => r.Name == BuiltInTenantRoles.UserAdmin);
        userAdmin.Permissions.Should().BeEquivalentTo(
            [Permissions.UsersRead, Permissions.UsersWrite, Permissions.UsersDelete, Permissions.RolesRead, Permissions.RolesWrite, Permissions.RolesDelete, Permissions.GroupsRead]);
        // useradmin must NOT hold roles:manage — that is the escalation-guard bypass capability.
        userAdmin.Permissions.Should().NotContain(RoleEndpoints.ManagePermission);
    }

    [Fact]
    public void BuiltInGroupAdmin_ManagesGroupsWithReadOnlyDirectoryAccess()
    {
        var groupAdmin = TenantRoleModel.BuiltInRoles().Single(r => r.Name == BuiltInTenantRoles.GroupAdmin);
        groupAdmin.Permissions.Should().BeEquivalentTo(
            [Permissions.GroupsRead, Permissions.GroupsWrite, Permissions.GroupsDelete, Permissions.GroupsMembers, Permissions.UsersRead, Permissions.RolesRead]);
        // groupadmin must NOT hold roles:manage — the privileged-group guards bound it instead.
        groupAdmin.Permissions.Should().NotContain(RoleEndpoints.ManagePermission);
    }

    [Fact]
    public void BuiltInApp_IsReadOnly()
    {
        var app = TenantRoleModel.BuiltInRoles().Single(r => r.Name == BuiltInTenantRoles.App);
        app.Permissions.Should().BeEquivalentTo([Permissions.UsersRead, Permissions.RolesRead, Permissions.GroupsRead]);
    }
}
