using FluentAssertions;
using Xunit;

namespace MyPassKeys.Tests;

/// <summary>
/// Tests for the pure group-graph helpers in <see cref="TenantGroupModel"/>: recursive
/// membership through nested groups, ancestor/descendant closure, effective role inheritance,
/// cycle detection, and tolerance of pre-existing cycles in stored data.
/// </summary>
public class GroupModelTests
{
    private static TenantGroup MakeGroup(string name, List<string>? roles = null) =>
        new() { Name = name, DisplayName = name, Roles = roles ?? [] };

    /// <summary>Makes child a direct member of parent (AD semantics: members of child are members of parent).</summary>
    private static void Nest(TenantGroup parent, TenantGroup child) => parent.MemberGroupIds.Add(child.Id);

    [Fact]
    public void IsUserMember_DirectMember_True()
    {
        var userId = Guid.CreateVersion7();
        var group = MakeGroup("engineering");
        group.MemberUserIds.Add(userId);

        TenantGroupModel.IsUserMember([group], group.Id, userId).Should().BeTrue();
    }

    [Fact]
    public void IsUserMember_NotAMember_False()
    {
        var group = MakeGroup("engineering");
        TenantGroupModel.IsUserMember([group], group.Id, Guid.CreateVersion7()).Should().BeFalse();
    }

    [Fact]
    public void IsUserMember_ThroughNestedGroups_True()
    {
        // user ∈ team ⊂ department ⊂ company  ⇒  user is a member of company.
        var userId = Guid.CreateVersion7();
        var team = MakeGroup("team");
        var department = MakeGroup("department");
        var company = MakeGroup("company");
        team.MemberUserIds.Add(userId);
        Nest(department, team);
        Nest(company, department);
        var all = new[] { team, department, company };

        TenantGroupModel.IsUserMember(all, company.Id, userId).Should().BeTrue();
        TenantGroupModel.IsUserMember(all, department.Id, userId).Should().BeTrue();
        TenantGroupModel.IsUserMember(all, team.Id, userId).Should().BeTrue();
    }

    [Fact]
    public void IsUserMember_MembershipDoesNotFlowDownward()
    {
        // user ∈ company directly does NOT make them a member of the nested team.
        var userId = Guid.CreateVersion7();
        var team = MakeGroup("team");
        var company = MakeGroup("company");
        company.MemberUserIds.Add(userId);
        Nest(company, team);

        TenantGroupModel.IsUserMember([team, company], team.Id, userId).Should().BeFalse();
    }

    [Fact]
    public void GroupsForUser_DiamondNesting_EachGroupOnce()
    {
        // team is nested in two parents which share a grandparent — no duplicates, all four found.
        var userId = Guid.CreateVersion7();
        var team = MakeGroup("team");
        var parentA = MakeGroup("parent-a");
        var parentB = MakeGroup("parent-b");
        var root = MakeGroup("root");
        team.MemberUserIds.Add(userId);
        Nest(parentA, team);
        Nest(parentB, team);
        Nest(root, parentA);
        Nest(root, parentB);

        var groups = TenantGroupModel.GroupsForUser([team, parentA, parentB, root], userId);

        groups.Select(g => g.Name).Should().BeEquivalentTo("team", "parent-a", "parent-b", "root");
    }

    [Fact]
    public void RoleNamesForUser_InheritsRolesFromAncestors()
    {
        var userId = Guid.CreateVersion7();
        var team = MakeGroup("team", ["developer"]);
        var company = MakeGroup("company", ["employee"]);
        team.MemberUserIds.Add(userId);
        Nest(company, team);

        var roles = TenantGroupModel.RoleNamesForUser([team, company], userId);

        roles.Should().BeEquivalentTo("developer", "employee");
    }

    [Fact]
    public void EffectiveRoleNames_GroupInheritsAncestorRoles()
    {
        var team = MakeGroup("team", ["developer"]);
        var company = MakeGroup("company", ["employee"]);
        Nest(company, team);

        TenantGroupModel.EffectiveRoleNames([team, company], team)
            .Should().BeEquivalentTo("developer", "employee");
        TenantGroupModel.EffectiveRoleNames([team, company], company)
            .Should().BeEquivalentTo("employee");
    }

    [Fact]
    public void RecursiveMemberUserIds_CollectsUsersFromNestedGroups()
    {
        var directUser = Guid.CreateVersion7();
        var nestedUser = Guid.CreateVersion7();
        var team = MakeGroup("team");
        var company = MakeGroup("company");
        company.MemberUserIds.Add(directUser);
        team.MemberUserIds.Add(nestedUser);
        Nest(company, team);

        TenantGroupModel.RecursiveMemberUserIds([team, company], company.Id)
            .Should().BeEquivalentTo([directUser, nestedUser]);
        TenantGroupModel.RecursiveMemberUserIds([team, company], team.Id)
            .Should().BeEquivalentTo([nestedUser]);
    }

    [Fact]
    public void WouldCreateCycle_SelfMembership_True()
    {
        var group = MakeGroup("g");
        TenantGroupModel.WouldCreateCycle([group], group.Id, group.Id).Should().BeTrue();
    }

    [Fact]
    public void WouldCreateCycle_TransitiveLoop_True()
    {
        // a ⊃ b ⊃ c; adding a as a member of c would close the loop.
        var a = MakeGroup("a");
        var b = MakeGroup("b");
        var c = MakeGroup("c");
        Nest(a, b);
        Nest(b, c);
        var all = new[] { a, b, c };

        TenantGroupModel.WouldCreateCycle(all, parentGroupId: c.Id, childGroupId: a.Id).Should().BeTrue();
        // The other direction (nesting c deeper under a) is fine.
        TenantGroupModel.WouldCreateCycle(all, parentGroupId: a.Id, childGroupId: c.Id).Should().BeFalse();
    }

    [Fact]
    public void Traversals_TolerateExistingCycleInStoredData()
    {
        // Defensive: if a cycle ever lands in the database, traversals must terminate.
        var userId = Guid.CreateVersion7();
        var a = MakeGroup("a", ["role-a"]);
        var b = MakeGroup("b", ["role-b"]);
        Nest(a, b);
        Nest(b, a);
        a.MemberUserIds.Add(userId);
        var all = new[] { a, b };

        TenantGroupModel.IsUserMember(all, b.Id, userId).Should().BeTrue();
        TenantGroupModel.RoleNamesForUser(all, userId).Should().BeEquivalentTo("role-a", "role-b");
        TenantGroupModel.DescendantGroups(all, a.Id).Should().HaveCount(1);
        TenantGroupModel.RecursiveMemberUserIds(all, b.Id).Should().BeEquivalentTo([userId]);
    }
}
