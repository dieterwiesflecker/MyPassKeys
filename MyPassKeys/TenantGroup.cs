namespace MyPassKeys;

/// <summary>
/// An Active-Directory-style group in a tenant. Groups collect users (<see cref="MemberUserIds"/>)
/// and other groups (<see cref="MemberGroupIds"/> — nesting), and carry a set of catalog role
/// names (<see cref="Roles"/>) that every member inherits, directly or transitively: a user in
/// group A, where A is a member of group B, holds the roles of both A and B. Group-derived roles
/// are unioned with the user's direct <see cref="Fido2AppUser.Roles"/> at token issuance.
/// </summary>
public class TenantGroup
{
    /// <summary>
    /// The unique identifier for the group record.
    /// </summary>
    public Guid Id { get; set; } = Guid.CreateVersion7();

    /// <summary>
    /// The ID of the tenant that owns this group.
    /// </summary>
    public Guid TenantId { get; set; }

    /// <summary>
    /// The normalized group identifier (trimmed, lower-cased). Unique per tenant and emitted as a
    /// 'groups' claim in issued JWTs. Immutable once created — to rename, delete and recreate.
    /// </summary>
    public string Name { get; set; } = string.Empty;

    /// <summary>
    /// A human-friendly label for the group, shown in admin UIs. Defaults to <see cref="Name"/>.
    /// </summary>
    public string DisplayName { get; set; } = string.Empty;

    /// <summary>
    /// An optional description of what the group is for.
    /// </summary>
    public string Description { get; set; } = string.Empty;

    /// <summary>
    /// Catalog role names (see <see cref="TenantRole.Name"/>) granted to every direct and
    /// transitive member of this group.
    /// </summary>
    public List<string> Roles { get; set; } = [];

    /// <summary>
    /// The IDs of the users that are direct members of this group.
    /// </summary>
    public List<Guid> MemberUserIds { get; set; } = [];

    /// <summary>
    /// The IDs of the groups that are direct members of this group (nested groups). Members of a
    /// nested group are transitive members of this group. Cycles are rejected at the API boundary.
    /// </summary>
    public List<Guid> MemberGroupIds { get; set; } = [];

    /// <summary>
    /// The timestamp when the group was created.
    /// </summary>
    public DateTime CreatedAt { get; set; } = DateTime.UtcNow;

    /// <summary>
    /// The timestamp when the group was last updated.
    /// </summary>
    public DateTime UpdatedAt { get; set; } = DateTime.UtcNow;

    /// <summary>
    /// Monotonic write generation, covered by the integrity seal and anchored in Redis
    /// (see VersionAnchor.cs) so a rolled-back (older but validly sealed) copy is detected.
    /// Incremented by IDocumentIntegrity.Seal on every sealed write.
    /// </summary>
    public long Version { get; set; }

    /// <summary>
    /// HMAC integrity seal over the security-critical fields (see DocumentIntegrity.cs).
    /// Set by Fido2MartenDbService on write, verified on read — never touch it by hand.
    /// </summary>
    public string? Integrity { get; set; }
}

/// <summary>
/// Pure graph helpers over a tenant's full group list (tenants are small — callers load all
/// groups once via <c>GetGroupsAsync</c> and traverse in memory). Every traversal carries a
/// visited set, so a pre-existing cycle in stored data degrades to a no-op instead of hanging.
/// </summary>
public static class TenantGroupModel
{
    /// <summary>
    /// Every group the user is a member of, directly or transitively: their direct groups plus
    /// all ancestors (groups that contain those groups, recursively).
    /// </summary>
    public static List<TenantGroup> GroupsForUser(IReadOnlyCollection<TenantGroup> allGroups, Guid userId)
    {
        var result = new Dictionary<Guid, TenantGroup>();
        var queue = new Queue<TenantGroup>(allGroups.Where(g => g.MemberUserIds.Contains(userId)));
        while (queue.Count > 0)
        {
            var group = queue.Dequeue();
            if (!result.TryAdd(group.Id, group)) continue;
            foreach (var parent in allGroups.Where(p => p.MemberGroupIds.Contains(group.Id)))
                queue.Enqueue(parent);
        }
        return result.Values.ToList();
    }

    /// <summary>
    /// Recursive membership check: true when the user is a direct member of the group or a member
    /// of any group nested (transitively) inside it.
    /// </summary>
    public static bool IsUserMember(IReadOnlyCollection<TenantGroup> allGroups, Guid groupId, Guid userId) =>
        GroupsForUser(allGroups, userId).Any(g => g.Id == groupId);

    /// <summary>
    /// The groups nested (transitively) inside the given group, excluding the group itself.
    /// </summary>
    public static List<TenantGroup> DescendantGroups(IReadOnlyCollection<TenantGroup> allGroups, Guid groupId)
    {
        var byId = allGroups.ToDictionary(g => g.Id);
        var result = new Dictionary<Guid, TenantGroup>();
        var queue = new Queue<Guid>(byId.TryGetValue(groupId, out var root) ? root.MemberGroupIds : []);
        while (queue.Count > 0)
        {
            var id = queue.Dequeue();
            if (id == groupId || !byId.TryGetValue(id, out var group)) continue;
            if (!result.TryAdd(id, group)) continue;
            foreach (var childId in group.MemberGroupIds)
                queue.Enqueue(childId);
        }
        return result.Values.ToList();
    }

    /// <summary>
    /// The groups that contain the given group, directly or transitively (its ancestors),
    /// excluding the group itself. A member of the group also holds the roles of these.
    /// </summary>
    public static List<TenantGroup> AncestorGroups(IReadOnlyCollection<TenantGroup> allGroups, Guid groupId)
    {
        var result = new Dictionary<Guid, TenantGroup>();
        var queue = new Queue<TenantGroup>(allGroups.Where(p => p.MemberGroupIds.Contains(groupId)));
        while (queue.Count > 0)
        {
            var parent = queue.Dequeue();
            if (parent.Id == groupId || !result.TryAdd(parent.Id, parent)) continue;
            foreach (var grandParent in allGroups.Where(p => p.MemberGroupIds.Contains(parent.Id)))
                queue.Enqueue(grandParent);
        }
        return result.Values.ToList();
    }

    /// <summary>
    /// Every user that is a member of the group, directly or via nested groups.
    /// </summary>
    public static HashSet<Guid> RecursiveMemberUserIds(IReadOnlyCollection<TenantGroup> allGroups, Guid groupId)
    {
        var byId = allGroups.ToDictionary(g => g.Id);
        var users = new HashSet<Guid>();
        if (byId.TryGetValue(groupId, out var root))
        {
            users.UnionWith(root.MemberUserIds);
            foreach (var descendant in DescendantGroups(allGroups, groupId))
                users.UnionWith(descendant.MemberUserIds);
        }
        return users;
    }

    /// <summary>
    /// True when making <paramref name="childGroupId"/> a member of <paramref name="parentGroupId"/>
    /// would create a membership cycle — i.e. the parent is the child itself or is already nested
    /// (transitively) inside the child.
    /// </summary>
    public static bool WouldCreateCycle(IReadOnlyCollection<TenantGroup> allGroups, Guid parentGroupId, Guid childGroupId) =>
        parentGroupId == childGroupId ||
        DescendantGroups(allGroups, childGroupId).Any(g => g.Id == parentGroupId);

    /// <summary>
    /// The role names a group confers on its members: its own <see cref="TenantGroup.Roles"/>
    /// plus those of every ancestor group (a member of this group is transitively a member of
    /// each ancestor).
    /// </summary>
    public static HashSet<string> EffectiveRoleNames(IReadOnlyCollection<TenantGroup> allGroups, TenantGroup group) =>
        group.Roles
            .Concat(AncestorGroups(allGroups, group.Id).SelectMany(a => a.Roles))
            .ToHashSet(StringComparer.Ordinal);

    /// <summary>
    /// The role names a user inherits from group memberships (direct and transitive). Union this
    /// with the user's direct <see cref="Fido2AppUser.Roles"/> for their effective role set.
    /// </summary>
    public static HashSet<string> RoleNamesForUser(IReadOnlyCollection<TenantGroup> allGroups, Guid userId) =>
        GroupsForUser(allGroups, userId)
            .SelectMany(g => g.Roles)
            .ToHashSet(StringComparer.Ordinal);
}
