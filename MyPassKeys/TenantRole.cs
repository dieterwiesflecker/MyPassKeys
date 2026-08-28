namespace MyPassKeys;

/// <summary>
/// A role in a tenant's role catalog. Roles are defined per tenant and are therefore
/// shared across every hostname that resolves to that tenant. Users are assigned roles
/// by <see cref="Name"/> (see <see cref="Fido2AppUser.Roles"/>).
/// </summary>
public class TenantRole
{
    /// <summary>
    /// The unique identifier for the role record.
    /// </summary>
    public Guid Id { get; set; } = Guid.CreateVersion7();

    /// <summary>
    /// The ID of the tenant that owns this role.
    /// </summary>
    public Guid TenantId { get; set; }

    /// <summary>
    /// The normalized role identifier (trimmed, lower-cased). Unique per tenant.
    /// This is the value stored on <see cref="Fido2AppUser.Roles"/> and emitted as a
    /// 'role' claim in issued JWTs. Immutable once created — to rename, delete and recreate.
    /// </summary>
    public string Name { get; set; } = string.Empty;

    /// <summary>
    /// A human-friendly label for the role, shown in admin UIs. Defaults to <see cref="Name"/>.
    /// </summary>
    public string DisplayName { get; set; } = string.Empty;

    /// <summary>
    /// An optional description of what the role is for.
    /// </summary>
    public string Description { get; set; } = string.Empty;

    /// <summary>
    /// Fine-grained permission strings granted by this role (e.g. "users:read", "billing:write").
    /// The union of permissions across a user's roles is emitted as the 'scp' claim (space-separated) in the JWT.
    /// </summary>
    public List<string> Permissions { get; set; } = [];

    /// <summary>
    /// The timestamp when the role was created.
    /// </summary>
    public DateTime CreatedAt { get; set; } = DateTime.UtcNow;

    /// <summary>
    /// The timestamp when the role was last updated.
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
