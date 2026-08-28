using System.ComponentModel.DataAnnotations;

namespace MyPassKeys;

/// <summary>
/// Represents an application user who can register and authenticate using FIDO2 credentials.
/// </summary>
public class Fido2AppUser
{
    /// <summary>
    /// The unique identifier for the user.
    /// </summary>
    [Key]
    public Guid Id { get; set; } = Guid.CreateVersion7();
    
    /// <summary>
    /// The ID of the tenant this user belongs to.
    /// </summary>
    [Required]
    public Guid TenantId { get; set; }
    
    private readonly string _username = string.Empty;

    /// <summary>
    /// The user's unique username, typically an email address. Normalized (trimmed + lower-cased)
    /// on assignment — including on Marten deserialization — so the case-sensitive
    /// (TenantId, Username) index behaves case-insensitively and the same person can't end up
    /// with two records that differ only by case.
    /// </summary>
    [Required]
    [EmailAddress]
    [MaxLength(128)]
    public string Username
    {
        get => _username;
        init => _username = value.NormalizeUsername();
    }
    
    /// <summary>
    /// The user's display name.
    /// </summary>
    [MaxLength(128)]
    public string DisplayName { get; init; } = string.Empty;
    
    /// <summary>
    /// A list of roles assigned to the user.
    /// </summary>
    public List<string> Roles { get; init; } = [];
    
    /// <summary>
    /// The timestamp when the user account was created.
    /// </summary>
    public DateTime CreatedAt { get; init; } = DateTime.UtcNow;

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
/// Represents a FIDO2 credential stored in the database, linked to a user.
/// </summary>
public class Fido2StoredCredential
{
    /// <summary>
    /// The ID of the tenant this credential belongs to.
    /// </summary>
    [Required] public Guid TenantId { get; set; } = Guid.CreateVersion7();
    
    /// <summary>
    /// The unique identifier for the credential record, typically a Base64Url encoding of the CredentialId.
    /// </summary>
    [Required]
    public required string Id { get; init; }
    
    /// <summary>
    /// The raw ID of the credential, as provided by the authenticator.
    /// </summary>
    public required byte[] CredentialId { get; init; }
    
    /// <summary>
    /// The public key of the credential.
    /// </summary>
    public required byte[] PublicKey { get; init; }
    
    /// <summary>
    /// The signature counter, used to detect cloned authenticators.
    /// </summary>
    public uint SignatureCounter { get; set; }
    
    /// <summary>
    /// The type of the credential (e.g., "public-key").
    /// </summary>
    [MaxLength(64)]
    public required string CredType { get; init; }
    
    /// <summary>
    /// The date and time when the credential was registered.
    /// </summary>
    public DateTime RegDate { get; init; }
    
    /// <summary>
    /// The Authenticator Attestation GUID, identifying the model of the authenticator.
    /// </summary>
    public Guid AaGuid { get; init; }
    
    /// <summary>
    /// The ID of the user who owns this credential.
    /// </summary>
    public required Guid UserId { get; init; }
    
    /// <summary>
    /// A list of transports (e.g., "usb", "nfc", "ble", "internal") supported by the authenticator.
    /// </summary>
    public required List<string> Transports { get; init; }
    
    /// <summary>
    /// Indicates if the credential is eligible to be backed up.
    /// </summary>
    public bool IsBackupEligible { get; init; }
    
    /// <summary>
    /// Indicates if the credential has been backed up.
    // </summary>
    public bool IsBackedUp { get; init; }
    
    /// <summary>
    /// The raw attestation object, for auditing and verification.
    /// </summary>
    public required byte[] AttestationObject { get; init; }
    
    /// <summary>
    /// The raw client data JSON from the registration ceremony.
    /// </summary>
    public required byte[] ClientDataJson { get; init; }

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
/// Represents the challenge data temporarily stored during a FIDO2 ceremony.
/// Note: This model may be obsolete if challenges are stored directly in a cache like Redis.
/// </summary>
public class Fido2ChallengeData
{
    /// <summary>
    /// A unique identifier for the challenge, often the username or a session ID.
    /// </summary>
    [Required]
    [MaxLength(64)]
    public required string Id { get; init; }
    
    /// <summary>
    /// The serialized JSON of the Fido2NetLib options object (e.g., CredentialCreateOptions or AssertionOptions).
    /// </summary>
    public required string Challenge { get; init; }
    
    /// <summary>
    /// The expiration time for this challenge to prevent replay attacks.
    /// </summary>
    public DateTime Expiration { get; init; }
}

/// <summary>
/// Represents a refresh token used to obtain new access tokens.
/// </summary>
public class Fido2RefreshToken
{
    /// <summary>
    /// The unique identifier for the refresh token record.
    /// </summary>
    public Guid Id { get; set; }
    
    /// <summary>
    /// The cryptographically random refresh token string.
    /// </summary>
    public string Token { get; set; } = string.Empty;
    
    /// <summary>
    /// The ID of the user to whom this token was issued.
    /// </summary>
    public Guid UserId { get; set; }
    
    /// <summary>
    /// The expiration date and time of the token.
    /// </summary>
    public DateTime Expiry { get; set; }
    
    /// <summary>
    /// A flag indicating if the token has been revoked. Used for refresh token rotation and replay detection.
    /// </summary>
    public bool IsRevoked { get; set; }

    /// <summary>
    /// When the token was revoked (rotated out), or null if still active. Used to distinguish a
    /// benign concurrent-tab replay (within a short grace window of rotation) from a genuine
    /// stolen-token replay (long after rotation), which triggers family-wide revocation.
    /// </summary>
    public DateTime? RevokedAt { get; set; }
    
    /// <summary>
    /// Stores the JWK Thumbprint (jkt) of the DPoP key.
    /// This binds the refresh token to a specific client key, preventing its use without proof of possession.
    /// </summary>
    public string? DpopJkt { get; set; }
    
    /// <summary>
    /// The ID of the tenant this refresh token belongs to.
    /// </summary>
    public Guid TenantId { get; set; }

    /// <summary>
    /// Monotonic write generation, covered by the integrity seal and anchored in Redis
    /// (see VersionAnchor.cs) so a rolled-back (older but validly sealed) copy is detected.
    /// Incremented by IDocumentIntegrity.Seal on every sealed write.
    /// </summary>
    public long Version { get; set; }

    /// <summary>
    /// HMAC integrity seal over the security-critical fields (see DocumentIntegrity.cs).
    /// Refresh tokens are sealed too: an unsealed attacker-inserted token could otherwise be
    /// exchanged for access tokens. Set by Fido2MartenDbService on write, verified on read.
    /// </summary>
    public string? Integrity { get; set; }
}