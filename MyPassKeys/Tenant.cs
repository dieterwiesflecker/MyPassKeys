using System.ComponentModel.DataAnnotations;
using System.Text.Json;

namespace MyPassKeys;

public class Tenant
{
    [Key]
    public Guid Id { get; set; } = Guid.CreateVersion7();

    /// <summary>
    /// Custom subdomain(s) where this tenant's clients reach MyPassKeys directly
    /// (e.g. ["auth.acme.com"]). Optional — most tenants leave this empty and are
    /// resolved by matching the calling Origin against <see cref="AllowedOrigins"/>.
    /// Populate only when a tenant wants their own subdomain CNAME'd to MyPassKeys.
    /// Hosts here must NOT collide with deployment hostnames in MyPassKeys:DeploymentHosts.
    /// </summary>
    public string[] Hosts { get; set; } = [];

    /// <summary>
    /// True for the single management tenant. POST /tenants and other tenant-admin
    /// endpoints require the caller's resolved tenant to be the management tenant.
    /// Exactly one tenant row carries this flag; seeded at startup if none exists.
    /// </summary>
    public bool IsManagementTenant { get; set; }

    /// <summary>
    /// A human-friendly name of the RelyingParty. Could also be named TenantName.
    /// Globally unique (case-insensitive) because it can be supplied as an X-Tenant-ID value
    /// to select this tenant; enforced by a unique Marten index plus a 409 guard on upsert.
    /// </summary>
    public string ServerName { get; set; } = string.Empty;

    /// <summary>
    /// Optional overrides mapping a Host entry (including port) to a FIDO2 Relying Party ID (rpId).
    /// By default the rpId is derived from the hostname (without port), so most setups can leave this empty.
    /// Only add entries when the rpId should differ from the hostname, e.g. to share passkeys across subdomains.
    /// Example: { "auth.example.com": "example.com" } — passkeys registered on auth.example.com will also work on example.com.
    /// </summary>
    public Dictionary<string, string> ServerDomains { get; set; } = new();

    /// <summary>
    /// A serialized URL which resolves to an image associated with the entity. For example, this could be a user’s avatar or a Relying Party's logo. This URL MUST be an a priori authenticated URL. Authenticators MUST accept and store a 128-byte minimum length for an icon member’s value. Authenticators MAY ignore an icon member’s value if its length is greater than 128 bytes. The URL’s scheme MAY be "data" to avoid fetches of the URL, at the cost of needing more storage.
    /// </summary>
    public string ServerIcon { get; set; } = string.Empty;

    /// <summary>
    /// The allowed origins for this tenant (e.g. "http://tenant1.localhost:5173")
    /// </summary>
    public string[] AllowedOrigins { get; set; } = [];

    /// <summary>
    /// JWT Issuer for this tenant. Derived from Host and set server-side — not user-controlled.
    /// </summary>
    public string JwtIssuer { get; set; } = string.Empty;

    /// <summary>
    /// JWT Audience for this tenant. Derived from Host and set server-side — not user-controlled.
    /// </summary>
    public string JwtAudience { get; set; } = string.Empty;

    /// <summary>
    /// ECDSA P-256 key pairs for JWT signing and verification.
    /// The first entry with IsActive=true is used for signing new tokens.
    /// All entries are used for validation (kid-based lookup), enabling zero-downtime key rotation.
    /// </summary>
    public List<JwtKeyEntry> JwtKeys { get; set; } = [];

    /// <summary>
    /// How often to automatically rotate the signing key, in days. 0 = disabled (manual only).
    /// When enabled, a background service creates a new active key and retires the old one.
    /// </summary>
    public int KeyRotationIntervalInDays { get; set; } = 0;

    /// <summary>
    /// Lifetime of the Access Token in minutes. Defaults to 60 minutes.
    /// </summary>
    public int AccessTokenLifetimeInMinutes { get; set; } = 60;

    /// <summary>
    /// Lifetime of the Refresh Token in hours. Defaults to 30 days.
    /// </summary>
    public int RefreshTokenLifetimeInHours { get; set; } = 720;

    /// <summary>
    /// Access tokens issued before this instant are rejected on validation. Updated by
    /// POST /tenants/{id}/revoke-sessions to force every user of the tenant to authenticate
    /// again. Defaults to <see cref="DateTime.MinValue"/> (no cutoff).
    /// </summary>
    public DateTime SessionsValidFrom { get; set; } = DateTime.MinValue;

    /// <summary>
    /// Controls who may self-register against this tenant. One of <see cref="RegistrationModes"/>.
    /// Defaults to <see cref="RegistrationModes.Open"/> — any email may request a verification code
    /// and complete passkey registration.
    /// </summary>
    public string RegistrationMode { get; set; } = RegistrationModes.Open;

    /// <summary>
    /// When <see cref="RegistrationMode"/> is <see cref="RegistrationModes.DomainAllowlist"/>,
    /// only emails whose domain matches one of these entries may register. Entry syntax:
    /// <list type="bullet">
    ///   <item><description><c>example.com</c> — matches the exact domain only (user@example.com).</description></item>
    ///   <item><description><c>*.example.com</c> — matches any subdomain (user@a.example.com, user@a.b.example.com)
    ///   but NOT the bare apex. Combine both entries to admit both.</description></item>
    /// </list>
    /// Wildcards are accepted ONLY as the literal prefix <c>*.</c>. Ignored in other modes.
    /// </summary>
    public string[] AllowedEmailDomains { get; set; } = [];

    /// <summary>
    /// Roles automatically granted to a user who self-registers while
    /// <see cref="RegistrationMode"/> is <see cref="RegistrationModes.Open"/>. Role names must
    /// exist in the tenant's role catalog; unknown names are silently skipped at registration
    /// time (the catalog is the authority). Empty = registrants get no roles (the historical
    /// behavior). Ignored in other modes.
    /// </summary>
    public string[] DefaultRoles { get; set; } = [];

    /// <summary>
    /// Tenants whose stored passkey credentials this tenant accepts during authentication
    /// (<c>make-assertion</c>). Intended for path-separated apps sharing one domain: WebAuthn
    /// scopes a passkey to the domain (rpId), so the browser offers the same passkey to every
    /// app on it — a trust link lets a user who registered in a linked tenant log in here
    /// without registering again, with a local user provisioned just-in-time subject to this
    /// tenant's <see cref="RegistrationMode"/>. The trust is DIRECTED: this list only makes
    /// THIS tenant accept the listed tenants' credentials. For symmetric app-switching, add
    /// the link on both tenants. Not transitive — only direct entries are consulted. A
    /// foreign-domain credential can never verify here anyway (rpId hash mismatch), so the
    /// exposure is limited to identity trust between same-domain apps.
    /// </summary>
    public Guid[] TrustedCredentialTenantIds { get; set; } = [];

    /// <summary>
    /// Per-domain default roles applied when <see cref="RegistrationMode"/> is
    /// <see cref="RegistrationModes.DomainAllowlist"/>. Keyed by a normalized entry from
    /// <see cref="AllowedEmailDomains"/> (e.g. <c>example.com</c> or <c>*.example.com</c>);
    /// the value is the role names granted to a registrant whose email matches that entry.
    /// When several entries match a single email (e.g. an apex and a wildcard), the union of
    /// their roles is granted. Keys not present in <see cref="AllowedEmailDomains"/> are dropped
    /// on save. Unknown role names are skipped at registration time.
    /// </summary>
    public Dictionary<string, string[]> DomainRoles { get; set; } = new();

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

    /// <summary>
    /// Returns an anonymous object without JwtPrivateKey for safe API serialization.
    /// </summary>
    public object ToPublicView() => new
    {
        Id, Hosts, IsManagementTenant, ServerName, ServerDomains, ServerIcon, AllowedOrigins,
        JwtIssuer, JwtAudience,
        JwtKeys = JwtKeys.Select(k => k.ToPublicView()),
        KeyRotationIntervalInDays, AccessTokenLifetimeInMinutes, RefreshTokenLifetimeInHours,
        SessionsValidFrom, RegistrationMode, AllowedEmailDomains, DefaultRoles, DomainRoles,
        TrustedCredentialTenantIds
    };
}

/// <summary>
/// Allowed values for <see cref="Tenant.RegistrationMode"/>. Stored as a string in Marten so
/// changing the set in code doesn't require a doc migration; validated at the API boundary.
/// </summary>
public static class RegistrationModes
{
    /// <summary>Any email may request a verification code and register a passkey.</summary>
    public const string Open = "open";

    /// <summary>Only emails whose domain is in <see cref="Tenant.AllowedEmailDomains"/> may register.</summary>
    public const string DomainAllowlist = "domain-allowlist";

    /// <summary>
    /// Only emails of users that have been pre-created by the tenant owner (via POST /users)
    /// may register. The convention is that the pre-created user's Username equals the email.
    /// </summary>
    public const string InviteOnly = "invite-only";

    public static readonly HashSet<string> All = [Open, DomainAllowlist, InviteOnly];
}

/// <summary>
/// Helpers for evaluating a tenant's registration policy. Centralized so the same rule is
/// applied at <c>auth/email/request-verification</c> and <c>make-credential-options</c>.
/// </summary>
public static class RegistrationPolicy
{
    /// <summary>
    /// True when <paramref name="email"/>'s domain matches at least one entry in
    /// <paramref name="allowedDomains"/>. Entry syntax:
    /// <list type="bullet">
    ///   <item><description><c>example.com</c> — exact match of the email's domain.</description></item>
    ///   <item><description><c>*.example.com</c> — strict subdomain match (any depth). Does NOT match
    ///   the apex; combine both entries to admit both.</description></item>
    /// </list>
    /// Comparison is case-insensitive. Entries are assumed normalized (see <see cref="NormalizeDomains"/>).
    /// </summary>
    public static bool IsDomainAllowed(string email, IEnumerable<string> allowedDomains)
    {
        var domain = ExtractDomain(email);
        if (domain == null) return false;
        foreach (var entry in allowedDomains)
            if (EntryMatches(domain, entry)) return true;
        return false;
    }

    /// <summary>
    /// Extracts the lower-cased domain part of an email, or null when the address has no
    /// usable domain (no '@', or '@' is the last character).
    /// </summary>
    public static string? ExtractDomain(string email)
    {
        var at = email.IndexOf('@');
        if (at < 0 || at == email.Length - 1) return null;
        return email[(at + 1)..].Trim().ToLowerInvariant();
    }

    /// <summary>
    /// True when <paramref name="domain"/> (already lower-cased) matches a single allowlist
    /// <paramref name="entry"/>. Exact match for a bare domain; strict subdomain match for a
    /// <c>*.suffix</c> wildcard (does NOT match the apex). Entries are assumed normalized.
    /// </summary>
    public static bool EntryMatches(string domain, string entry)
    {
        if (string.IsNullOrEmpty(entry)) return false;
        if (entry.StartsWith("*.", StringComparison.Ordinal))
        {
            var suffix = entry[2..];
            if (suffix.Length == 0) return false;
            return domain.EndsWith("." + suffix, StringComparison.Ordinal);
        }
        return domain == entry;
    }

    /// <summary>
    /// Resolves the role names a self-registering <paramref name="email"/> should receive under
    /// the tenant's current policy: <see cref="Tenant.DefaultRoles"/> in Open mode, or the union
    /// of <see cref="Tenant.DomainRoles"/> for every matching allowlist entry in DomainAllowlist
    /// mode. Returns the raw desired names (still normalized); callers intersect with the live
    /// role catalog so a stale name can't be granted. Empty for InviteOnly (roles are pre-set).
    /// </summary>
    public static string[] RolesForRegistration(Tenant tenant, string email)
    {
        switch (tenant.RegistrationMode)
        {
            case RegistrationModes.Open:
                return tenant.DefaultRoles;
            case RegistrationModes.DomainAllowlist:
            {
                var domain = ExtractDomain(email);
                if (domain == null) return [];
                var roles = new List<string>();
                foreach (var entry in tenant.AllowedEmailDomains)
                {
                    if (!EntryMatches(domain, entry)) continue;
                    if (tenant.DomainRoles.TryGetValue(entry, out var entryRoles) && entryRoles != null)
                        roles.AddRange(entryRoles);
                }
                return roles.Distinct().ToArray();
            }
            default:
                return [];
        }
    }

    /// <summary>
    /// Decides whether a user unknown to <paramref name="tenant"/> may be created just-in-time
    /// during a trusted cross-tenant passkey login (<see cref="Tenant.TrustedCredentialTenantIds"/>).
    /// Mirrors self-registration: Open always allows, DomainAllowlist requires a matching email
    /// domain, InviteOnly never auto-creates — there the pre-created user IS the invite, and an
    /// existing local user logs in regardless of mode. No fresh email verification is needed:
    /// no passkey is attached here, and the assertion already proves possession of the email
    /// owner's credential vetted by the trusted tenant.
    /// </summary>
    public static bool CanJitProvision(Tenant tenant, string email) =>
        tenant.RegistrationMode switch
        {
            RegistrationModes.Open => true,
            RegistrationModes.DomainAllowlist => IsDomainAllowed(email, tenant.AllowedEmailDomains),
            _ => false,
        };

    /// <summary>
    /// Trims, lower-cases, drops empties and de-duplicates a role-name list (matching the
    /// normalization <see cref="TenantRole.Name"/> uses), so stored default/domain roles line up
    /// with catalog names.
    /// </summary>
    public static string[] NormalizeRoles(IEnumerable<string>? roles) =>
        (roles ?? [])
            .Select(r => r.Trim().ToLowerInvariant())
            .Where(r => r.Length > 0)
            .Distinct()
            .ToArray();

    /// <summary>
    /// Normalizes a per-domain role map for storage: lower-cases/strips "@" from each key (same
    /// rule as <see cref="NormalizeDomains"/>), keeps only keys present in <paramref name="allowedDomains"/>,
    /// normalizes each role list, and drops entries that end up empty. Role-name existence is NOT
    /// checked here (the catalog may not exist yet at tenant creation) — that's done at registration.
    /// </summary>
    public static Dictionary<string, string[]> NormalizeDomainRoles(
        IDictionary<string, string[]>? domainRoles, IEnumerable<string> allowedDomains)
    {
        var allowed = allowedDomains.ToHashSet();
        var result = new Dictionary<string, string[]>();
        foreach (var (rawKey, roles) in domainRoles ?? new Dictionary<string, string[]>())
        {
            var key = rawKey.Trim().ToLowerInvariant();
            if (key.StartsWith('@')) key = key[1..];
            if (key.Length == 0 || !allowed.Contains(key)) continue;
            var norm = NormalizeRoles(roles);
            if (norm.Length > 0) result[key] = norm;
        }
        return result;
    }

    /// <summary>
    /// Normalizes a list of domain entries supplied through the tenant management API:
    /// trims whitespace, strips a leading "@" (but preserves "*."), lower-cases, drops empties,
    /// de-duplicates. Entries that aren't either a bare domain or a strict <c>*.domain</c>
    /// wildcard are returned in <c>Invalid</c> so the endpoint can 400 the request.
    /// </summary>
    public static (string[] Normalized, string[] Invalid) NormalizeDomains(IEnumerable<string>? domains)
    {
        var normalized = new List<string>();
        var invalid = new List<string>();
        foreach (var raw in domains ?? [])
        {
            // Trim, lower-case, strip a leading "@" (e.g. pasted "@example.com"). The "*." prefix is
            // preserved verbatim because that is the wildcard syntax.
            var d = raw.Trim().ToLowerInvariant();
            if (d.StartsWith('@')) d = d[1..];
            if (d.Length == 0) continue;

            if (!IsValidEntry(d)) { invalid.Add(raw); continue; }
            normalized.Add(d);
        }
        return (normalized.Distinct().ToArray(), invalid.ToArray());
    }

    /// <summary>
    /// An entry is valid iff it is either a bare domain with no '*' anywhere, or the literal
    /// prefix "*." followed by a non-empty bare domain (no further '*' allowed). This rejects
    /// shapes like "*", "*foo.com", "foo.*.com", "**.foo.com".
    /// </summary>
    private static bool IsValidEntry(string entry)
    {
        if (entry.StartsWith("*.", StringComparison.Ordinal))
        {
            var suffix = entry[2..];
            return suffix.Length > 0 && !suffix.Contains('*');
        }
        return !entry.Contains('*');
    }
}

public class JwtKeyEntry
{
    public string Kid { get; set; } = string.Empty;
    public JsonElement PrivateKey { get; set; }
    public JsonElement PublicKey { get; set; }
    public DateTime CreatedAt { get; set; } = DateTime.UtcNow;
    public bool IsActive { get; set; }

    public object ToPublicView() => new { Kid, PublicKey, CreatedAt, IsActive };
}