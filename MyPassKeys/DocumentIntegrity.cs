using System.Security.Cryptography;
using System.Text;

namespace MyPassKeys;

/// <summary>
/// Thrown when a security-critical document read from the database (or the Redis tenant cache)
/// has a missing or invalid integrity seal — i.e. its protected fields were modified by
/// something other than this application (direct DB write, cache poisoning). Deliberately NOT
/// caught anywhere: the request fails (fail closed) and the resulting 500 + log entry is the
/// tamper alarm.
/// </summary>
public sealed class DocumentTamperedException(string message) : Exception(message);

/// <summary>
/// HMAC integrity seals over the security-critical fields of stored documents, so an attacker
/// with database write access cannot silently escalate privileges (edit roles/permissions/group
/// membership, swap a credential's public key, insert a refresh token, or flip sensitive tenant
/// flags). The MAC key is held only by the app — derived from the KEK ring — so a DB writer
/// cannot recompute a valid seal. Sealing happens exclusively in <see cref="Fido2MartenDbService"/>
/// on write; verification on every read (plus <see cref="TenantService"/> for cache hits).
/// Residual risks (documented, out of scope here): rollback to an older validly-sealed copy of
/// the same document, and the startup migration blessing documents inserted while unsealed docs
/// still exist (it logs a warning count — after the first migration that count must stay 0).
/// </summary>
public interface IDocumentIntegrity
{
    /// <summary>Increments the document's <c>Version</c> (a sealed write is a new generation)
    /// and computes and stores the seal. Call ONLY on trusted state — never on a loaded
    /// document that hasn't been verified first.</summary>
    void Seal(object document);

    /// <summary>Throws <see cref="DocumentTamperedException"/> when the seal is missing,
    /// malformed, made with an unknown key, or doesn't match the protected fields.</summary>
    void Verify(object document);

    /// <summary>True when the document carries any seal (valid or not). Distinguishes legacy
    /// pre-integrity documents (migration seals them) from tampered ones (migration must not).</summary>
    bool HasSeal(object document);

    /// <summary>True when the seal was made with the CURRENT key. False for previous-key seals —
    /// the startup migration re-seals those after verifying them.</summary>
    bool IsSealedWithCurrentKey(object document);
}

/// <summary>
/// HMAC-SHA256 implementation. Seal format: <c>v1.{kekId}.{base64 mac}</c>. Each MAC key is
/// derived per-KEK via HKDF-SHA256 (info "MyPassKeys.DocumentIntegrity.v1"), so the ring in
/// MyPassKeys:KeyEncryptionKey / PreviousKeyEncryptionKeys covers integrity too and KEK rotation
/// rotates the MAC keys with the same startup-migration flow. The MAC input is a canonical
/// string (type tag + schema version + protected fields, collections sorted) built by hand so
/// it is independent of storage serialization details.
/// </summary>
public sealed class HmacDocumentIntegrity : IDocumentIntegrity
{
    private const string Version = "v1";

    // Separators in the canonical payload: '|' between fields, U+001F between list elements,
    // U+001E between a map key and its value. Encoding ambiguity is not exploitable: seals bind
    // type+tenant+id (the document identity), sealing and verification canonicalize the same
    // in-memory document, and text fields never legitimately contain these control characters.
    private const char Field = '|';
    private const char Element = '\u001F';
    private const char KeyValue = '\u001E';

    private static readonly byte[] HkdfInfo = Encoding.UTF8.GetBytes("MyPassKeys.DocumentIntegrity.v1");

    private readonly string _currentKeyId;
    private readonly Dictionary<string, byte[]> _macKeysById;

    public HmacDocumentIntegrity(byte[] currentKek, IEnumerable<byte[]>? previousKeks = null)
    {
        _currentKeyId = KekConfig.ComputeKekId(currentKek);
        _macKeysById = new Dictionary<string, byte[]> { [_currentKeyId] = DeriveMacKey(currentKek) };
        foreach (var kek in previousKeks ?? [])
            _macKeysById.TryAdd(KekConfig.ComputeKekId(kek), DeriveMacKey(kek));
    }

    public static HmacDocumentIntegrity FromConfiguration(IConfiguration configuration)
    {
        var (current, previous) = KekConfig.Load(configuration);
        return new HmacDocumentIntegrity(current, previous);
    }

    private static byte[] DeriveMacKey(byte[] kek) =>
        HKDF.DeriveKey(HashAlgorithmName.SHA256, kek, outputLength: 32, salt: null, info: HkdfInfo);

    public void Seal(object document)
    {
        // A sealed write is a new generation. The version is inside the MAC payload, and
        // Fido2MartenDbService anchors it in Redis after the save — restoring an older (validly
        // sealed) copy of the document then fails the anchor check (see VersionAnchor.cs).
        SetVersion(document, GetVersion(document) + 1);
        var mac = ComputeMac(_macKeysById[_currentKeyId], CanonicalPayload(document));
        SetSeal(document, $"{Version}.{_currentKeyId}.{Convert.ToBase64String(mac)}");
    }

    public void Verify(object document)
    {
        var seal = GetSeal(document);
        if (string.IsNullOrEmpty(seal))
            throw new DocumentTamperedException(
                $"{Describe(document)} has no integrity seal. Either the seal was stripped by a direct " +
                "database write, or the document was created outside this application. The startup " +
                "migration seals legacy documents — investigate before restarting.");

        var parts = seal.Split('.', 3);
        if (parts.Length != 3 || parts[0] != Version || !_macKeysById.TryGetValue(parts[1], out var macKey))
            throw new DocumentTamperedException(
                $"{Describe(document)} carries an unrecognized integrity seal ('{seal[..Math.Min(seal.Length, 16)]}…'). " +
                "If the KEK was rotated, add the old key to MyPassKeys:PreviousKeyEncryptionKeys and restart.");

        byte[] expected;
        try { expected = Convert.FromBase64String(parts[2]); }
        catch (FormatException) { throw new DocumentTamperedException($"{Describe(document)} has a malformed integrity seal."); }

        var actual = ComputeMac(macKey, CanonicalPayload(document));
        if (!CryptographicOperations.FixedTimeEquals(actual, expected))
            throw new DocumentTamperedException(
                $"{Describe(document)} failed its integrity check — a security-critical field was modified " +
                "outside this application (direct database write or cache tampering). Refusing to use it.");
    }

    public bool HasSeal(object document) => !string.IsNullOrEmpty(GetSeal(document));

    public bool IsSealedWithCurrentKey(object document)
    {
        var parts = (GetSeal(document) ?? "").Split('.', 3);
        return parts.Length == 3 && parts[0] == Version && parts[1] == _currentKeyId;
    }

    private static byte[] ComputeMac(byte[] macKey, byte[] payload) => HMACSHA256.HashData(macKey, payload);

    // ------------------------------------------------------------------
    // Per-type plumbing
    // ------------------------------------------------------------------

    /// <summary>The document's write generation. Also used by <see cref="RedisVersionAnchor"/>.</summary>
    internal static long GetVersion(object document) => document switch
    {
        Tenant t => t.Version,
        Fido2AppUser u => u.Version,
        Fido2StoredCredential c => c.Version,
        TenantRole r => r.Version,
        TenantGroup g => g.Version,
        Fido2RefreshToken rt => rt.Version,
        _ => throw new ArgumentException($"No integrity support for {document.GetType().Name}.", nameof(document))
    };

    private static void SetVersion(object document, long version)
    {
        switch (document)
        {
            case Tenant t: t.Version = version; break;
            case Fido2AppUser u: u.Version = version; break;
            case Fido2StoredCredential c: c.Version = version; break;
            case TenantRole r: r.Version = version; break;
            case TenantGroup g: g.Version = version; break;
            case Fido2RefreshToken rt: rt.Version = version; break;
            default: throw new ArgumentException($"No integrity support for {document.GetType().Name}.", nameof(document));
        }
    }

    private static string? GetSeal(object document) => document switch
    {
        Tenant t => t.Integrity,
        Fido2AppUser u => u.Integrity,
        Fido2StoredCredential c => c.Integrity,
        TenantRole r => r.Integrity,
        TenantGroup g => g.Integrity,
        Fido2RefreshToken rt => rt.Integrity,
        _ => throw new ArgumentException($"No integrity support for {document.GetType().Name}.", nameof(document))
    };

    private static void SetSeal(object document, string seal)
    {
        switch (document)
        {
            case Tenant t: t.Integrity = seal; break;
            case Fido2AppUser u: u.Integrity = seal; break;
            case Fido2StoredCredential c: c.Integrity = seal; break;
            case TenantRole r: r.Integrity = seal; break;
            case TenantGroup g: g.Integrity = seal; break;
            case Fido2RefreshToken rt: rt.Integrity = seal; break;
            default: throw new ArgumentException($"No integrity support for {document.GetType().Name}.", nameof(document));
        }
    }

    private static string Describe(object document) => document switch
    {
        Tenant t => $"Tenant {t.Id} ('{t.ServerName}')",
        Fido2AppUser u => $"User {u.Id} ('{u.Username}', tenant {u.TenantId})",
        Fido2StoredCredential c => $"Credential '{c.Id}' (user {c.UserId}, tenant {c.TenantId})",
        TenantRole r => $"Role {r.Id} ('{r.Name}', tenant {r.TenantId})",
        TenantGroup g => $"Group {g.Id} ('{g.Name}', tenant {g.TenantId})",
        Fido2RefreshToken rt => $"Refresh token {rt.Id} (user {rt.UserId}, tenant {rt.TenantId})",
        _ => document.GetType().Name
    };

    /// <summary>
    /// Canonical MAC input: fixed field order, order-insensitive collections sorted ordinally,
    /// GUIDs in "D" format, timestamps as whole Unix seconds (matching JWT iat / session-cutoff
    /// granularity and immune to sub-second precision loss in storage round-trips). Bump the
    /// schema version constant in a payload when changing its shape — old seals then fail
    /// verification, so add migration re-seal handling before doing so.
    /// </summary>
    private static byte[] CanonicalPayload(object document)
    {
        var sb = new StringBuilder(256);
        switch (document)
        {
            case Fido2AppUser u:
                AppendHeader(sb, "user", 1, u.TenantId, u.Id.ToString("D"));
                AppendField(sb, u.Username);
                AppendSorted(sb, u.Roles);
                break;

            case Fido2StoredCredential c:
                AppendHeader(sb, "credential", 1, c.TenantId, c.Id);
                AppendField(sb, c.UserId.ToString("D"));
                AppendField(sb, Convert.ToBase64String(c.CredentialId));
                AppendField(sb, Convert.ToBase64String(c.PublicKey));
                AppendField(sb, c.CredType);
                AppendField(sb, c.SignatureCounter.ToString());
                break;

            case TenantRole r:
                AppendHeader(sb, "role", 1, r.TenantId, r.Id.ToString("D"));
                AppendField(sb, r.Name);
                AppendSorted(sb, r.Permissions);
                break;

            case TenantGroup g:
                AppendHeader(sb, "group", 1, g.TenantId, g.Id.ToString("D"));
                AppendField(sb, g.Name);
                AppendSorted(sb, g.MemberUserIds.Select(id => id.ToString("D")));
                AppendSorted(sb, g.MemberGroupIds.Select(id => id.ToString("D")));
                AppendSorted(sb, g.Roles);
                break;

            case Fido2RefreshToken rt:
                AppendHeader(sb, "refresh", 1, rt.TenantId, rt.Id.ToString("D"));
                AppendField(sb, rt.Token);
                AppendField(sb, rt.UserId.ToString("D"));
                AppendField(sb, ToUnixSeconds(rt.Expiry).ToString());
                AppendField(sb, rt.DpopJkt ?? "");
                AppendField(sb, rt.IsRevoked ? "1" : "0");
                AppendField(sb, (rt.RevokedAt is { } revoked ? ToUnixSeconds(revoked) : -1).ToString());
                break;

            case Tenant t:
                AppendHeader(sb, "tenant", 1, t.Id, t.Id.ToString("D"));
                AppendField(sb, t.ServerName);
                AppendField(sb, t.IsManagementTenant ? "1" : "0");
                AppendSorted(sb, t.Hosts);
                AppendSorted(sb, t.AllowedOrigins);
                AppendSorted(sb, t.ServerDomains.Select(kv => $"{kv.Key}{KeyValue}{kv.Value}"));
                AppendField(sb, t.JwtIssuer);
                AppendField(sb, t.JwtAudience);
                AppendField(sb, t.RegistrationMode);
                AppendField(sb, ToUnixSeconds(t.SessionsValidFrom).ToString());
                AppendField(sb, t.AccessTokenLifetimeInMinutes.ToString());
                AppendField(sb, t.RefreshTokenLifetimeInHours.ToString());
                AppendSorted(sb, t.TrustedCredentialTenantIds.Select(id => id.ToString("D")));
                AppendSorted(sb, t.AllowedEmailDomains);
                AppendSorted(sb, t.DefaultRoles);
                AppendSorted(sb, t.DomainRoles.Select(kv =>
                    $"{kv.Key}{KeyValue}{string.Join(Element, (kv.Value ?? []).OrderBy(x => x, StringComparer.Ordinal))}"));
                break;

            default:
                throw new ArgumentException($"No integrity support for {document.GetType().Name}.", nameof(document));
        }
        // Every payload ends with the write generation, so a valid seal is bound to exactly one
        // version — the anchor check compares this version against the latest recorded one.
        AppendField(sb, GetVersion(document).ToString());
        return Encoding.UTF8.GetBytes(sb.ToString());
    }

    private static void AppendHeader(StringBuilder sb, string type, int version, Guid tenantId, string id) =>
        sb.Append(type).Append(Field).Append(version)
          .Append(Field).Append(tenantId.ToString("D"))
          .Append(Field).Append(id);

    private static void AppendField(StringBuilder sb, string value) =>
        sb.Append(Field).Append(value);

    private static void AppendSorted(StringBuilder sb, IEnumerable<string> values)
    {
        sb.Append(Field).Append('[');
        sb.AppendJoin(Element, values.OrderBy(v => v, StringComparer.Ordinal));
        sb.Append(']');
    }

    private static long ToUnixSeconds(DateTime dt) =>
        new DateTimeOffset(DateTime.SpecifyKind(dt, DateTimeKind.Utc)).ToUnixTimeSeconds();
}
