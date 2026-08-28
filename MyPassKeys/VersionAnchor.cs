using StackExchange.Redis;

namespace MyPassKeys;

/// <summary>
/// Rollback protection for sealed documents. The HMAC seal (DocumentIntegrity.cs) stops an
/// attacker from *editing* a document, but not from restoring an OLDER, validly-sealed copy
/// (e.g. a user record from before their admin role was revoked). Each sealed write bumps the
/// document's <c>Version</c> (inside the MAC), and the latest version is anchored here in
/// Redis — a store a Postgres-credentialed attacker cannot reach. On read, a stored version
/// below the anchor is a rollback and fails closed.
///
/// Semantics (best-effort by design):
/// - anchor missing (first deploy, Redis flush/loss): adopt the stored version and log — after
///   the startup migration has anchored everything, runtime adoption is a signal worth watching.
/// - stored version ABOVE the anchor: the app crashed between save and anchor update — repair
///   the anchor upward.
/// - stored version BELOW the anchor: rollback → <see cref="DocumentTamperedException"/>.
/// Defeating this layer requires write access to BOTH Postgres and Redis. Restoring a Postgres
/// backup is therefore a deliberate operation: set <c>MyPassKeys:ResetVersionAnchors=true</c>
/// for ONE startup so the migration re-adopts the restored versions, then remove the flag.
/// </summary>
public interface IVersionAnchor
{
    /// <summary>Throws <see cref="DocumentTamperedException"/> when the document's version is
    /// older than the anchored one. Adopts/repairs the anchor when it is missing or behind.</summary>
    Task CheckAsync(object document);

    /// <summary>Records the document's version as the new anchor. Call after a successful save.</summary>
    Task RecordAsync(object document);
}

public sealed class RedisVersionAnchor(
    IConnectionMultiplexer redis,
    ILogger<RedisVersionAnchor> logger) : IVersionAnchor
{
    public async Task CheckAsync(object document)
    {
        var (key, version) = Describe(document);
        var stored = await redis.GetDatabase().StringGetAsync(key);

        if (!stored.HasValue)
        {
            // No anchor. Legitimate on the first deploy or after a Redis flush; the startup
            // migration anchors every document, so seeing this at runtime is worth a log line.
            logger.LogWarning("No version anchor for {Key} — adopting stored version {Version}.", key, version);
            await RecordAsync(document);
            return;
        }

        var anchor = (long)stored;
        if (version < anchor)
            throw new DocumentTamperedException(
                $"Version anchor mismatch for '{key}': the stored document is generation {version}, but " +
                $"generation {anchor} was previously written — an older copy was restored behind the " +
                "application's back (database rollback). Refusing to use it. If this is a deliberate " +
                "backup restore, start once with MyPassKeys:ResetVersionAnchors=true.");

        if (version > anchor)
            await RecordAsync(document); // crashed between save and anchor update — repair upward
    }

    public async Task RecordAsync(object document)
    {
        var (key, version) = Describe(document);
        // No expiry: an expiring anchor would silently reopen the rollback window.
        await redis.GetDatabase().StringSetAsync(key, version, null, When.Always);
    }

    /// <summary>Anchor key + current version. Keys have no TTL: document ids are never reused
    /// (GUIDs / authenticator-generated credential ids), so stale anchors of deleted documents
    /// are harmless junk, and an expiring anchor would silently reopen the rollback window.</summary>
    private static (string Key, long Version) Describe(object document)
    {
        var version = HmacDocumentIntegrity.GetVersion(document);
        var key = document switch
        {
            Tenant t => $"docver:tenant:{t.Id}",
            Fido2AppUser u => $"docver:user:{u.Id}",
            Fido2StoredCredential c => $"docver:credential:{c.Id}",
            TenantRole r => $"docver:role:{r.Id}",
            TenantGroup g => $"docver:group:{g.Id}",
            Fido2RefreshToken rt => $"docver:refresh:{rt.Id}",
            _ => throw new ArgumentException($"No version-anchor support for {document.GetType().Name}.", nameof(document))
        };
        return (key, version);
    }
}
