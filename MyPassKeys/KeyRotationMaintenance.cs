using Marten;
using StackExchange.Redis;

namespace MyPassKeys;

/// <summary>
/// On-demand re-encryption / re-sealing of every security-critical document under the CURRENT KEK.
/// This is the same idempotent work the startup migrations in <c>Program.cs</c> perform (signing-key
/// re-encryption + integrity-seal re-keying), exposed so an operator can run it explicitly
/// (<c>POST /admin/rekey</c>) and CONFIRM that zero documents remain on a previous KEK BEFORE
/// retiring that KEK from <c>MyPassKeys:PreviousKeyEncryptionKeys</c>. Retiring a KEK while any blob
/// or seal still depends on it makes that data unrecoverable — this endpoint removes the guesswork.
///
/// Like the startup migration, this shares the documented exception to the
/// "seal/verify plumbing lives only in <see cref="Fido2MartenDbService"/>" invariant: it uses the
/// raw Marten session because it must re-seal already-sealed documents. It still honours the core
/// rules — verify (seal + rollback anchor) BEFORE re-sealing, and record anchors only AFTER
/// <c>SaveChangesAsync</c> succeeds.
/// </summary>
public static class KeyRotationMaintenance
{
    /// <summary>Per-type counts of what the rekey pass changed. Zero across the board means every
    /// document is already sealed/encrypted under the current KEK and the previous KEK is safe to
    /// retire.</summary>
    public sealed record RekeyResult
    {
        public int SigningKeysReEncrypted { get; set; }
        public int TenantsReSealed { get; set; }
        public int UsersReSealed { get; set; }
        public int CredentialsReSealed { get; set; }
        public int RolesReSealed { get; set; }
        public int GroupsReSealed { get; set; }
        public int RefreshTokensReSealed { get; set; }

        public int TotalReSealed =>
            TenantsReSealed + UsersReSealed + CredentialsReSealed +
            RolesReSealed + GroupsReSealed + RefreshTokensReSealed;

        /// <summary>True when nothing needed changing — the safe signal to retire a previous KEK.</summary>
        public bool FullyOnCurrentKey => SigningKeysReEncrypted == 0 && TotalReSealed == 0;
    }

    public static async Task<RekeyResult> RekeyAllUnderCurrentKeyAsync(
        IDocumentSession session,
        IConnectionMultiplexer redis,
        IKeyProtector keyProtector,
        IDocumentIntegrity integrity,
        IVersionAnchor anchors,
        ILogger logger)
    {
        var result = new RekeyResult();
        var anchorQueue = new List<object>();
        var invalidatedTenants = new List<Tenant>();

        // Re-seals the five non-tenant document types under the current KEK. Tenants are handled
        // separately below because they also carry encrypted signing keys.
        async Task<int> ReSealAsync<T>() where T : class
        {
            var count = 0;
            foreach (var doc in await session.Query<T>().ToListAsync())
            {
                // Never re-seal tampered or rolled-back data — that would bless it. A failure here
                // throws DocumentTamperedException and aborts the whole rekey (fail closed).
                integrity.Verify(doc);
                await anchors.CheckAsync(doc);

                if (integrity.IsSealedWithCurrentKey(doc)) continue;
                integrity.Seal(doc);
                session.Store(doc);
                anchorQueue.Add(doc);
                count++;
            }
            return count;
        }

        result.UsersReSealed = await ReSealAsync<Fido2AppUser>();
        result.CredentialsReSealed = await ReSealAsync<Fido2StoredCredential>();
        result.RolesReSealed = await ReSealAsync<TenantRole>();
        result.GroupsReSealed = await ReSealAsync<TenantGroup>();
        result.RefreshTokensReSealed = await ReSealAsync<Fido2RefreshToken>();

        // Tenants: re-encrypt any signing key not already under the current KEK, and re-seal the
        // tenant if its seal is stale OR any key changed (so the version anchor advances and the
        // Redis tenant cache is invalidated, matching the startup migration's UpsertTenantAsync).
        foreach (var tenant in await session.Query<Tenant>().ToListAsync())
        {
            integrity.Verify(tenant);
            await anchors.CheckAsync(tenant);

            var reEncrypted = 0;
            foreach (var entry in tenant.JwtKeys)
            {
                if (keyProtector.IsProtectedWithCurrentKey(entry.PrivateKey)) continue;
                entry.PrivateKey = keyProtector.Protect(
                    keyProtector.Unprotect(entry.PrivateKey, entry.Kid), entry.Kid);
                reEncrypted++;
            }

            var sealStale = !integrity.IsSealedWithCurrentKey(tenant);
            if (reEncrypted > 0 || sealStale)
            {
                integrity.Seal(tenant);
                session.Store(tenant);
                anchorQueue.Add(tenant);
                invalidatedTenants.Add(tenant);
                result.SigningKeysReEncrypted += reEncrypted;
                if (sealStale) result.TenantsReSealed++;
            }
        }

        await session.SaveChangesAsync();

        // Anchors are recorded only after the save succeeds — never anchor an unpersisted version.
        foreach (var doc in anchorQueue)
            await anchors.RecordAsync(doc);

        // Drop cached copies of re-sealed/re-encrypted tenants so no previous-KEK copy outlives this.
        foreach (var tenant in invalidatedTenants)
            await TenantEndpoints.InvalidateTenantCacheAsync(redis, tenant);

        logger.LogInformation(
            "Rekey pass complete: re-encrypted {SigningKeys} signing key(s); re-sealed {Total} document(s) " +
            "(tenants {Tenants}, users {Users}, credentials {Creds}, roles {Roles}, groups {Groups}, refresh {Refresh}).",
            result.SigningKeysReEncrypted, result.TotalReSealed, result.TenantsReSealed, result.UsersReSealed,
            result.CredentialsReSealed, result.RolesReSealed, result.GroupsReSealed, result.RefreshTokensReSealed);

        return result;
    }
}
