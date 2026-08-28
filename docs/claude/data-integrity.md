# Document Integrity (HMAC Seals & Rollback Protection)

## HMAC seals

Security-critical documents carry an `Integrity` seal (`v1.{kekId}.{base64 hmac}`): `Tenant`, `Fido2AppUser`, `Fido2StoredCredential`, `TenantRole`, `TenantGroup`, and `Fido2RefreshToken` (the last because an attacker-inserted refresh token could otherwise be exchanged for access tokens). `IDocumentIntegrity` / `HmacDocumentIntegrity` in `DocumentIntegrity.cs`; MAC keys are HKDF-derived from the same KEK ring as signing-key encryption (`MyPassKeys:KeyEncryptionKey` + `PreviousKeyEncryptionKeys`), so there is no second secret to provision and KEK rotation covers both.

**Invariant — all seal/verify plumbing lives in `Fido2MartenDbService`** (plus `TenantService`, which re-verifies resolved tenants because they round-trip the Redis cache): every write of these types seals first (`integrity.Seal(doc)` before `session.Store`), every read verifies (`Verified(...)` wrappers), and loaded documents are verified BEFORE being mutated and re-sealed (re-sealing unverified data would bless tampering). When adding a method there, keep this invariant. Do NOT write these types via raw Marten sessions elsewhere, and do NOT use the Patch API on them (a partial SQL update invalidates the seal — this is why refresh-token revocation loads documents instead of patching; bulk revocation also sets `RevokedAt`, which the replay heuristic treats as intended).

## What's sealed per type

See `CanonicalPayload`: identity (type tag + schema version + TenantId + Id) plus the authorization-relevant fields — user Username/Roles; credential UserId/CredentialId/PublicKey/CredType/SignatureCounter; role Name/Permissions; group Name/members/roles; refresh-token Token/UserId/Expiry/DpopJkt/IsRevoked/RevokedAt; tenant ServerName/IsManagementTenant/Hosts/AllowedOrigins/ServerDomains/issuer/audience/RegistrationMode/SessionsValidFrom/lifetimes/TrustedCredentialTenantIds/AllowedEmailDomains/DefaultRoles/DomainRoles. Cosmetic fields (DisplayName, timestamps, ServerIcon, JwtKeys — the private-key blobs are independently AES-GCM-authenticated) are outside the seal. Collections are canonicalized sorted; timestamps as whole Unix seconds. Bump a payload's schema version only with migration handling.

## Failure = incident

Verification failure throws `DocumentTamperedException` (uncaught → 500; during bootstrap it aborts startup — fail closed, e.g. a tampered bootstrap-owner user stops the app). An idempotent startup migration (first block in the bootstrap scope in `Program.cs`, MUST stay before any verifying read; uses the raw Marten session) seals unsealed legacy documents (logs a Warning count — after the first migration this must stay 0; nonzero later means something wrote behind the app's back), re-seals valid previous-KEK seals, and leaves invalid seals untouched with a Critical log.

## Rollback protection (version anchors)

Every sealed write bumps the document's `Version` (a monotonic write generation, covered by the MAC — `IDocumentIntegrity.Seal` increments it) and, after a successful `SaveChangesAsync`, records it in Redis under `docver:{type}:{id}` (no TTL — ids are never reused, so stale anchors of deleted docs are inert; an expiring anchor would silently reopen the rollback window). Reads compare: stored version below the anchor = a restored older-but-validly-sealed copy → `DocumentTamperedException`; missing anchor (first deploy / Redis loss) is adopted with a warning; anchor behind the doc (crash between save and record) is repaired upward. `IVersionAnchor` / `RedisVersionAnchor` in `VersionAnchor.cs`; checks live in `Fido2MartenDbService.VerifiedAsync` and `TenantService`.

Invariants: record anchors only AFTER SaveChanges succeeds, and never anchor a document that failed verification. Defeating this layer needs write access to BOTH Postgres and Redis.

## Restoring a Postgres backup

Requires a deliberate step: start ONCE with `MyPassKeys:ResetVersionAnchors=true` (env `MyPassKeys__ResetVersionAnchors`) — the startup migration then skips rollback checks and re-adopts the restored versions as the new baseline — and remove the flag again. Without it, every document older than its anchor fails closed after a restore.

## Residual risks (by design, documented)

The startup migration cannot distinguish legitimate legacy documents from attacker-inserted ones while unsealed documents still exist; a rollback executed against BOTH stores (Postgres + Redis anchors) in concert is not detected; and an app-server compromise (KEK holder) defeats the layer entirely — it defends against DB/Redis-level writers only.
