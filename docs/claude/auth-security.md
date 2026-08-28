# Auth & Security

## DPoP authentication

Custom `Fido2TokenAuthenticationHandler` validates `Authorization: DPoP <token>` + `DPoP` proof header. Tokens bound via `cnf` claim with JWK thumbprint. JTI replay protection in Redis. DPoP prevents stolen token reuse.

**JTI cache keys are hashed**: the replay key is `dpop-jti:{base64(SHA-256(jti))}` via `TokenService.DpopJtiReplayKey` (both call sites — `GetDpopKeyFromProof` and `ValidateTokenAsync`). The `jti` is attacker-controlled and unbounded; hashing bounds the Redis key to a fixed 32 bytes so oversized `jti` values can't exhaust memory. Use the helper — never interpolate a raw `jti` into a Redis key.

**Enforcement**: any endpoint marked `.RequireAuthorization()` is enforced by this handler, which **rejects requests without a `cnf` claim** — plain bearer tokens are unconditionally refused. There is no fallback scheme.

## FIDO2 flow

Email verification (`request-verification` → `verify`) required before first registration. Then registration (`make-credential-options` → `make-credential`) and authentication (`assertion-options` → `make-assertion`) with challenges stored in Redis (3-min expiry).

**Assertion subject invariant (`make-assertion`)**: the token subject is resolved from the **verified credential's owner** (`GetUserByIdAsync(cred.UserId)`), NEVER from the caller-supplied `username` query param. The assertion is verified against `cred.PublicKey` and the authenticator's `userHandle` is checked to equal `cred.UserId`, so `cred.UserId` is the authenticated identity; the request is rejected if the supplied `username` doesn't match that owner. This closes a cross-user auth bypass where anyone holding one valid passkey could mint a token for another user by passing a different `username`. Do not "simplify" this back to a username lookup.

## Per-tenant registration policy

Each tenant carries `RegistrationMode` (`open` | `domain-allowlist` | `invite-only`, default `open`) and `AllowedEmailDomains: string[]`. Centralized in `RegistrationPolicy` (`Tenant.cs`) and enforced at two points: (1) `auth/email/request-verification` silently suppresses ineligible emails — it never reveals "domain rejected" vs "uninvited" vs "already registered" (all return the same generic response, otherwise enumerable); (2) `make-credential-options` rejects self-registration for `invite-only` tenants and, for pre-created `invite-only` users registering their *first* passkey, requires a fresh email-verification token (otherwise an attacker who learns an invited address could race the legitimate user to attach a passkey).

Domain entry syntax: a bare `example.com` matches the apex only; `*.example.com` matches any subdomain (strict — does NOT match the apex). Combine both entries to admit both. Wildcards are accepted ONLY as the literal `*.` prefix; other patterns (`foo.*.com`, `*foo.com`, bare `*`, `**.foo`) are rejected at upsert with a 400 listing the invalid entries. Entries are normalized (trim, strip leading `@`, lowercase, dedupe) at the API boundary. For `invite-only`, the convention is that `Fido2AppUser.Username` equals the email — admins pre-create via `POST /users` and the user then completes `request-verification` → `verify` → `make-credential` against that username.

## Cross-tenant passkey trust links + JIT provisioning

`Tenant.TrustedCredentialTenantIds` (Guid[], set via `POST`/`PUT /tenants`, tenantadmin-gated, validated: no self-reference, ids must exist) makes THIS tenant accept `make-assertion` against credentials stored in the listed tenants. Built for path-separated apps sharing one domain (WebAuthn scopes passkeys to the rpId/domain, so the browser offers the same passkey to every app on it): register once in app1's tenant, then log in to app2's tenant with the same passkey. The trust is **directed and non-transitive** — for symmetric app-switching, set the link on both tenants.

There is NO background sync: on a trusted login where no local user exists, one is provisioned **just-in-time** subject to the target tenant's `RegistrationMode` (`RegistrationPolicy.CanJitProvision`: `open` always, `domain-allowlist` iff the email domain matches, `invite-only` never — there the admin-pre-created user *is* the invite and logs in without JIT; an existing local user always logs in regardless of mode). The JIT user gets only the target tenant's policy-default roles (`WithPolicyRolesAsync`, same catalog-intersected logic as self-registration) — rights stay strictly per-tenant, nothing is copied from the home tenant, and tokens are always minted with the target tenant's issuer/keys/roles.

Invariants:
- **(a)** the **credential stays single-homed** — counter updates use `UpsertCredentialForTenantAsync(cred.TenantId, ...)`; the current-tenant `UpsertCredentialAsync` would silently re-home it (do not "simplify" this back).
- **(b)** the assertion-subject invariant carries over — the home-tenant owner is resolved via `GetUserByIdForTenantAsync(cred.TenantId, cred.UserId)`, the supplied `username` must match that owner, and only then is the *local* subject resolved by username.
- **(c)** rejections return the same generic 401 (no policy leak).

`assertion-options` unions trusted-tenant credentials into `allowCredentials` (still no enumeration signal) and `make-credential-options` unions them into `excludeCredentials` so the authenticator refuses to mint a duplicate same-domain passkey. Cross-domain abuse is impossible regardless of trust config: a foreign-domain credential never passes rpId-hash verification.

**Silent app switch — `POST /auth/exchange`** (anonymous route, `refresh` rate limit): body `{subjectToken}` + `DPoP` proof header (htm/htu of the exchange call, `ath` of the subject token) + target `X-Tenant-ID`. The unvalidated `tenant_id` claim only *selects* which trusted tenant's keys must then fully validate the token (`TokenService.ValidateTokenForTenantAsync` — the explicit-tenant twin of `ValidateTokenAsync`; signature, issuer/audience, lifetime, session cutoffs, complete DPoP validation). The subject token must be DPoP-bound (`cnf` required, mirroring the auth handler); the home user is resolved from the validated `sub` via `GetUserByIdForTenantAsync`, then the same local-subject/JIT logic as `make-assertion` runs and target-tenant tokens are minted bound to the same DPoP key (`TokenService.ReadDpopJwk` — extracts the jwk without re-validating, since a second validating pass would trip the proof's JTI replay check).

## Token lifecycle

Access tokens (configurable, default 60 min), refresh tokens (configurable, default 720 hours) with rotation and revocation. `TokenService` handles signing (private key), validation (public key), DPoP proof validation, and JWK thumbprint computation.

## Refresh-token rotation & replay defense

On refresh, new tokens are minted first, then the old token is marked `IsRevoked` with a `RevokedAt` timestamp (rotation is last so a generation failure doesn't strand the session). Reuse of an already-revoked token is age-discriminated via `Fido2Endpoints.IsReplayOutsideGraceWindow`: within `RefreshReplayGraceWindow` (60s) of rotation it's treated as a benign concurrent-tab race (reject only that request); **outside** the window it's treated as theft and `RevokeUserRefreshTokensAsync` nukes the user's whole refresh-token family. Both branches return an identical generic 401 so the caller can't tell which fired. A null `RevokedAt` (legacy tokens) fails safe toward the benign branch. Tokens are DPoP-bound via `DpopJkt`; a bound token can't be refreshed without proving possession of the same key.

## JWT signing key rotation (background)

`BackgroundKeyManagementService` runs hourly. Auto-rotates when `KeyRotationIntervalInDays` is exceeded (retires old key, creates new). Cleans up retired keys older than `RefreshTokenLifetimeInHours`. After any change it invalidates the Redis tenant cache via the shared `TenantEndpoints.InvalidateTenantCacheAsync` (internal) helper — the same one the manual `/tenants/{id}/rotate-key`, `/cleanup-keys` and `PUT /tenants/{id}` endpoints use. Use this helper for **all** cache invalidation; it clears every key shape (`Tenant:host:{host}`, `Tenant:origin:{origin}`, `Tenant:id:{id}`, `Tenant:name:{name}`, `Tenant:management`). Do not hand-roll a single-key delete — an earlier bug deleted a non-existent `Tenant:{host}` key, leaving a stale (retired) signing key cached for the 5-min TTL after each rotation.

## Forced re-login / session revocation

`POST /tenants/{id}/revoke-sessions` (tenantadmin) and `POST /users/{id}/revoke-sessions` (`roles:manage`) revoke refresh tokens **and** set an access-token cutoff so existing tokens die immediately. The tenant-wide cutoff is `Tenant.SessionsValidFrom`; the per-user cutoff is a Redis key `user-sessions-revoked:{tenantId}:{userId}` (TTL = access-token lifetime). `TokenService.ValidateTokenAsync` rejects any token whose `iat` predates the applicable cutoff (whole-second granularity, so a re-login in the same second is not locked out). Access tokens are otherwise non-revocable — validation is stateless.

## Rate limiting

`auth` policy (10 req/min/IP), `refresh` policy (20 req/min/IP), `email` policy (5 req/min/IP), `tenant-create` policy (5 req/hour/IP, applied to `POST /tenants`). All partitioned by IP because `UseRateLimiter` runs before authentication.
