# Multi-tenancy

## Document store

**Marten** is the active document store on PostgreSQL (not EF Core). Documents: `Fido2AppUser`, `Fido2StoredCredential`, `Fido2RefreshToken`, `Tenant`, `TenantRole`, `TenantGroup`. Schema and indexes configured in `Program.cs` via `AddMarten`. An EF Core implementation (`Fido2EfDbService`) exists behind `IFido2DbService` but is inactive — swap via DI registration in `Program.cs`.

## Deployment hosts vs tenant hosts

`MyPassKeys:DeploymentHosts` (config) lists the hostnames where THIS installation is reachable (e.g. `["auth.example.com", "localhost:5205"]`). A host-gate middleware in `Program.cs` 404s any request whose `Host` is neither a deployment host nor a per-tenant `Tenant.Hosts` entry. Tenants cannot claim a deployment host — `POST`/`PUT /tenants` rejects overlap.

## Tenant resolution order

`TenantService.GetCurrentTenantAsync` resolves the tenant in three steps, each Redis-cached (5-min TTL):

0. **`X-Tenant-ID` header (explicit, authoritative).** Accepts either a tenant **UUID** (cache key `Tenant:id:{id}`) or a **`ServerName`** (cache key `Tenant:name:{name}`, normalized `Trim().ToLower()`). UUID-shaped values only attempt an ID lookup; other strings only attempt a `ServerName` lookup. This is the **only** way to disambiguate apps that share an `Origin` but differ by path (e.g. `abc.com/a-app` vs `abc.com/b-app`) — browsers never send the path, so origin/host alone cannot tell them apart. Frontends should send the **UUID** (immutable); `ServerName` is a guessable, rename-able convenience for dev. **Strict / no fallback**: when the header is present, its result is authoritative — if it resolves to no tenant the resolver returns null (caller 404s) and does **not** fall through to Host/Origin. Silent fallback would mask a bad header and could mis-route to a different tenant than the client intended. Treat `X-Tenant-ID` as a routing hint, never a trust signal — authenticated actions still require a tenant-signed DPoP token.
1. If incoming `Host` is NOT a deployment host, look it up against `Tenant.Hosts` (custom-subdomain mode — a customer CNAMEs `auth.customer.com` to this server). Cache key `Tenant:host:{host}`.
2. Otherwise (deployment host), match the `Origin` header against `Tenant.AllowedOrigins` via `GetTenantsByOriginAsync` (returns **all** matches). Cache key `Tenant:origin:{origin}`. Resolution of the match set: (a) if the **management tenant** is among the matches it always wins — safe because `IsManagementTenant` is never settable via the API, so it cannot be impersonated; (b) else if **more than one** non-management tenant matches, it throws `AmbiguousTenantException` rather than silently picking one (a middleware in `Program.cs` converts it to a **409** telling the caller to send `X-Tenant-ID`) — this is a security boundary: with open self-service a tenant that claims another's origin must not win origin resolution; (c) else the single match resolves. No `Origin` on a deployment host returns null — backends fetching `/.well-known/*` must send an `Origin` header or use a custom subdomain. The management tenant has a separate cache key `Tenant:management`.

**CORS + shared origins**: `AllowedOrigins` is CORS/resolution data, **not** an access boundary (CORS only constrains browsers; the real isolation is per-tenant GUID scoping + per-tenant ECDSA signing keys + DPoP). `AllowedOrigins` has **no collision guard** (unlike `Hosts`), by design — sharing an origin is how path-separated tenants coexist. The CORS preflight (`OPTIONS`) carries no `X-Tenant-ID`, so on a shared origin `TenantCorsPolicyProvider` catches `AmbiguousTenantException` and reflects just the request's `Origin` (allowed by definition if multiple tenants list it); the real request then carries `X-Tenant-ID`.

**Dynamic CORS**: `TenantCorsPolicyProvider` resolves allowed origins per tenant; fallback to `AllowFrontend` policy.

## Management tenant

A single tenant document in each deployment with `IsManagementTenant = true` — the only place from which other tenants can be administered. It is a *regular* tenant otherwise: it has its own users, credentials, refresh tokens, and roles, and is reachable via its `AllowedOrigins` (deployment-host mode) or `Hosts` (custom-subdomain mode) just like any other tenant. It is **not** a super-tenant — it does NOT see or own other tenants' data; each tenant's documents are still strictly tenant-scoped, and there is no installation-wide "see all tenants" role. What makes it special is purely the flag: (a) `POST /tenants` requires the *request's* resolved tenant to be the management tenant — so creating customer tenants only works when calling from a management-tenant origin/host; (b) the flag is set once at bootstrap and is not editable via `PUT /tenants/{id}`; (c) it has its own Redis cache key `Tenant:management`. Mental model: it's "the tenant the admin console logs into" — admin-console users authenticate against it like any RP, and their `tenantadmin`/`useradmin` memberships there are what authorize tenant-management endpoints.

## Tenant provisioning

Tenants are created/updated dynamically via `POST /tenants`, but only when the resolved tenant is the management tenant **and** the caller holds a `tenantadmin` or `useradmin` membership in it. `JwtAudience` is **required** on `POST /tenants` (it identifies the target resource server/app and is shared across tenants that target the same app). `JwtIssuer` is **auto-derived and immutable**: on creation it is set to `{base}/t/{tenantId}` where `base` is `MyPassKeys:IssuerBaseUrl` (falling back to `https://{firstDeploymentHost}`), so every tenant's issuer is globally unique by construction regardless of shared deployment hostnames. Any caller-supplied `JwtIssuer` is ignored on `POST` and cannot be changed via `PUT /tenants/{id}`. Resource servers validating tokens reconstruct the expected issuer from the token's `tenant_id` claim using the same formula. A defensive uniqueness guard (`GetTenantByIssuerAsync`) still rejects issuer collisions with a 409. `Hosts` and `AllowedOrigins` are both editable on existing tenants via `PUT /tenants/{id}`; cache is invalidated for both old and new values so changes apply immediately. **`ServerName` is globally unique (case-insensitive)** because it doubles as an `X-Tenant-ID` selector — enforced by a unique Marten computed index (`Casing.Lower`) plus a 409 guard on `POST`/`PUT`; it is trimmed at the API boundary and display casing is preserved. Every newly created tenant is seeded with the built-in role catalog (`tenantadmin` + `useradmin` + `app`) and the creator is upserted as a `tenantadmin` member of it. **Abuse controls for self-service creation**: `POST /tenants` carries the `tenant-create` rate-limit policy (5/hour/IP — partitioned by IP since the limiter runs before auth) and a per-user quota `MyPassKeys:MaxTenantsPerUser` (default 10, 0 disables) that counts tenants where the caller already holds `tenantadmin` (excluding the management tenant) and returns 429 when exceeded.

## Bootstrap + startup invariant

A new deployment has no tenants and no users, but `POST /tenants` requires an authenticated tenantadmin in the management tenant — a chicken-and-egg. `Program.cs` resolves it as follows, on **every** startup (idempotent):

1. If no management tenant exists yet, seed one with `IsManagementTenant == true`, `AllowedOrigins` from `MyPassKeys:BootstrapManagementOrigins` (string array; trailing slashes stripped), and `JwtIssuer`/`JwtAudience` from `BootstrapManagementIssuer`/`BootstrapManagementAudience`. After this initial seed those config values are **not** re-applied — edit the tenant via `PUT /tenants/{id}` instead.
2. Backfill the built-in role catalog (`tenantadmin`/`useradmin`/`app`) into every existing tenant. Missing built-in roles are added; an already-present built-in role has its permission set **reconciled** — newly-introduced canonical permissions are union'd in (e.g. `roles:read` onto an old `useradmin`) without removing any extra permissions an admin added.
3. **Invariant** — ensure the user from `Tenant:BootstrapOwnerEmail` exists as a `Fido2AppUser` in the management tenant and holds `tenantadmin`. If missing, create a stub user (no passkey yet — they'll attach one on first login). If present but not tenantadmin, add the role. This guarantees the operator can always log back into the management portal, even if every other tenantadmin lost access. To change the bootstrap email, edit the config and restart — the *old* email's tenantadmin grant is NOT revoked; remove it manually via `DELETE /users/{id}/roles/tenantadmin` if desired.

## Tenant-aware FIDO2

`Fido2Factory` creates per-request `IFido2` instances, deriving `rpId` from the `Origin` header (or `Host` fallback) with optional `ServerDomains` overrides for cross-subdomain passkey sharing.

## Well-known endpoints

Defined in `Program.cs`:
- `/.well-known/jwks.json` — tenant's public keys for external JWT verification (includes active + retired keys).
- `/.well-known/webauthn` — tenant's `AllowedOrigins` for W3C Related Origin Requests (cross-origin WebAuthn ceremonies).
