# MyPassKeys

**A self-hostable, multi-tenant FIDO2 / WebAuthn passkey authentication server** with
DPoP (Demonstration of Proof-of-Possession) token binding — built to issue signed,
sender-constrained tokens for your own applications without depending on a third-party
identity provider.

> ⚠️ **Status: early open-source release.** MyPassKeys implements a lot of security-critical
> machinery (asymmetric token signing, DPoP, document-integrity seals, KEK-encrypted keys at
> rest). It has been running in a single production deployment, but it has **not** yet had an
> independent third-party audit. Review it yourself before trusting it with real users, and see
> [SECURITY.md](SECURITY.md) for how to report issues.

## Why

Passwords are phishable and breachable; passkeys aren't. MyPassKeys lets you stand up a passkey
authentication service for one or many applications ("tenants") on your own infrastructure. Your
app backends verify the issued JWTs using published public keys (JWKS) — there is **no shared
secret** between the auth server and your APIs.

## Features

- **Passkeys / WebAuthn** registration and login (built on [Fido2NetLib](https://github.com/passwordless-lib/fido2-net-lib)).
- **DPoP token binding** — access tokens are cryptographically bound to a browser-held key, so a
  stolen token is useless without the private key that never leaves the device.
- **Asymmetric JWT signing** — per-tenant ECDSA P-256 keys; public keys published at
  `/.well-known/jwks.json` for stateless verification by your resource servers.
- **Multi-tenancy** — one deployment serves many applications, each with isolated users,
  credentials, roles, groups and signing keys.
- **RBAC + AD-style groups** — per-tenant role catalog, nested groups, permission claims.
- **Registration policies** — `open` / `domain-allowlist` / `invite-only`, plus cross-tenant
  passkey trust links and just-in-time provisioning for path-separated apps on one domain.
- **Defense in depth at rest** — signing keys are envelope-encrypted (AES-256-GCM) under a
  key-encryption key (KEK); security-critical documents carry HMAC integrity seals and Redis
  version anchors for rollback protection.
- **Email verification**, refresh-token rotation with replay detection, session revocation, and
  IP-partitioned rate limiting.

## Tech stack

- **ASP.NET Core 10** minimal APIs (AOT-friendly, source-generated JSON).
- **PostgreSQL** via [Marten](https://martendb.io/) as a document store.
- **Redis** for challenges, JTI replay detection, and tenant caching.

## Quickstart (local, Docker)

```bash
# 1. Copy the sample environment and fill in secrets
cp .env.example .env
#    - set POSTGRES_PASSWORD, REDIS_PASSWORD
#    - generate a KEK:  openssl rand -base64 32   ->  KEY_ENCRYPTION_KEY
#    - (optional) set RESEND_API_KEY for outbound verification emails

# 2. Bring everything up
docker compose -f compose.yaml up --build
```

The API is then reachable on `http://localhost:8080`. In Development mode an interactive API
reference is served at `/scalar/v1`.

### Running the app standalone

```bash
# Requires a local PostgreSQL + Redis (see appsettings.json for connection strings)
dotnet run --project MyPassKeys/
```

### Tests

```bash
dotnet test MyPassKeys.Tests/MyPassKeys.Tests.csproj
```

## Configuration

All configuration lives in `appsettings.json` (documented inline) and can be overridden with
environment variables using the standard ASP.NET `__` convention (e.g.
`MyPassKeys__KeyEncryptionKey`). The must-set values for any real deployment:

| Setting | Purpose |
| --- | --- |
| `MyPassKeys:KeyEncryptionKey` | **Required.** Base64 32-byte KEK encrypting signing keys at rest. The app refuses to start without it. |
| `MyPassKeys:DeploymentHosts` | Hostnames where this installation is reachable; anything else is 404'd. |
| `MyPassKeys:BootstrapManagementOrigins` | Origins seeded onto the management tenant on first startup. |
| `Tenant:BootstrapOwnerEmail` | Email guaranteed to hold `tenantadmin` in the management tenant. |
| `Resend:ApiKey` / `Resend:FromEmail` | Outbound email for verification codes. |

## How it fits together

```
┌─────────────────────────┐     passkey ceremony + DPoP      ┌──────────────────────────┐
│  Browser / frontend     │ ───────────────────────────────► │  MyPassKeys (auth server)│
│  (holds DPoP key pair)  │ ◄─────── DPoP-bound JWT ───────── │  signs with tenant ECDSA │
└───────────┬─────────────┘                                  └────────────┬─────────────┘
            │  Authorization: DPoP <token> + DPoP proof                   │ publishes public keys
            ▼                                                             ▼
┌─────────────────────────┐   fetches /.well-known/jwks.json   ┌──────────────────────────┐
│  Your API backends      │ ◄───────────────────────────────  │  /.well-known/jwks.json  │
│  verify token + DPoP    │                                    └──────────────────────────┘
└─────────────────────────┘
```

Three independent cryptographic proofs back every authenticated request: the **passkey**
(proves the user), the **JWT signature** (proves MyPassKeys issued the token), and the **DPoP
proof** (proves the caller holds the bound key).

A deep architecture reference — multi-tenancy resolution, the RBAC/group model, document
integrity seals, KEK rotation, and every security invariant — lives in
[CLAUDE.md](CLAUDE.md).

## Deployment

See [DEPLOYMENT.md](DEPLOYMENT.md) for deploying to a single server behind a reverse proxy,
including the zero-downtime KEK-rotation runbook.

## Contributing

Contributions are welcome — see [CONTRIBUTING.md](CONTRIBUTING.md). Because this is an auth
server, security-relevant changes get extra scrutiny.

## License

Licensed under the [Apache License 2.0](LICENSE).
