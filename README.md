# MyPassKeys

[![CI](https://github.com/dieterwiesflecker/MyPassKeys/actions/workflows/ci.yml/badge.svg)](https://github.com/dieterwiesflecker/MyPassKeys/actions/workflows/ci.yml)
[![License: Apache 2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)
[![.NET](https://img.shields.io/badge/.NET-10.0-512BD4?logo=dotnet&logoColor=white)](https://dotnet.microsoft.com/)
[![WebAuthn](https://img.shields.io/badge/FIDO2-WebAuthn-3423A6.svg)](https://www.w3.org/TR/webauthn-2/)

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
# 1. Copy the sample environment. The defaults already work for local development —
#    no edits needed to get started (see the comments in the file for what each does).
cp .env.example .env

# 2. Bring everything up
docker compose -f compose.yaml up --build
```

The API is then reachable on `http://localhost:8080`. In Development mode an interactive API
reference is served at `/scalar/v1`.

Everything the Docker path needs lives in `.env` — you do not edit `appsettings.json`. The
committed defaults ship a **dev-only** KEK and passwords so local just works; the values you must
change before going to production are flagged "REQUIRED IN PRODUCTION" in `.env.example`.

### Running the app standalone

```bash
# Start Postgres + Redis from the same compose file, then run the app on the host:
docker compose -f compose.yaml up -d db redis
dotnet run --project MyPassKeys/
```

A standalone `dotnet run` does **not** read `.env`; it uses `appsettings.json` +
`appsettings.Development.json` (dev-only localhost defaults that match `.env.example`). Kestrel
listens on `http://localhost:5205`.

### Tests

```bash
dotnet test MyPassKeys.Tests/MyPassKeys.Tests.csproj
```

## Configuration

Configuration comes from two places depending on how you run the app:

- **Docker (local & production)** — everything is driven by the **`.env`** file next to the compose
  files. `compose.yaml` maps each `.env` variable to the app's config, so `.env` is the *only* file
  you edit. `.env.example` is the documented, copy-me template.
- **Standalone `dotnet run`** — reads `appsettings.json` + `appsettings.Development.json` (dev-only
  localhost defaults). `.env` is not read on this path.

Under the hood every setting is an ASP.NET config key overridable with the standard `__` env-var
convention (e.g. `MyPassKeys__KeyEncryptionKey`); the compose files just wire the friendly `.env`
names onto those keys. The values you must set for a **real deployment** (all flagged
"REQUIRED IN PRODUCTION" in `.env.example`):

| `.env` variable | Config key | Purpose |
| --- | --- | --- |
| `KEY_ENCRYPTION_KEY` | `MyPassKeys:KeyEncryptionKey` | **Required.** Base64 32-byte KEK encrypting signing keys at rest. The app refuses to start without it. Back it up. |
| `DEPLOYMENT_HOST` | `MyPassKeys:DeploymentHosts` | Hostname where this installation is reachable; anything else is 404'd. |
| `ISSUER_BASE_URL` | `MyPassKeys:IssuerBaseUrl` | Base for per-tenant token issuers; keep stable for the life of your tenants. |
| `BOOTSTRAP_OWNER_EMAIL` | `Tenant:BootstrapOwnerEmail` | Email guaranteed to hold `tenantadmin` in the management tenant. |
| `BOOTSTRAP_MANAGEMENT_ORIGIN` | `MyPassKeys:BootstrapManagementOrigins` | Admin-portal origin seeded onto the management tenant on first startup. |
| `BOOTSTRAP_MANAGEMENT_ISSUER` / `BOOTSTRAP_MANAGEMENT_AUDIENCE` | `MyPassKeys:BootstrapManagementIssuer` / `…Audience` | JWT issuer/audience for the management tenant, seeded on first startup (blank → derived from `DEPLOYMENT_HOST`). |
| `POSTGRES_PASSWORD` / `REDIS_PASSWORD` | `ConnectionStrings:*` | Strong, unique datastore credentials. |
| `RESEND_API_KEY` / `RESEND_FROM_EMAIL` | `Resend:ApiKey` / `Resend:FromEmail` | Outbound email for verification codes. |

## Local development vs. production

MyPassKeys runs in one of two modes, selected by `ASPNETCORE_ENVIRONMENT`. **Local development is
convenience-first** (ships with working throwaway secrets so it starts with zero setup);
**production is safety-first** (nothing sensitive is committed, real secrets are required, and
developer tooling is switched off). Understand the difference before you expose this to real users.

| | **Local development** | **Production** |
| --- | --- | --- |
| How you run it | `docker compose -f compose.yaml up` **or** `dotnet run` / Rider Run | `docker compose -f compose.yaml -f compose.prod.yaml up -d` (via `./deploy.sh`) |
| `ASPNETCORE_ENVIRONMENT` | `Development` | `Production` |
| Where config comes from | Docker: `.env` with built-in local defaults · standalone: `appsettings.json` + `appsettings.Development.json` | The server's `.env` only — **you never edit `appsettings.json`** |
| Reachable at | `http://localhost:8080` (Docker) / `http://localhost:5205` (standalone) | Your real hostname over **HTTPS**, behind a reverse proxy |
| HTTPS | Not required — WebAuthn exempts `localhost` | **Required.** WebAuthn refuses non-HTTPS origins; you must terminate TLS (Caddy/Traefik/nginx) |
| KEK (`KEY_ENCRYPTION_KEY`) | A shared **dev-only** throwaway key, pre-filled so it just works | A unique key you generate and **back up**; `./deploy.sh` makes one if absent. Losing it is unrecoverable |
| DB / Redis passwords | Throwaway `mypasskeys` | Strong, unique values you set |
| Required-var enforcement | Lenient — sensible defaults fill the gaps | Strict — the stack refuses to start if `DEPLOYMENT_HOST` / `ISSUER_BASE_URL` / `BOOTSTRAP_OWNER_EMAIL` are missing |
| Scalar API explorer (`/scalar/v1`) | **On** | **Off** |
| `/debug/token` (decodes tokens **without auth**) | **On** | **Off** — never exposed |
| Email verification codes | Logged to the console if `RESEND_API_KEY` is empty | Sent for real via a configured Resend key |
| Trusted proxies (`X-Forwarded-For`) | Loopback only | You must list your proxy/CDN CIDRs, or client IPs (used for rate limiting) resolve to the proxy |

**Never treat the local defaults as production-ready.** The committed dev KEK and `mypasskeys`
passwords are public in this repo, and `/scalar/v1` + `/debug/token` deliberately expose internals.
A real deployment must run in `Production` mode (which `./deploy.sh` and `compose.prod.yaml` do for
you) with its own secrets in the server's `.env`. See [DEPLOYMENT.md](DEPLOYMENT.md) for the full
production runbook.

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
