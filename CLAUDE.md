# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Build & Run Commands

```bash
# Build
dotnet build MyPassKeys/MyPassKeys.csproj

# Run tests
dotnet test MyPassKeys.Tests/MyPassKeys.Tests.csproj

# Run a single test
dotnet test MyPassKeys.Tests/MyPassKeys.Tests.csproj --filter "FullyQualifiedName~TestMethodName"

# Run all services via Docker Compose
docker-compose -f compose.yaml up

# Run .NET app standalone (requires PostgreSQL + Redis)
dotnet run --project MyPassKeys/

# Production deploy (builds image locally, ships to remote server via SSH, configures Caddy)
./deploy.sh
```

## Dependencies

- **`Microsoft.OpenApi` must stay on the 2.x line.** It is pinned as a direct `PackageReference` (currently 2.9.0) to override the vulnerable transitive 2.0.0 (advisory GHSA-v5pm-xwqc-g5wc, patched in 2.7.5). Do NOT bump it to 3.x: `Microsoft.AspNetCore.OpenApi` (ASP.NET Core 10) is built against Microsoft.OpenApi 2.x and its bundled XML-comment source generator assigns to `IOpenApiMediaType.Example`, which became read-only in 3.x — the generated `OpenApiXmlCommentSupport.generated.cs` then fails to compile (`CS0200`). Only move to 3.x once ASP.NET Core itself does.

## Architecture

**Multi-tenant FIDO2/WebAuthn passkey authentication service** with DPoP (Demonstration of Proof-of-Possession) token binding, designed to issue tokens for external tenant applications.

### Services (compose.yaml)
- **MyPassKeys** — ASP.NET Core 10.0 API (port 8080)
- **db** — PostgreSQL 18 (document store via Marten)
- **redis** — Redis 8 (challenge storage, JTI replay detection, tenant caching)

Production overrides in `compose.prod.yaml`. `deploy.sh` builds the image locally, ships it via SSH, and runs `docker compose -f compose.yaml -f compose.prod.yaml up` on the server behind a reverse proxy (Caddy). See `DEPLOYMENT.md`.

### Asymmetric JWT signing
Tokens signed with per-tenant ECDSA P-256 private keys (ES256). Public keys exposed via `/.well-known/jwks.json` so external tenant backends verify tokens without shared secrets. See [token-signing.md](docs/claude/token-signing.md).

## Detailed reference docs

@docs/claude/multitenancy.md
@docs/claude/auth-security.md
@docs/claude/rbac-groups.md
@docs/claude/data-integrity.md
@docs/claude/token-signing.md
@docs/claude/config-infra.md
