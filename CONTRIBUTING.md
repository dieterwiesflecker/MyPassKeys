# Contributing to MyPassKeys

Thanks for your interest in improving MyPassKeys! This is authentication infrastructure, so
correctness and security matter more than speed.

## Getting started

1. Install the [.NET 10 SDK](https://dotnet.microsoft.com/) and Docker.
2. Fork and clone the repository.
3. `cp .env.example .env` and fill in local secrets (generate a KEK with `openssl rand -base64 32`).
4. `docker compose -f compose.yaml up --build` to run the full stack, or `dotnet run --project MyPassKeys/`
   against a local Postgres + Redis.

## Before you open a PR

- **Build:** `dotnet build MyPassKeys/MyPassKeys.csproj`
- **Test:** `dotnet test MyPassKeys.Tests/MyPassKeys.Tests.csproj` — all tests must pass, and
  new behavior should come with tests.
- **Read [CLAUDE.md](CLAUDE.md).** It documents the security invariants this codebase depends on
  (assertion-subject resolution, document-integrity seals, DPoP enforcement, tenant isolation,
  the escalation guards, KEK handling, AOT serialization registration, …). Many "simplifications"
  are deliberately called out as things **not** to do — please don't undo them without discussion.
- If you add a request/response DTO, register it on `AppJsonSerializerContext` (source-generated
  JSON — otherwise it fails at runtime in published builds).
- If you add an endpoint group, wire it in `Program.cs`.

## Security-sensitive changes

Anything touching token issuance/validation, DPoP, tenant resolution, RBAC, or the integrity/KEK
layers will get extra review. Please describe the threat model impact in your PR. If you believe
you've found a vulnerability, **do not** open a public issue — see [SECURITY.md](SECURITY.md).

## Style

Match the surrounding code — naming, comment density, and idioms. Keep changes focused; unrelated
refactors are harder to review in an auth codebase.

## License

By contributing, you agree that your contributions are licensed under the project's
[Apache License 2.0](LICENSE).
