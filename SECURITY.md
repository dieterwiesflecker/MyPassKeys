# Security Policy

MyPassKeys is authentication infrastructure, so we take security reports seriously.

## Reporting a vulnerability

**Please do not open a public GitHub issue for security vulnerabilities.**

Instead, report privately through one of:

- GitHub's [private vulnerability reporting](https://docs.github.com/en/code-security/security-advisories/guidance-on-reporting-and-writing-information-about-vulnerabilities/privately-reporting-a-security-vulnerability)
  ("Report a vulnerability" under the **Security** tab of this repository), or
- email **urslis@proton.me**.

Please include:

- a description of the issue and its impact,
- steps to reproduce (a proof-of-concept if possible),
- affected version / commit,
- any suggested remediation.

We aim to acknowledge reports within **72 hours** and to provide a remediation timeline after
triage. We'll credit reporters who wish to be acknowledged once a fix is released.

## Scope

In scope: authentication bypasses, token forgery, tenant isolation breaks, privilege escalation,
DPoP/replay weaknesses, key/secret exposure, and integrity-seal / rollback-protection defeats.

Out of scope: findings that require compromising the application server itself (the KEK holder) —
the at-rest protections are explicitly documented as defending against database/Redis-level
attackers only, not a full app-server compromise (see `CLAUDE.md` → "Residual risks").

## Deploying securely

- Always set a strong, unique `MyPassKeys:KeyEncryptionKey` and keep it out of the database.
- Never commit real secrets. `.env` is gitignored; use `.env.example` as the template.
- Populate `ForwardedHeaders:KnownNetworks` / `KnownProxies` in production so `X-Forwarded-For`
  cannot be spoofed to bypass rate limiting.
- Never expose the development-only `/debug/token` endpoint in production (it is only wired when
  the environment is Development).
