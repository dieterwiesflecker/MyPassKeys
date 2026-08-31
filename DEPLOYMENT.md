# Deploying MyPassKeys

MyPassKeys is a single container (`mypasskeys`) plus PostgreSQL and Redis. It expects to sit
behind a TLS-terminating reverse proxy (Caddy, Traefik, nginx, …). WebAuthn **requires HTTPS**
(except on `localhost`), so a real domain with a valid certificate is mandatory in production.

This guide is the **production** path (`ASPNETCORE_ENVIRONMENT=Production`): real secrets in the
server's `.env`, developer tooling off, required config enforced. For how that differs from running
locally in Development mode, see [README → Local development vs. production](README.md#local-development-vs-production).

## 1. Prepare the server

All production configuration lives in a single `.env` file on the server — you never edit
`appsettings.json`. Copy `.env.example` to `/opt/mypasskeys/.env` and fill in the values flagged
**REQUIRED IN PRODUCTION**:

```bash
# On the server
mkdir -p /opt/mypasskeys
# Copy .env.example to /opt/mypasskeys/.env and fill it in:
#   POSTGRES_PASSWORD, REDIS_PASSWORD  -> strong unique values
#   KEY_ENCRYPTION_KEY                 -> openssl rand -base64 32   (BACK THIS UP)
#                                         (or leave empty — ./deploy.sh generates one for you)
#   DEPLOYMENT_HOST                    -> your public hostname, e.g. auth.example.com
#   ISSUER_BASE_URL                    -> https://<that host>       (keep stable forever)
#   BOOTSTRAP_OWNER_EMAIL              -> the account that owns the management tenant
#   BOOTSTRAP_MANAGEMENT_ORIGIN        -> your admin-portal origin (first boot only)
#   RESEND_API_KEY, RESEND_FROM_EMAIL  -> if you want verification emails
```

`compose.prod.yaml` treats `DEPLOYMENT_HOST`, `ISSUER_BASE_URL` and `BOOTSTRAP_OWNER_EMAIL` as
mandatory — the stack refuses to start if any is missing, so a misconfigured deploy fails loudly
instead of silently 404'ing.

## 2. Point a reverse proxy at it

The app listens on `:8080`. Example Caddyfile:

```
auth.example.com {
  reverse_proxy localhost:8080
}
```

`DEPLOYMENT_HOST` in `.env` must match this hostname — the host-gate middleware 404s any request
whose `Host` isn't a deployment host (or a per-tenant custom subdomain).

## 3. Deploy

From your workstation, copy `deploy.env.example` → `deploy.env`, fill in `SERVER` and
`AUTH_DOMAIN`, then:

```bash
./deploy.sh
```

This builds the image locally, ships it over SSH, and runs
`docker compose -f compose.yaml -f compose.prod.yaml up -d` on the server.

> Prefer a registry-based flow? Push the image to GHCR (or any registry) from CI and have the
> server `docker compose pull && up -d` instead of the tarball upload. The compose files work
> either way — just replace the local `build:` with an `image:` pointing at your registry tag.

## Running MyPassKeys alongside other services on one server

MyPassKeys deliberately ships **only** the passkeys stack. If you also run other services on the
same box (for example a separate embedding/ML API, an app backend, etc.), keep each project in its
own repository and let a **single reverse proxy** front all of them by hostname:

```
auth.example.com   -> mypasskeys:8080
api.example.com    -> your-other-service:xxxx
app.example.com    -> your-frontend
```

Recommended layout:

- Each project has its own `compose.yaml` and its own `.env`.
- One shared Caddy (or Traefik) instance terminates TLS and routes by domain.
- Give each project its **own** PostgreSQL/Redis unless you have a specific reason to share — the
  isolation is cleaner and one project's migration can't disturb another.
- Keep server-specific glue (the real domains, the Caddyfile, the production `.env` files) in a
  **private** ops repo or just on the server — never in the public application repos.

This keeps the public MyPassKeys repository free of any host, domain, or secret specific to your
deployment.

## KEK rotation (zero-downtime)

The key-encryption key (KEK) encrypts every tenant's signing key at rest. Rotate it periodically
without downtime — the app keeps a "previous" KEK live during the transition so nothing is
stranded:

1. **Start the rotation:**
   ```bash
   ./deploy.sh rotate-kek
   ```
   Moves the current KEK to `PREVIOUS_KEY_ENCRYPTION_KEY`, generates a fresh current key in the
   server's `.env`, and restarts the app. On startup it re-encrypts all signing keys and re-seals
   all documents under the new key (reading old blobs via the previous key).

2. **Verify everything moved:** as a management-tenant `tenantadmin`, call
   `POST https://<AUTH_DOMAIN>/admin/rekey` and confirm the response shows
   `"fullyOnCurrentKey": true` with every count `0`. Re-run until clean.

3. **Retire the old key:**
   ```bash
   ./deploy.sh retire-kek
   ```
   Removes `PREVIOUS_KEY_ENCRYPTION_KEY` and restarts. Only do this **after** step 2 confirms
   nothing still depends on the old key — once it's gone, anything still on it is unrecoverable.

Keep only two live KEKs at a time (current + one previous). Losing the current KEK with no valid
backup makes all signing keys unrecoverable.

## Restoring a PostgreSQL backup

MyPassKeys uses Redis "version anchors" to detect document rollbacks, so a restored Postgres
backup will fail closed unless you tell it the restore is intentional. Start the app **once** with
`MyPassKeys__ResetVersionAnchors=true`, let it re-adopt the restored versions as the new baseline,
then remove the flag and restart. See `CLAUDE.md` → "Rollback protection" for the full rationale.
