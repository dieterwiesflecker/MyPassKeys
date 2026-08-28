#!/usr/bin/env bash
set -euo pipefail

# ---------------------------------------------------------------------------
# MyPassKeys single-server deploy helper.
#
# Server-specific settings are read from a gitignored `deploy.env` next to this
# script (copy deploy.env.example → deploy.env). Nothing here is committed with
# your real host or domain in it.
#
# Usage:
#   ./deploy.sh              Build the image locally and deploy everything.
#   ./deploy.sh rotate-kek   Start a key-encryption-key rotation (see DEPLOYMENT.md).
#   ./deploy.sh retire-kek   Finish a rotation by dropping the previous KEK.
# ---------------------------------------------------------------------------

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# --- Load server config ---
if [ -f "$SCRIPT_DIR/deploy.env" ]; then
  # shellcheck disable=SC1091
  source "$SCRIPT_DIR/deploy.env"
fi

: "${SERVER:?Set SERVER (e.g. root@your.server.ip) in deploy.env}"
: "${REMOTE_DIR:=/opt/mypasskeys}"
: "${AUTH_DOMAIN:?Set AUTH_DOMAIN (e.g. auth.example.com) in deploy.env}"

COMPOSE="docker compose -f compose.yaml -f compose.prod.yaml"

usage() {
  sed -n '3,15p' "$SCRIPT_DIR/deploy.sh" | sed 's/^# \{0,1\}//'
}

# --- Restart just the app container so it re-reads the .env (KEK changes need no rebuild) ---
restart_app() {
  echo "=== Restarting mypasskeys to apply .env ==="
  ssh "$SERVER" "cd $REMOTE_DIR && $COMPOSE up -d --force-recreate --no-deps mypasskeys"
}

rotate_kek() {
  echo "=== Rotating KEK on $SERVER ==="
  ssh "$SERVER" "cd $REMOTE_DIR && umask 077 && \
    OLD=\$(grep '^KEY_ENCRYPTION_KEY=' .env | head -1 | cut -d= -f2-) && \
    if [ -z \"\$OLD\" ]; then echo 'ERROR: no KEY_ENCRYPTION_KEY in .env yet — run a normal deploy first.'; exit 1; fi && \
    NEW=\$(openssl rand -base64 32) && \
    { grep -v -e '^KEY_ENCRYPTION_KEY=' -e '^PREVIOUS_KEY_ENCRYPTION_KEY=' .env; \
      echo \"PREVIOUS_KEY_ENCRYPTION_KEY=\$OLD\"; \
      echo \"KEY_ENCRYPTION_KEY=\$NEW\"; } > .env.tmp && mv .env.tmp .env && \
    echo 'Updated .env: previous <- old current, current <- freshly generated key.'"

  restart_app

  cat <<NEXT

=== KEK rotation applied ===
The app restarted and its startup migration is re-encrypting signing keys and re-sealing documents
under the NEW key (old blobs are read via the previous key, still present).

Next steps:
  1. As a management-tenant tenantadmin, call:  POST https://$AUTH_DOMAIN/admin/rekey
     Confirm the response shows  "fullyOnCurrentKey": true  with every count 0.
  2. Then retire the old key:  ./deploy.sh retire-kek
NEXT
}

retire_kek() {
  HAS_PREV=$(ssh "$SERVER" "grep -c '^PREVIOUS_KEY_ENCRYPTION_KEY=..*' $REMOTE_DIR/.env || true")
  if [ "${HAS_PREV:-0}" = "0" ]; then
    echo "Nothing to retire: PREVIOUS_KEY_ENCRYPTION_KEY is not set in the server's .env."
    exit 0
  fi

  if [ "${FORCE:-0}" != "1" ]; then
    echo "This removes the PREVIOUS key-encryption key. Any data still encrypted under it becomes"
    echo "UNRECOVERABLE. Only proceed if POST /admin/rekey reported \"fullyOnCurrentKey\": true."
    read -r -p "Retire the previous KEK now? [y/N] " reply
    case "$reply" in
      y|Y) ;;
      *) echo "Aborted."; exit 1 ;;
    esac
  fi

  echo "=== Retiring previous KEK on $SERVER ==="
  ssh "$SERVER" "cd $REMOTE_DIR && umask 077 && \
    grep -v '^PREVIOUS_KEY_ENCRYPTION_KEY=' .env > .env.tmp && mv .env.tmp .env && \
    echo 'Removed PREVIOUS_KEY_ENCRYPTION_KEY from .env.'"

  restart_app
  echo ""
  echo "=== Previous KEK retired. Rotation complete. ==="
}

full_deploy() {
  echo "=== Building mypasskeys image locally ==="
  docker compose build --pull mypasskeys

  echo "=== Saving mypasskeys image to tarball ==="
  docker save mypasskeys | gzip > /tmp/mypasskeys.tar.gz

  echo "=== Uploading to server ==="
  ssh "$SERVER" "mkdir -p $REMOTE_DIR"
  scp /tmp/mypasskeys.tar.gz "$SERVER:$REMOTE_DIR/"
  scp compose.yaml compose.prod.yaml "$SERVER:$REMOTE_DIR/"

  echo "=== Ensuring .env exists on the server ==="
  ssh "$SERVER" "test -f $REMOTE_DIR/.env || { echo 'ERROR: $REMOTE_DIR/.env not found. Copy .env.example to the server as .env and fill it in.'; exit 1; }"

  # The app refuses to start without a KEK; generate one on the server if the operator forgot.
  echo "=== Ensuring KEY_ENCRYPTION_KEY is set ==="
  ssh "$SERVER" "grep -q '^KEY_ENCRYPTION_KEY=..*' $REMOTE_DIR/.env || { umask 077; echo \"KEY_ENCRYPTION_KEY=\$(openssl rand -base64 32)\" >> $REMOTE_DIR/.env; echo 'Generated new KEY_ENCRYPTION_KEY in .env'; }"

  echo "=== Loading image on server ==="
  ssh "$SERVER" "cd $REMOTE_DIR && docker load < mypasskeys.tar.gz && rm mypasskeys.tar.gz"

  echo "=== Pulling db + redis images on server ==="
  ssh "$SERVER" "cd $REMOTE_DIR && $COMPOSE pull db redis"

  echo "=== Starting all services ==="
  ssh "$SERVER" "cd $REMOTE_DIR && $COMPOSE up -d --force-recreate"

  rm -f /tmp/mypasskeys.tar.gz

  echo "=== Verifying ==="
  ssh "$SERVER" "cd $REMOTE_DIR && $COMPOSE ps"
  sleep 5
  curl -sf -o /dev/null -w "$AUTH_DOMAIN: HTTP %{http_code}\n" \
    "https://$AUTH_DOMAIN/.well-known/jwks.json" || echo "$AUTH_DOMAIN: (jwks needs a tenant/Origin — non-fatal)"
  echo "=== Deploy complete ==="
}

case "${1:-deploy}" in
  deploy)     full_deploy ;;
  rotate-kek) rotate_kek ;;
  retire-kek) retire_kek ;;
  -h|--help|help) usage ;;
  *) echo "Unknown command: $1"; echo ""; usage; exit 1 ;;
esac
