#!/usr/bin/env bash
# Drive the isolated TEST stack (project leviathan-test) without ever touching
# the running production stack (project leviathan-ai-edge).
#
#   ./test-stack.sh up        build + start the test stack
#   ./test-stack.sh down      stop + remove test containers (keeps test volumes)
#   ./test-stack.sh nuke      down + delete test volumes (fresh ledger next up)
#   ./test-stack.sh logs      follow logs
#   ./test-stack.sh ps        list test containers
#   ./test-stack.sh topup ID [AMOUNT]   credit a test identity (default 100 credits)
#
# Safety: every compose call is pinned to `-p leviathan-test`, so it can only
# create/stop containers, networks and volumes labelled with that project.
# Production (leviathan-ai-edge) is a different project and is never selected.
set -euo pipefail
cd "$(dirname "$0")"

PROJECT=leviathan-test
FILES=(-f docker-compose.yml -f docker-compose.wallet.yml -f docker-compose.test.yml)
ENVFILE=.env.test

dc() { docker compose -p "$PROJECT" "${FILES[@]}" --env-file "$ENVFILE" "$@"; }

case "${1:-}" in
  up)
    [ -f "$ENVFILE" ] || { echo "Missing $ENVFILE — cp .env.test.example .env.test and edit it."; exit 1; }
    # A guard: refuse to run if this would somehow target production.
    if [ "$PROJECT" = "leviathan-ai-edge" ]; then echo "refusing: PROJECT is production"; exit 1; fi
    dc up -d --build
    EDGE_DOMAIN="$(grep -E '^EDGE_PUBLIC_DOMAIN=' "$ENVFILE" | cut -d= -f2-)"
    echo
    echo "test stack up (project $PROJECT). Production containers untouched."
    echo "  dApp : https://${EDGE_DOMAIN}:8443/wallet/"
    echo "  API  : https://${EDGE_DOMAIN}:8443/v1/...  (direct: http://127.0.0.1:18090)"
    echo "  admin: http://127.0.0.1:18000   (topup: ./test-stack.sh topup <identity_id>)"
    echo
    echo "First start: the test Caddy fetches a Let's Encrypt cert via DNS-01."
    echo "Watch it:  ./test-stack.sh logs   (look for 'certificate obtained')."
    echo "Ensure the host firewall allows inbound TCP 8443."
    ;;
  down)  dc down ;;
  nuke)  dc down -v ;;
  logs)  dc logs -f --tail=100 ;;
  ps)    dc ps ;;
  topup)
    id="${2:?usage: ./test-stack.sh topup <identity_id> [amount_credits]}"
    amount="${3:-100}"
    token="$(grep -E '^ADMIN_TOKEN=' "$ENVFILE" | cut -d= -f2-)"
    curl -fsS -X POST http://127.0.0.1:18000/v1/topup \
      -H "Authorization: Bearer $token" -H 'content-type: application/json' \
      -d "{\"identity_id\": $id, \"amount\": $amount, \"source\": \"test-$(id -u)-$RANDOM\"}"
    echo
    ;;
  *)
    grep -E '^#( |$)' "$0" | sed 's/^# \{0,1\}//'
    exit 1 ;;
esac
