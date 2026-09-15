#!/usr/bin/env bash
#
# Development PostgreSQL on :5433 (keeps :5432 free for anything else).
# Usage: bash scripts/dev-postgres.sh up | down | psql

set -euo pipefail

NAME="solvaren-pg"
PORT="${SOLVAREN_PG_PORT:-5433}"

case "${1:-up}" in
  up)
    if docker ps --format '{{.Names}}' | grep -q "^${NAME}$"; then
      echo "Already running on :${PORT}"
    else
      docker run -d --name "${NAME}" -p "${PORT}:5432" \
        -e POSTGRES_PASSWORD=postgres postgres:16 >/dev/null
      echo "Started ${NAME} on :${PORT}"
      echo "  export DATABASE_URL=postgres://postgres:postgres@localhost:${PORT}/postgres"
    fi
    ;;
  down)
    docker rm -f "${NAME}" >/dev/null 2>&1 || true
    echo "Stopped ${NAME}"
    ;;
  psql)
    docker exec -it "${NAME}" psql -U postgres
    ;;
  *)
    echo "Usage: $0 up|down|psql" >&2
    exit 1
    ;;
esac
