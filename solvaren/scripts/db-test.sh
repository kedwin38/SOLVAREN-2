#!/usr/bin/env bash
#
# Database security assertions: attack the schema directly with psql (spec §24).
#
# The guarantees under test are enforced by triggers and CHECK constraints, so a mocked
# database proves nothing. Requires a migrated PostgreSQL and SOLVAREN test data seeded
# by db/tests/immutability.sql.
#
# Usage: bash scripts/db-test.sh [host] [port] [database]
# Env:   PGUSER, PGPASSWORD

set -euo pipefail
cd "$(dirname "$0")/.."

HOST="${1:-localhost}"
PORT="${2:-5432}"
DB="${3:-postgres}"

export PGHOST="$HOST" PGPORT="$PORT" PGDATABASE="$DB"

echo "SOLVAREN database security assertions"
echo "target: $HOST:$PORT/$DB"
echo ""

psql -X -q -v ON_ERROR_STOP=0 -f db/tests/immutability.sql 2>&1 | tee /tmp/solvaren-db-test.log

# The SQL script raises exceptions on failure; count them.
errors=$(grep -c 'ERROR' /tmp/solvaren-db-test.log || true)
if [ "$errors" -gt 0 ]; then
  echo ""
  echo "✗ $errors assertion(s) failed."
  exit 1
fi
echo ""
echo "✓ All database assertions passed."
