#!/usr/bin/env bash
# Delegates to the cross-platform Node implementation (scripts/check-invariants.mjs).
set -euo pipefail
cd "$(dirname "$0")/.."
exec node scripts/check-invariants.mjs
