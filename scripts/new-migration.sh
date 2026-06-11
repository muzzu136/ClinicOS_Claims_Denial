#!/usr/bin/env bash
# new-migration.sh — create the next numbered migration file.
#
# Usage:   ./scripts/new-migration.sh <description_in_snake_case>
# Example: ./scripts/new-migration.sh add_orders_table
#          → creates worker/migrations/0002_add_orders_table.sql
#
# Why use this instead of picking a number yourself: sequence numbers
# are append-only and the deploy pipeline assumes strict ordering. This
# script scans worker/migrations/ for the highest existing NNNN_ prefix
# and increments. Avoids duplicate numbers, gaps, and out-of-order files.

set -euo pipefail

if [ $# -ne 1 ]; then
  echo "usage: $0 <description_in_snake_case>" >&2
  echo "example: $0 add_orders_table" >&2
  exit 1
fi

DESCRIPTION="$1"

# Validate description: lowercase letters, digits, underscores only.
if ! [[ "$DESCRIPTION" =~ ^[a-z][a-z0-9_]*$ ]]; then
  echo "error: description must be snake_case (lowercase, digits, underscores; start with a letter)" >&2
  echo "got: $DESCRIPTION" >&2
  exit 1
fi

# Resolve repo root via this script's location, then find migrations dir.
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
MIGRATIONS_DIR="$REPO_ROOT/worker/migrations"

if [ ! -d "$MIGRATIONS_DIR" ]; then
  echo "error: $MIGRATIONS_DIR does not exist" >&2
  echo "this app does not appear to use migrations yet" >&2
  exit 1
fi

# Find the highest existing NNNN_ prefix. Files are NNNN_xxx.sql; if none
# exist yet, start at 0001.
HIGHEST=$(ls "$MIGRATIONS_DIR" 2>/dev/null \
  | grep -E '^[0-9]{4}_' \
  | sed -E 's/^([0-9]{4})_.*/\1/' \
  | sort -n \
  | tail -1 \
  || true)

if [ -z "$HIGHEST" ]; then
  NEXT="0001"
else
  # Strip leading zeros for arithmetic, then zero-pad back to 4.
  NEXT=$(printf "%04d" $((10#$HIGHEST + 1)))
fi

OUTFILE="$MIGRATIONS_DIR/${NEXT}_${DESCRIPTION}.sql"

if [ -e "$OUTFILE" ]; then
  echo "error: $OUTFILE already exists" >&2
  exit 1
fi

cat > "$OUTFILE" <<EOF
-- ${NEXT}_${DESCRIPTION}.sql
--
-- Append-only: do not edit after this file has been deployed.
-- See worker/migrations/0001_initial.sql for the full rules.

EOF

echo "created: $OUTFILE"
echo ""
echo "next: edit the file to add your DDL, then commit + deploy."
