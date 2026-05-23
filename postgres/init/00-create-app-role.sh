#!/bin/bash
# Creates the least-privilege application role used by the n8n workflow.
# Runs once at first container init. POSTGRES_APP_PASSWORD must be set.
set -euo pipefail

: "${POSTGRES_APP_PASSWORD:?FATAL: POSTGRES_APP_PASSWORD not set}"
: "${POSTGRES_APP_USER:?FATAL: POSTGRES_APP_USER not set}"

# Escape single quotes in the password for inclusion in an SQL string literal.
ESCAPED_PASSWORD="${POSTGRES_APP_PASSWORD//\'/\'\'}"

# Validate the username — only safe characters, since we interpolate it as an identifier.
if ! [[ "$POSTGRES_APP_USER" =~ ^[a-zA-Z_][a-zA-Z0-9_]*$ ]]; then
  echo "FATAL: POSTGRES_APP_USER contains unsafe characters: $POSTGRES_APP_USER" >&2
  exit 1
fi

psql -v ON_ERROR_STOP=1 \
     --username "$POSTGRES_USER" \
     --dbname "$POSTGRES_DB" <<SQL
DO \$do\$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = '$POSTGRES_APP_USER') THEN
    EXECUTE 'CREATE ROLE "$POSTGRES_APP_USER" LOGIN PASSWORD ''$ESCAPED_PASSWORD''';
  ELSE
    EXECUTE 'ALTER ROLE  "$POSTGRES_APP_USER" WITH PASSWORD ''$ESCAPED_PASSWORD''';
  END IF;
END
\$do\$;
SQL
