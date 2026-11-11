#!/usr/bin/env bash
# Starts a throwaway PostgreSQL cluster, applies migrations and runs the DB tests.
# Requires PostgreSQL server binaries (initdb, pg_ctl). When run as root, the cluster runs as the "postgres" user.
set -euo pipefail

cd "$(dirname "$0")/.."

PG_BIN="${PG_BIN:-$(dirname "$(command -v initdb 2>/dev/null || ls -d /usr/lib/postgresql/*/bin/initdb | sort -V | tail -1)")}"
PORT="${TEST_PG_PORT:-54329}"
DATA="$(mktemp -d)"
chmod 755 "$DATA"

as_pg() {
  if [ "$(id -u)" -eq 0 ]; then
    runuser -u postgres -- "$@"
  else
    "$@"
  fi
}

cleanup() {
  as_pg "$PG_BIN/pg_ctl" -D "$DATA/pg" -m immediate stop >/dev/null 2>&1 || true
  rm -rf "$DATA"
}
trap cleanup EXIT

if [ "$(id -u)" -eq 0 ]; then chown postgres "$DATA"; fi
as_pg "$PG_BIN/initdb" -D "$DATA/pg" -U owner --auth=trust -E UTF8 >/dev/null
as_pg "$PG_BIN/pg_ctl" -D "$DATA/pg" -o "-p $PORT -c listen_addresses=127.0.0.1 -c unix_socket_directories=$DATA" -w start >/dev/null
as_pg "$PG_BIN/createdb" -h 127.0.0.1 -p "$PORT" -U owner deepsec_test

export TEST_DATABASE_URL="postgres://owner@127.0.0.1:$PORT/deepsec_test"
node --test "test/db/*.test.ts"
