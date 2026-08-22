#!/usr/bin/env bash
#
# Bring the local stack up, down, or report on it.
#
#   scripts/dev_stack.sh up | down | status
#
# Four processes: a PostgreSQL cluster, the SOC API, the Ask SENTRA service, and
# the Next console. The cluster is owned by the invoking user rather than by
# systemd — Kali ships postgresql-17 without an initialised cluster, and setting
# one up this way needs no root and cannot collide with a system cluster, since
# it listens on 5433 and keeps its data outside /var.
#
# Prerequisites, done once:
#   .venv                     python3 -m venv --system-site-packages .venv
#                             .venv/bin/pip install -r requirements.txt
#   the cluster               initdb (this script does it if the directory is empty)
#   .env                      DATABASE_URL pointing at 127.0.0.1:5433/sentra
#   schema                    .venv/bin/python -m database.migrate
#
# psycopg cannot be installed into Kali's system Python (PEP 668), so every
# Python process here must be .venv/bin/python.

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

PGBIN=${PGBIN:-/usr/lib/postgresql/17/bin}
PGDATA=${PGDATA:-$HOME/.local/share/sentra-pg}
PGPORT=${PGPORT:-5433}
API_PORT=${API_PORT:-8000}
AI_PORT=${AI_PORT:-8100}
WEB_PORT=${WEB_PORT:-3100}
LOGS="$ROOT/.dev-logs"
VENV="$ROOT/.venv/bin/python"

mkdir -p "$LOGS"

port_pid() { ss -ltnp 2>/dev/null | grep ":$1 " | grep -oP 'pid=\K[0-9]+' | head -1; }

wait_for() { # url, label
  for _ in $(seq 1 45); do
    if [ "$(curl -s -o /dev/null -w '%{http_code}' --max-time 2 "$1" 2>/dev/null)" = "200" ]; then
      echo "  ready   $2"
      return 0
    fi
    sleep 1
  done
  echo "  TIMEOUT $2 — see $LOGS"
  return 1
}

case "${1:-status}" in
up)
  [ -x "$VENV" ] || { echo "No .venv. See the header of this script."; exit 1; }

  if [ ! -d "$PGDATA/base" ]; then
    echo "Initialising the cluster in $PGDATA"
    mkdir -p "$(dirname "$PGDATA")"
    "$PGBIN/initdb" -D "$PGDATA" -U "$USER" -A trust --auth-host=trust -E UTF8 >/dev/null
  fi

  if "$PGBIN/pg_isready" -h 127.0.0.1 -p "$PGPORT" >/dev/null 2>&1; then
    echo "  running postgres :$PGPORT"
  else
    "$PGBIN/pg_ctl" -D "$PGDATA" -l "$LOGS/postgres.log" \
      -o "-p $PGPORT -k /tmp -c listen_addresses=127.0.0.1" start >/dev/null
    echo "  started postgres :$PGPORT"
  fi

  # createdb is not idempotent, so an existing database is not an error here.
  "$PGBIN/createdb" -h 127.0.0.1 -p "$PGPORT" -U "$USER" sentra 2>/dev/null || true
  "$PGBIN/createdb" -h 127.0.0.1 -p "$PGPORT" -U "$USER" sentra_test 2>/dev/null || true

  # setsid and </dev/null matter: without a new session and a detached stdin the
  # children stay in the caller's process group, so whatever invoked this script
  # waits on them and kills them when it gives up.
  spawn() { # logfile, command...
    local log=$1; shift
    setsid nohup "$@" > "$log" 2>&1 < /dev/null &
    disown 2>/dev/null || true
  }

  [ -n "$(port_pid "$API_PORT")" ] || spawn "$LOGS/api.log" \
    "$VENV" -m uvicorn api_server:app --host 127.0.0.1 --port "$API_PORT"

  [ -n "$(port_pid "$AI_PORT")" ] || spawn "$LOGS/ai.log" \
    "$VENV" -m uvicorn prototype_ai_chat.api:app --host 127.0.0.1 --port "$AI_PORT"

  # The local binary, not npx: npx will go to the network if it cannot resolve.
  [ -n "$(port_pid "$WEB_PORT")" ] || ( cd Frontend && \
    setsid nohup ./node_modules/.bin/next start -p "$WEB_PORT" \
      > "$LOGS/web.log" 2>&1 < /dev/null & disown 2>/dev/null || true )

  wait_for "http://127.0.0.1:$API_PORT/health" "SOC API      :$API_PORT" || true
  wait_for "http://127.0.0.1:$AI_PORT/health"  "Ask SENTRA   :$AI_PORT"  || true
  wait_for "http://127.0.0.1:$WEB_PORT/dashboard" "console      :$WEB_PORT" || true
  echo
  echo "  Console: http://localhost:$WEB_PORT"
  ;;

down)
  for p in "$WEB_PORT" "$AI_PORT" "$API_PORT"; do
    pid=$(port_pid "$p")
    [ -n "$pid" ] && { kill "$pid" 2>/dev/null || true; echo "  stopped :$p"; }
  done
  # The cluster is left running by default: it holds the incident store, and
  # stopping it is a separate decision from restarting the services.
  if [ "${2:-}" = "--with-postgres" ]; then
    "$PGBIN/pg_ctl" -D "$PGDATA" stop >/dev/null 2>&1 && echo "  stopped postgres :$PGPORT"
  else
    echo "  postgres left running (pass --with-postgres to stop it too)"
  fi
  ;;

status)
  "$PGBIN/pg_isready" -h 127.0.0.1 -p "$PGPORT" 2>&1 | sed 's/^/  /' || true
  for pair in "SOC API:$API_PORT:/health" "Ask SENTRA:$AI_PORT:/health" "console:$WEB_PORT:/dashboard"; do
    name=${pair%%:*}; rest=${pair#*:}; port=${rest%%:*}; path=${rest#*:}
    code=$(curl -s -o /dev/null -w '%{http_code}' --max-time 3 "http://127.0.0.1:$port$path" 2>/dev/null)
    printf '  %-11s :%-5s %s\n' "$name" "$port" "${code:-down}"
  done
  ;;

*)
  echo "usage: $0 up|down [--with-postgres]|status"
  exit 1
  ;;
esac
