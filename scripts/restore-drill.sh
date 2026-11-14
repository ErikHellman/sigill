#!/usr/bin/env bash
# Backup and restore drill: run Sigill with Litestream replicating to a local file replica,
# write some data through the API, then restore the replica as if onto a fresh host and
# check that the restored database is intact and holds the same data.
#
# Needs: a release or debug `sigill` binary, `litestream` on PATH, python3, curl.
#   scripts/restore-drill.sh [path/to/sigill]
set -euo pipefail

SIGILL=${1:-target/debug/sigill}
WORK=$(mktemp -d)
trap 'kill $(jobs -p) 2>/dev/null || true; rm -rf "$WORK"' EXIT
mkdir -p "$WORK/keys" "$WORK/replica"
export SIGILL_MASTER_KEY=restore-drill-master-key-0123456789abcdef
export SIGILL_CONFIG="$WORK/sigill.toml"
cat > "$SIGILL_CONFIG" <<TOML
[server]
listen = "127.0.0.1:18181"
public_url = "http://127.0.0.1:18181"
[database]
path = "$WORK/live.db"
[bounce]
enabled = false
[delivery]
mode = "smarthost"
smarthost = "127.0.0.1:9"
[streams.transactional]
default_from = "noreply@mail.example.com"
[[domains]]
name = "mail.example.com"
stream = "transactional"
dkim_selector = "d1"
dkim_key_dir = "$WORK/keys"
return_path_domain = "bounces.example.com"
TOML
cat > "$WORK/litestream.yml" <<YML
dbs:
  - path: $WORK/live.db
    replicas:
      - type: file
        path: $WORK/replica
        sync-interval: 1s
YML

"$SIGILL" dkim-keygen >/dev/null
"$SIGILL" migrate >/dev/null
KEY=$("$SIGILL" app create --name drill | awk '/^API key/ {print $3}')
litestream replicate -config "$WORK/litestream.yml" >"$WORK/litestream.log" 2>&1 &
"$SIGILL" serve >"$WORK/serve.log" 2>&1 &
for _ in $(seq 50); do curl -sf --noproxy '*' http://127.0.0.1:18181/healthz >/dev/null && break; sleep 0.2; done

api() { curl -sf --noproxy '*' -H "Authorization: Bearer $KEY" -H 'content-type: application/json' "$@"; }
api -X PUT http://127.0.0.1:18181/v1/templates/drill \
  -d '{"subject":"Drill {{ n }}","html":"<p>{{ n }}</p>","text":"{{ n }}"}' >/dev/null
for n in $(seq 1 25); do
  api -X POST http://127.0.0.1:18181/v1/messages \
    -d "{\"template\":\"drill\",\"to\":[\"r$n@example.org\"],\"variables\":{\"n\":$n}}" >/dev/null
done
sleep 3   # let Litestream ship the WAL

kill %2; wait %2 2>/dev/null || true   # stop sigill cleanly (SIGTERM)
sleep 2; kill %1; wait %1 2>/dev/null || true

litestream restore -config "$WORK/litestream.yml" -o "$WORK/restored.db" "$WORK/live.db"

python3 - "$WORK/live.db" "$WORK/restored.db" <<'PY'
import sqlite3, sys
def stats(path):
    c = sqlite3.connect(path)
    assert c.execute("PRAGMA integrity_check").fetchone()[0] == "ok", path
    return [c.execute(f"SELECT COUNT(*) FROM {t}").fetchone()[0]
            for t in ("apps", "templates", "messages", "deliveries", "delivery_events")]
live, restored = stats(sys.argv[1]), stats(sys.argv[2])
print("live:    ", live)
print("restored:", restored)
assert restored == live, "restored database differs"
assert restored[2] == 25, "expected 25 messages"
print("restore drill passed")
PY
