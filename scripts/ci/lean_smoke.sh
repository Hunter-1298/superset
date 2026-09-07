#!/usr/bin/env bash
#
# Licensed to the Apache Software Foundation (ASF) under one or more
# contributor license agreements.  See the NOTICE file distributed with
# this work for additional information regarding copyright ownership.
# The ASF licenses this file to You under the Apache License, Version 2.0
# (the "License"); you may not use this file except in compliance with
# the License.  You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# Smoke test the exact production (`lean`) image that was scanned. Nothing is
# rebuilt or re-tagged: the reference must be an immutable registry digest that
# is already present in the local daemon (see pull_exact_image.sh).
#
#   scripts/ci/lean_smoke.sh <repo@sha256:digest> <evidence-dir>
#
# Verifies, in order:
#   1. the image runs as the non-root `superset` user
#   2. the installed apache-superset version matches the source tree
#   3. `superset db upgrade` succeeds and the metadata DB sits at the migration head
#   4. `superset fab create-admin` and `superset init` succeed
#   5. the default entrypoint (gunicorn) serves /health = 200 "OK" within 120 s
#   6. a valid DB login returns a JWT, /api/v1/me/ answers 200 for it,
#      and an invalid login is rejected with 401
# Container logs and every HTTP response are written to <evidence-dir>.
set -euo pipefail

IMAGE_REF="${1:?image reference (repo@sha256:...)}"
OUT="${2:?evidence dir}"
HEALTH_TIMEOUT="${HEALTH_TIMEOUT:-120}"
ADMIN_USER="${ADMIN_USER:-admin}"
ADMIN_PASSWORD="${ADMIN_PASSWORD:-$(python3 -c 'import secrets; print(secrets.token_urlsafe(24))')}"
SECRET_KEY="${SUPERSET_SECRET_KEY:-$(python3 -c 'import secrets; print(secrets.token_urlsafe(42))')}"
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$HERE/../.." && pwd)"
EXPECTED_VERSION="${EXPECTED_VERSION:-$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["version"])' "$REPO_ROOT/superset-frontend/package.json")}"

case "$IMAGE_REF" in
  *@sha256:*) ;;
  *) echo "::error::refusing mutable image reference '$IMAGE_REF'" >&2; exit 2;;
esac
docker image inspect --format '{{join .RepoDigests "\n"}}' "$IMAGE_REF" | grep -qx -- "$IMAGE_REF" \
  || { echo "::error::$IMAGE_REF is not present locally under that digest; pull_exact_image.sh first" >&2; exit 2; }

mkdir -p "$OUT"
RUN_ID="lean-smoke-$$"
VOLUME="${RUN_ID}-home"
SERVER="${RUN_ID}-server"
STATUS=1
STEP="setup"
declare -A RESULTS=()

cleanup() {
  docker logs "$SERVER" > "$OUT/server.log" 2>&1 || true
  docker rm -f "$SERVER" > /dev/null 2>&1 || true
  docker volume rm -f "$VOLUME" > /dev/null 2>&1 || true
  python3 - "$OUT/lean-smoke.json" "$IMAGE_REF" "$STATUS" "$STEP" "${!RESULTS[@]}" <<'PY' "${RESULTS[@]}"
import json, sys
out, image_ref, status, step, *rest = sys.argv[1:]
n = len(rest) // 2
keys, values = rest[:n], rest[n:]
json.dump(
    {
        "image_ref": image_ref,
        "passed": status == "0",
        "failed_step": None if status == "0" else step,
        "checks": dict(zip(keys, values)),
    },
    open(out, "w"),
    indent=2,
    sort_keys=True,
)
PY
  if [[ "$STATUS" -ne 0 ]]; then
    echo "::error::lean-smoke failed at step '$STEP' (see $OUT)" >&2
  fi
}
trap cleanup EXIT

record() { RESULTS["$1"]="$2"; echo "[$1] $2"; }
fail() { echo "::error::$*" >&2; exit 1; }

# Runs the image's own CLI as the image's own user with the same volume the server uses.
run_cli() {
  docker run --rm --platform linux/amd64 \
    -e SUPERSET_SECRET_KEY="$SECRET_KEY" \
    -v "$VOLUME:/app/superset_home" \
    "$IMAGE_REF" "$@"
}

STEP="non-root user"
CONFIG_USER="$(docker image inspect --format '{{.Config.User}}' "$IMAGE_REF")"
[[ "$CONFIG_USER" == "superset" ]] || fail "image USER is '$CONFIG_USER', expected superset"
UID_IN_IMAGE="$(run_cli id -u)"
[[ "$UID_IN_IMAGE" != "0" ]] || fail "image runs as uid 0"
record user "$CONFIG_USER (uid $UID_IN_IMAGE)"

STEP="version"
VERSION="$(run_cli python -c 'import importlib.metadata as m; print(m.version("apache-superset"))')"
[[ "$VERSION" == "$EXPECTED_VERSION" ]] || fail "apache-superset is $VERSION, source tree says $EXPECTED_VERSION"
record version "$VERSION"

STEP="db upgrade"
run_cli superset db upgrade > "$OUT/db-upgrade.log" 2>&1 || { cat "$OUT/db-upgrade.log"; fail "superset db upgrade failed"; }
run_cli superset db current > "$OUT/db-current.log" 2>&1 || { cat "$OUT/db-current.log"; fail "superset db current failed"; }
grep -q '(head)' "$OUT/db-current.log" || { cat "$OUT/db-current.log"; fail "metadata DB is not at the migration head"; }
record migrations "$(grep '(head)' "$OUT/db-current.log" | tail -1 | tr -d '\r')"

STEP="create-admin + init"
run_cli superset fab create-admin \
  --username "$ADMIN_USER" --firstname Smoke --lastname Test \
  --email "smoke@example.invalid" --password "$ADMIN_PASSWORD" > "$OUT/create-admin.log" 2>&1 \
  || { cat "$OUT/create-admin.log"; fail "create-admin failed"; }
run_cli superset init > "$OUT/init.log" 2>&1 || { cat "$OUT/init.log"; fail "superset init failed"; }
record init "ok"

STEP="server start"
docker run -d --name "$SERVER" --platform linux/amd64 \
  -e SUPERSET_SECRET_KEY="$SECRET_KEY" \
  -v "$VOLUME:/app/superset_home" \
  -p 127.0.0.1::8088 \
  "$IMAGE_REF" > /dev/null
PORT="$(docker port "$SERVER" 8088/tcp | head -1 | sed 's/.*://')"
BASE="http://127.0.0.1:${PORT}"
SERVER_UID="$(docker exec "$SERVER" id -u)"
[[ "$SERVER_UID" != "0" ]] || fail "server container runs as uid 0"

STEP="health"
deadline=$((SECONDS + HEALTH_TIMEOUT))
health_code=""
while (( SECONDS < deadline )); do
  health_code="$(curl -s -o "$OUT/health.txt" -w '%{http_code}' "$BASE/health" || true)"
  if [[ "$health_code" == "200" ]] && grep -qx 'OK' "$OUT/health.txt"; then
    break
  fi
  if ! docker inspect --format '{{.State.Running}}' "$SERVER" 2>/dev/null | grep -q true; then
    docker logs "$SERVER" 2>&1 | tail -50
    fail "server container exited before /health answered"
  fi
  sleep 2
done
if ! { [[ "$health_code" == "200" ]] && grep -qx 'OK' "$OUT/health.txt"; }; then
  docker logs "$SERVER" 2>&1 | tail -50
  fail "/health did not return 200 OK within ${HEALTH_TIMEOUT}s (last: $health_code)"
fi
record health "200 OK after $((HEALTH_TIMEOUT - (deadline - SECONDS)))s"

STEP="login"
login_code="$(curl -s -o "$OUT/login.json" -w '%{http_code}' \
  -H 'Content-Type: application/json' \
  -d "$(python3 -c 'import json,sys; print(json.dumps({"username": sys.argv[1], "password": sys.argv[2], "provider": "db", "refresh": True}))' "$ADMIN_USER" "$ADMIN_PASSWORD")" \
  "$BASE/api/v1/security/login")"
[[ "$login_code" == "200" ]] || { cat "$OUT/login.json"; fail "login returned $login_code"; }
TOKEN="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["access_token"])' "$OUT/login.json")"
# Keep the token in memory only; the evidence copy records which keys were issued, not their values.
python3 - "$OUT/login.json" <<'PY'
import json, sys
p = sys.argv[1]
d = json.load(open(p))
json.dump({k: "<redacted>" for k in d}, open(p, "w"), indent=2)
PY
[[ -n "$TOKEN" ]] || fail "login response has no access_token"
me_code="$(curl -s -o "$OUT/me.json" -w '%{http_code}' -H "Authorization: Bearer $TOKEN" "$BASE/api/v1/me/")"
[[ "$me_code" == "200" ]] || { cat "$OUT/me.json"; fail "/api/v1/me/ returned $me_code"; }
ME_USER="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["result"]["username"])' "$OUT/me.json")"
[[ "$ME_USER" == "$ADMIN_USER" ]] || fail "/api/v1/me/ is '$ME_USER', expected $ADMIN_USER"
record login "JWT issued; /api/v1/me/ -> $ME_USER"

STEP="invalid login"
bad_code="$(curl -s -o "$OUT/login-invalid.json" -w '%{http_code}' \
  -H 'Content-Type: application/json' \
  -d "$(python3 -c 'import json,sys; print(json.dumps({"username": sys.argv[1], "password": "definitely-wrong-" + sys.argv[2], "provider": "db"}))' "$ADMIN_USER" "$ADMIN_PASSWORD")" \
  "$BASE/api/v1/security/login")"
[[ "$bad_code" == "401" ]] || { cat "$OUT/login-invalid.json"; fail "invalid login returned $bad_code, expected 401"; }
record invalid_login "401"

STATUS=0
echo "lean-smoke passed for $IMAGE_REF"
