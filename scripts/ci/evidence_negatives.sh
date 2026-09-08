#!/usr/bin/env bash
# Licensed to the Apache Software Foundation (ASF) under one
# or more contributor license agreements.  See the NOTICE file
# distributed with this work for additional information
# regarding copyright ownership.  The ASF licenses this file
# to you under the Apache License, Version 2.0 (the
# "License"); you may not use this file except in compliance
# with the License.  You may obtain a copy of the License at
#
#   http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing,
# software distributed under the License is distributed on an
# "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
# KIND, either express or implied.  See the License for the
# specific language governing permissions and limitations
# under the License.
#
# Prove that the controller's fail-closed evidence intake rejects invalid and
# source-mismatched bundles, using a real scan-evidence bundle from this
# repository as the starting point.
#
#   evidence_negatives.sh BUNDLE_DIR RUN_ID RUN_ATTEMPT HEAD_SHA OUT_DIR
#
# The pristine bundle must be accepted first (positive control). Every other
# case copies the bundle, applies one change, and requires `hardening-loop
# evidence-verify` to exit non-zero with a rejection reason naming that change.
# Verdicts are written to OUT_DIR/<case>.json; the script fails on the first
# case whose outcome differs from the expectation.
set -euo pipefail

BUNDLE="${1:?extracted scan-evidence bundle directory}"
RUN_ID="${2:?workflow run id the bundle came from}"
RUN_ATTEMPT="${3:?workflow run attempt}"
HEAD_SHA="${4:?head sha GitHub reports for that run}"
OUT_DIR="${5:?output directory for verdicts}"

: "${GITHUB_REPOSITORY:?GITHUB_REPOSITORY must be set}"
GIT_CHECKOUT="${GIT_CHECKOUT:-.}"
SOURCE_BRANCH="${SOURCE_BRANCH:-main}"
EVENT="${EVENT:-push}"
# BASELINE_SHA overrides the controller's built-in baseline (only for exercising the script
# against a synthetic bundle whose git history is not the fork's).
BASELINE_ARGS=()
if [ -n "${BASELINE_SHA:-}" ]; then
  BASELINE_ARGS=(--baseline-sha "$BASELINE_SHA")
fi

mkdir -p "$OUT_DIR"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

verify() {
  # verify NAME BUNDLE [extra evidence-verify args...]; echoes the exit code
  local name="$1" bundle="$2"
  shift 2
  set +e
  hardening-loop evidence-verify "$bundle" \
    --run-id "$RUN_ID" --run-attempt "$RUN_ATTEMPT" --head-sha "$HEAD_SHA" \
    --source-repo "$GITHUB_REPOSITORY" --source-branch "$SOURCE_BRANCH" \
    --event "$EVENT" --git "$GIT_CHECKOUT" "${BASELINE_ARGS[@]}" \
    --out "$OUT_DIR/$name.json" "$@" > "$OUT_DIR/$name.log" 2>&1
  local rc=$?
  set -e
  echo "$rc"
}

expect_rejected() {
  # expect_rejected NAME BUNDLE REASON_SUBSTRING [extra args...]
  local name="$1" bundle="$2" needle="$3"
  shift 3
  local rc
  rc="$(verify "$name" "$bundle" "$@")"
  if [ "$rc" -eq 0 ]; then
    echo "::error::${name}: evidence was ACCEPTED, expected rejection (${needle})"
    cat "$OUT_DIR/$name.log"
    exit 1
  fi
  if ! grep -Fq "$needle" "$OUT_DIR/$name.json"; then
    echo "::error::${name}: rejected, but no reason mentions '${needle}'"
    cat "$OUT_DIR/$name.log"
    exit 1
  fi
  echo "${name}: rejected as expected (${needle})"
}

copy_bundle() {
  local dest="$WORK/$1"
  rm -rf "$dest"
  cp -R "$BUNDLE" "$dest"
  echo "$dest"
}

# Positive control: the untouched bundle must pass, otherwise the negatives prove nothing.
rc="$(verify pristine "$BUNDLE")"
if [ "$rc" -ne 0 ]; then
  echo "::error::pristine bundle was rejected; cannot run negatives against it"
  cat "$OUT_DIR/pristine.log"
  exit 1
fi
echo "pristine: accepted (positive control)"

# 1. A raw scanner result is altered after the manifest was written.
b="$(copy_bundle tampered-raw)"
target="$(python3 - "$b" <<'PY'
import json, pathlib, sys
root = pathlib.Path(sys.argv[1])
files = json.loads((root / "manifest.json").read_text())["files"]
raw = sorted(f for f in files if f.endswith("trivy-vuln.json"))
print(raw[0] if raw else sorted(files)[0])
PY
)"
printf '\n' >> "$b/$target"
expect_rejected tampered-raw "$b" "checksum mismatch"

# 2. The manifest itself is edited to claim another source commit.
b="$(copy_bundle tampered-manifest)"
python3 - "$b" <<'PY'
import json, pathlib, sys
p = pathlib.Path(sys.argv[1]) / "manifest.json"
m = json.loads(p.read_text())
m["source_sha"] = "0" * 40
p.write_text(json.dumps(m, indent=2) + "\n")
PY
expect_rejected tampered-manifest "$b" "manifest.json does not match SHA256SUMS"

# 3. An attached runtime record is altered.
b="$(copy_bundle tampered-runtime)"
runtime="$(python3 - "$b" <<'PY'
import json, pathlib, sys
root = pathlib.Path(sys.argv[1])
m = json.loads((root / "manifest.json").read_text())
listed = (m.get("attachments") or {}).get("runtime") or []
print(listed[0] if listed else "")
PY
)"
if [ -z "$runtime" ]; then
  echo "::error::tampered-runtime: bundle lists no runtime attachments; scan-manifest must attach lean-smoke and app-runs records"
  exit 1
fi
printf '\n' >> "$b/$runtime"
expect_rejected tampered-runtime "$b" "checksum mismatch"

# 4. Source-mismatched: the run GitHub reports is for a different head commit.
expect_rejected wrong-head "$BUNDLE" "workflow run was for" \
  --head-sha "ffffffffffffffffffffffffffffffffffffffff"

# 5. Source-mismatched: evidence presented as if from another branch.
expect_rejected wrong-branch "$BUNDLE" "source_branch" --source-branch upstream-master

# 6. Source-mismatched: evidence presented as if from another repository.
expect_rejected wrong-repo "$BUNDLE" "source_repo" --source-repo "${GITHUB_REPOSITORY_OWNER}/not-superset"

# 7. Source-mismatched: manifest claims a different workflow run.
expect_rejected wrong-run "$BUNDLE" "manifest run_id" --run-id "$((RUN_ID + 1))"

# 8. Incomplete bundle: scan-manifest never wrote manifest.json.
b="$(copy_bundle no-manifest)"
rm -f "$b/manifest.json"
expect_rejected no-manifest "$b" "no manifest.json"

# 9. Incomplete bundle: a required scan job directory is missing.
b="$(copy_bundle missing-job)"
job_dir="$(python3 - "$b" <<'PY'
import json, pathlib, sys
root = pathlib.Path(sys.argv[1])
m = json.loads((root / "manifest.json").read_text())
name = sorted(m["jobs"])[0]
target, mode = name.split("-", 1)
print(f"{target}/{mode}")
PY
)"
rm -rf "${b:?}/${job_dir:?}"
expect_rejected missing-job "$b" "missing evidence file"

{
  echo "### evidence negatives"
  echo
  echo "pristine bundle accepted; every mutated or mis-attributed presentation rejected:"
  echo
  for f in "$OUT_DIR"/*.json; do
    n="$(basename "$f" .json)"
    [ "$n" = pristine ] && continue
    echo "- \`${n}\`: $(python3 -c 'import json,sys; print("; ".join(json.load(open(sys.argv[1]))["reasons"]))' "$f")"
  done
} >> "${GITHUB_STEP_SUMMARY:-/dev/null}"
