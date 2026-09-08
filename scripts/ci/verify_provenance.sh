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
# Verify the SLSA build-provenance attestations that build-image signed for the
# lean and ci digests, and file the verification results as evidence.
#
#   verify_provenance.sh IMAGE LEAN_DIGEST CI_DIGEST OUT_DIR
#
# For each digest `gh attestation verify` must find an attestation whose subject
# is exactly that digest, signed by a workflow of this repository, with the SLSA
# v1 provenance predicate whose build is the run that produced it. The JSON that
# gh returns is written to OUT_DIR/<target>.json; the script fails on the first
# digest that cannot be verified or whose provenance names another repository.
set -euo pipefail

IMAGE="${1:?image without tag, e.g. ghcr.io/owner/superset}"
LEAN_DIGEST="${2:?lean digest sha256:...}"
CI_DIGEST="${3:?ci digest sha256:...}"
OUT_DIR="${4:?output directory}"

: "${GITHUB_REPOSITORY:?GITHUB_REPOSITORY must be set}"
: "${GITHUB_SHA:?GITHUB_SHA must be set}"
: "${GITHUB_RUN_ID:?GITHUB_RUN_ID must be set}"
: "${GITHUB_RUN_ATTEMPT:?GITHUB_RUN_ATTEMPT must be set}"
: "${GITHUB_SERVER_URL:=https://github.com}"
: "${GH_TOKEN:?GH_TOKEN must be set (gh attestation verify reads the attestation log)}"

mkdir -p "$OUT_DIR"

verify_one() {
  local target="$1" digest="$2" out="$OUT_DIR/$1.json"
  if [[ ! "$digest" =~ ^sha256:[0-9a-f]{64}$ ]]; then
    echo "::error::${target}: '${digest}' is not a sha256 digest" >&2
    return 1
  fi
  gh attestation verify "oci://${IMAGE}@${digest}" \
    --repo "$GITHUB_REPOSITORY" \
    --predicate-type https://slsa.dev/provenance/v1 \
    --format json > "$out"
  python3 - "$out" "$digest" "$GITHUB_REPOSITORY" "$GITHUB_SERVER_URL" "$GITHUB_SHA" \
    "$GITHUB_RUN_ID" "$GITHUB_RUN_ATTEMPT" <<'PY'
import json
import sys

out, digest, repo, server, source_sha, run_id, run_attempt = sys.argv[1:8]
run_uri = f"{server}/{repo}/actions/runs/{run_id}/attempts/{run_attempt}"
results = json.load(open(out))
if not isinstance(results, list) or not results:
    sys.exit(f"{out}: gh returned no verification results")
algo, value = digest.split(":", 1)
for res in results:
    statement = res["verificationResult"]["statement"]
    subjects = statement.get("subject") or []
    if not any(s.get("digest", {}).get(algo) == value for s in subjects):
        sys.exit(f"{out}: attestation subject is not {digest}")
    if statement.get("predicateType") != "https://slsa.dev/provenance/v1":
        sys.exit(f"{out}: predicateType {statement.get('predicateType')!r}")
    # Certificate extensions come from the OIDC token GitHub issued to the signing run and
    # cannot be edited by the workflow, unlike the predicate body.
    cert = res["verificationResult"]["signature"]["certificate"]
    if cert.get("sourceRepositoryURI") != f"{server}/{repo}":
        sys.exit(f"{out}: signed from {cert.get('sourceRepositoryURI')!r}, expected {server}/{repo}")
    if cert.get("sourceRepositoryDigest") != source_sha:
        sys.exit(f"{out}: signed at {cert.get('sourceRepositoryDigest')!r}, this run builds {source_sha}")
    if cert.get("runnerEnvironment") != "github-hosted":
        sys.exit(f"{out}: runnerEnvironment {cert.get('runnerEnvironment')!r}")
    if cert.get("runInvocationURI") != run_uri:
        sys.exit(f"{out}: signed by run {cert.get('runInvocationURI')!r}, this is {run_uri}")
    print(f"{digest}: provenance ok, signed by {cert.get('buildSignerURI')} ({cert.get('runInvocationURI')})")
PY
}

verify_one lean "$LEAN_DIGEST"
verify_one ci "$CI_DIGEST"

{
  echo "### build provenance"
  echo
  echo "- lean \`${LEAN_DIGEST}\`: attestation verified"
  echo "- ci   \`${CI_DIGEST}\`: attestation verified"
} >> "${GITHUB_STEP_SUMMARY:-/dev/null}"
