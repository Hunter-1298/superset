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
# Sign a SLSA v1 build-provenance attestation for one immutable image digest.
#
#   attest_provenance.sh IMAGE DIGEST TARGET BUILDX_METADATA_JSON OUT_DIR
#
# The predicate is derived from the GitHub Actions run context (repository,
# commit, workflow file, run and attempt) and the buildx metadata that
# build_image.sh recorded for the same digest. cosign signs it keylessly with
# the run's OIDC identity, records the signature in the Sigstore transparency
# log and stores the attestation next to the image in the registry, so the
# image digest that scanners and runtime checks address is not changed. The
# predicate is written to OUT_DIR/<target>-predicate.json for the evidence
# bundle. Requires `id-token: write` and registry push access.
#
# Optional: COSIGN_ATTEST_ARGS may carry extra signer flags (for example a
# `--key` when exercising the scripts against a local registry); production
# runs leave it unset and sign keylessly.
set -euo pipefail

IMAGE="${1:?image without tag, e.g. ghcr.io/owner/superset}"
DIGEST="${2:?image digest sha256:...}"
TARGET="${3:?build target (lean|ci)}"
METADATA="${4:?buildx metadata json written by build_image.sh}"
OUT_DIR="${5:?output directory}"

: "${GITHUB_REPOSITORY:?GITHUB_REPOSITORY must be set}"
: "${GITHUB_SHA:?GITHUB_SHA must be set}"
: "${GITHUB_REF:?GITHUB_REF must be set}"
: "${GITHUB_WORKFLOW_REF:?GITHUB_WORKFLOW_REF must be set}"
: "${GITHUB_RUN_ID:?GITHUB_RUN_ID must be set}"
: "${GITHUB_RUN_ATTEMPT:?GITHUB_RUN_ATTEMPT must be set}"
: "${GITHUB_EVENT_NAME:?GITHUB_EVENT_NAME must be set}"
: "${GITHUB_SERVER_URL:=https://github.com}"
: "${RUNNER_ENVIRONMENT:=github-hosted}"

if [[ ! "$DIGEST" =~ ^sha256:[0-9a-f]{64}$ ]]; then
  echo "::error::${TARGET}: '${DIGEST}' is not a sha256 digest" >&2
  exit 1
fi
if [ ! -f "$METADATA" ]; then
  echo "::error::${TARGET}: buildx metadata ${METADATA} missing" >&2
  exit 1
fi

mkdir -p "$OUT_DIR"
PREDICATE="$OUT_DIR/${TARGET}-predicate.json"

python3 - "$METADATA" "$DIGEST" "$TARGET" "$PREDICATE" <<'PY'
import json
import os
import sys
from datetime import datetime, timezone

metadata_path, digest, target, out = sys.argv[1:5]
metadata = json.load(open(metadata_path))
built = metadata.get("containerimage.digest")
if built != digest:
    sys.exit(f"{metadata_path}: buildx recorded digest {built!r}, attesting {digest}")

env = os.environ
server = env.get("GITHUB_SERVER_URL", "https://github.com")
repo = env["GITHUB_REPOSITORY"]
workflow_path, _, workflow_ref = env["GITHUB_WORKFLOW_REF"].partition("@")
workflow_path = workflow_path.removeprefix(repo + "/")
run_uri = f"{server}/{repo}/actions/runs/{env['GITHUB_RUN_ID']}/attempts/{env['GITHUB_RUN_ATTEMPT']}"

predicate = {
    "buildDefinition": {
        "buildType": "https://actions.github.io/buildtypes/workflow/v1",
        "externalParameters": {
            "workflow": {
                "ref": workflow_ref,
                "repository": f"{server}/{repo}",
                "path": workflow_path,
            },
            "target": target,
            "platform": env.get("PLATFORM", ""),
        },
        "internalParameters": {
            "github": {
                "event_name": env["GITHUB_EVENT_NAME"],
                "repository_id": env.get("GITHUB_REPOSITORY_ID", ""),
                "repository_owner_id": env.get("GITHUB_REPOSITORY_OWNER_ID", ""),
                "runner_environment": env.get("RUNNER_ENVIRONMENT", "github-hosted"),
            },
            "buildx": {
                "image.name": metadata.get("image.name"),
                "containerimage.digest": built,
                "containerimage.config.digest": metadata.get("containerimage.config.digest"),
                "buildx.build.ref": metadata.get("buildx.build.ref"),
            },
        },
        "resolvedDependencies": [
            {
                "uri": f"git+{server}/{repo}@{env['GITHUB_REF']}",
                "digest": {"gitCommit": env["GITHUB_SHA"]},
            }
        ],
    },
    "runDetails": {
        "builder": {"id": f"{server}/{repo}/{workflow_path}@{workflow_ref}"},
        "metadata": {
            "invocationId": run_uri,
            "finishedOn": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        },
    },
}
json.dump(predicate, open(out, "w"), indent=2, sort_keys=True)
print(f"{digest}: predicate written to {out} ({run_uri})")
PY

extra_args=()
if [ -n "${COSIGN_ATTEST_ARGS:-}" ]; then
  # shellcheck disable=SC2206 # deliberate word splitting of operator-supplied flags
  extra_args=(${COSIGN_ATTEST_ARGS})
fi
cosign attest --yes --type slsaprovenance1 --predicate "$PREDICATE" "${extra_args[@]}" "${IMAGE}@${DIGEST}"
echo "${DIGEST}: provenance attestation signed and stored in the registry"
