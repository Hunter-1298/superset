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
# Verify the SLSA v1 provenance attestations that attest_provenance.sh signed
# for the lean and ci digests, and file them as evidence.
#
#   verify_provenance.sh IMAGE LEAN_DIGEST CI_DIGEST OUT_DIR
#
# cosign checks the Sigstore signature and transparency-log entry and, from the
# Fulcio certificate that GitHub's OIDC token produced (which the workflow body
# cannot edit), requires the signer to be this repository's security-scan
# workflow at this run's ref, building this commit. The decoded in-toto
# statement must then name exactly the digest being verified, carry the SLSA v1
# predicate type and describe this run. The raw DSSE envelope, the decoded
# statement and the registry manifest holding the certificate and Rekor bundle
# are written under OUT_DIR so the bundle can be re-verified offline. The
# script fails on the first digest whose attestation is missing or does not
# match.
#
# Optional: COSIGN_VERIFY_ARGS may carry extra verifier flags (for example a
# `--key` when testing against a non-keyless signature); production runs leave
# it unset and use the keyless identity checks below.
set -euo pipefail

IMAGE="${1:?image without tag, e.g. ghcr.io/owner/superset}"
LEAN_DIGEST="${2:?lean digest sha256:...}"
CI_DIGEST="${3:?ci digest sha256:...}"
OUT_DIR="${4:?output directory}"

: "${GITHUB_REPOSITORY:?GITHUB_REPOSITORY must be set}"
: "${GITHUB_SHA:?GITHUB_SHA must be set}"
: "${GITHUB_WORKFLOW_REF:?GITHUB_WORKFLOW_REF must be set}"
: "${GITHUB_RUN_ID:?GITHUB_RUN_ID must be set}"
: "${GITHUB_RUN_ATTEMPT:?GITHUB_RUN_ATTEMPT must be set}"
: "${GITHUB_SERVER_URL:=https://github.com}"

mkdir -p "$OUT_DIR"

SIGNER_IDENTITY="${GITHUB_SERVER_URL}/${GITHUB_WORKFLOW_REF}"
OIDC_ISSUER="https://token.actions.githubusercontent.com"

verifier_args=(
  --type slsaprovenance1
  --certificate-oidc-issuer "$OIDC_ISSUER"
  --certificate-identity "$SIGNER_IDENTITY"
  --certificate-github-workflow-repository "$GITHUB_REPOSITORY"
  --certificate-github-workflow-sha "$GITHUB_SHA"
)
if [ -n "${COSIGN_VERIFY_ARGS:-}" ]; then
  # shellcheck disable=SC2206 # deliberate word splitting of operator-supplied flags
  verifier_args=(--type slsaprovenance1 ${COSIGN_VERIFY_ARGS})
fi

verify_one() {
  local target="$1" digest="$2"
  local envelope="$OUT_DIR/${target}-attestation.jsonl"
  local statement="$OUT_DIR/${target}-statement.json"
  local att_manifest="$OUT_DIR/${target}-attestation-manifest.json"
  if [[ ! "$digest" =~ ^sha256:[0-9a-f]{64}$ ]]; then
    echo "::error::${target}: '${digest}' is not a sha256 digest" >&2
    return 1
  fi
  cosign verify-attestation "${verifier_args[@]}" "${IMAGE}@${digest}" > "$envelope"
  if [ ! -s "$envelope" ]; then
    echo "::error::${target}: cosign accepted ${digest} but returned no attestation" >&2
    return 1
  fi
  # The registry manifest of the attestation carries the signing certificate
  # and the Rekor bundle as layer annotations; keep it for offline re-checks.
  docker buildx imagetools inspect --raw "$(cosign triangulate --type attestation "${IMAGE}@${digest}")" \
    > "$att_manifest"
  python3 - "$envelope" "$statement" "$digest" "$target" "$GITHUB_REPOSITORY" "$GITHUB_SERVER_URL" \
    "$GITHUB_SHA" "$GITHUB_RUN_ID" "$GITHUB_RUN_ATTEMPT" <<'PY'
import base64
import json
import sys

envelope_path, statement_path, digest, target, repo, server, source_sha, run_id, run_attempt = sys.argv[1:10]
run_uri = f"{server}/{repo}/actions/runs/{run_id}/attempts/{run_attempt}"
algo, value = digest.split(":", 1)
slsa_v1 = "https://slsa.dev/provenance/v1"

statements = []
for line in open(envelope_path):
    line = line.strip()
    if not line:
        continue
    env = json.loads(line)
    if env.get("payloadType") != "application/vnd.in-toto+json":
        sys.exit(f"{envelope_path}: payloadType {env.get('payloadType')!r}")
    statements.append(json.loads(base64.b64decode(env["payload"])))
if not statements:
    sys.exit(f"{envelope_path}: no attestation envelopes")

# An immutable digest can carry signature-valid attestations from several runs
# (a rerun or a concurrent build of the same source produces the same digest),
# and cosign returns all of them. Every statement must be well-formed and name
# this digest; the run under verification is proven only by a statement that
# matches every expected field, and only those statements are filed.
def mismatch(st):
    subjects = st.get("subject") or []
    if not any(s.get("digest", {}).get(algo) == value for s in subjects):
        sys.exit(f"{envelope_path}: attestation subject is not {digest}")
    if st.get("predicateType") != slsa_v1:
        return f"predicateType {st.get('predicateType')!r}"
    pred = st.get("predicate") or {}
    build = pred.get("buildDefinition") or {}
    run = pred.get("runDetails") or {}
    ext = build.get("externalParameters") or {}
    if ext.get("target") != target:
        return f"built target {ext.get('target')!r}, expected {target}"
    if (ext.get("workflow") or {}).get("repository") != f"{server}/{repo}":
        return f"names repository {(ext.get('workflow') or {}).get('repository')!r}"
    deps = build.get("resolvedDependencies") or []
    if not any(d.get("digest", {}).get("gitCommit") == source_sha for d in deps):
        return f"does not resolve source commit {source_sha}"
    # cosign re-marshals the predicate through the in-toto Go structs, which
    # spell the field `invocationID`; the SLSA v1 spec spells it `invocationId`.
    meta = run.get("metadata") or {}
    invocation = meta.get("invocationId", meta.get("invocationID"))
    if invocation != run_uri:
        return f"invocation {invocation!r}, this is {run_uri}"
    return None


matched = []
skipped = []
for st in statements:
    reason = mismatch(st)
    if reason is None:
        matched.append(st)
    else:
        skipped.append(reason)
if not matched:
    sys.exit(
        f"{envelope_path}: none of {len(statements)} attestation(s) describes this run: "
        + "; ".join(skipped)
    )

json.dump(matched[0] if len(matched) == 1 else matched, open(statement_path, "w"), indent=2, sort_keys=True)
print(
    f"{digest}: provenance ok ({len(matched)} attestation(s) for {run_uri}, "
    f"{len(skipped)} from other runs ignored)"
)
PY
}

verify_one lean "$LEAN_DIGEST"
verify_one ci "$CI_DIGEST"

{
  echo "### build provenance"
  echo
  echo "- signer: \`${SIGNER_IDENTITY}\` via \`${OIDC_ISSUER}\`"
  echo "- lean \`${LEAN_DIGEST}\`: attestation verified"
  echo "- ci   \`${CI_DIGEST}\`: attestation verified"
} >> "${GITHUB_STEP_SUMMARY:-/dev/null}"
