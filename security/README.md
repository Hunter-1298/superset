<!--
    Licensed to the Apache Software Foundation (ASF) under one
    or more contributor license agreements.  See the NOTICE file
    distributed with this work for additional information
    regarding copyright ownership.  The ASF licenses this file
    to you under the Apache License, Version 2.0 (the
    "License"); you may not use this file except in compliance
    with the License.  You may obtain a copy of the License at

      http://www.apache.org/licenses/LICENSE-2.0

    Unless required by applicable law or agreed to in writing,
    software distributed under the License is distributed on an
    "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
    KIND, either express or implied.  See the License for the
    specific language governing permissions and limitations
    under the License.
-->

# CVE hardening loop: how this fork is scanned and remediated

This fork of Apache Superset is the target of an event-driven CVE remediation
loop. `main` was created from the `6.1.0` release commit
`c83fb2bb1dcfac41ac51bcebd82471f4a7180d18` and is the only branch that is
scanned, remediated and gated. `master` is the fork's original history and
`upstream-master` mirrors `apache/superset` for comparison; neither is touched
by the loop. Nothing here is ever pushed to `apache/superset`.

The automation lives in
[Hunter-1298/superset-hardening-loop](https://github.com/Hunter-1298/superset-hardening-loop)
(the "controller"). This repository holds the CI that produces the evidence the
controller consumes, the human-approved OpenVEX documents, and the issue and
label conventions the two sides share. For the threat model that decides what
counts as a vulnerability, read [`SECURITY.md`](../SECURITY.md) first.

## What runs, and when

`.github/workflows/security-scan.yml` runs on every push and pull request to
`main` and nightly at 06:17 UTC. One run does the following, and every job
addresses the same immutable image digests:

| job | what it proves |
|---|---|
| `forbid-ignore-files` | no `.trivyignore`, `.grype.yaml` or similar exists anywhere in the tree |
| `vex-lint` | every document under `security/vex/approved/` is valid OpenVEX and cites an issue labelled `disposition:approved`; nothing from `security/vex/proposed/` is duplicated there |
| `build-image` | builds the `lean` (production) and `ci` (Postgres driver added) Dockerfile targets for `linux/amd64`, pushes them to GHCR by digest, and signs a SLSA build-provenance attestation for each digest |
| `scan-lean-raw`, `scan-ci-raw` | Syft SBOM + Trivy + Grype on the exact digest, no suppression of any kind; raw JSON and SARIF are both kept |
| `scan-lean-policy` | the same scan of the same digest with only the approved OpenVEX applied |
| `policy-gate` | applies `SCAN_GATE_MODE` to the policy scan of `lean` (see below) |
| `lean-smoke` | pulls the exact `lean` digest, checks its labels, platform and non-root user, runs `db upgrade`/`init`, starts the default entrypoint and checks `/health` and a DB login |
| `app-runs` | starts the exact `ci` digest with Postgres and Redis and exercises migrations, health, login, dashboards, chart data, SQL Lab and CSV export |
| `scan-manifest` | verifies both provenance attestations, then writes `manifest.json` + `SHA256SUMS` over every scan result, gate verdict, runtime record and provenance file and uploads the single `scan-evidence-<sha>` artifact |

The `ci` image exists only because the production image has no Postgres
driver; its extra layer is recorded in the manifest as `ci_layer_delta` and its
scan is filed as separate integration coverage, never mixed into the `lean`
numbers.

### Gate mode

`SCAN_GATE_MODE` is `report` unless the repository variable `SCAN_GATE_MODE`
or a manual dispatch input says `enforce`.

* `report` records the policy HIGH and CRITICAL counts for `lean` and stays
  green, so a dependency regression shows up as a larger count, not a red
  check. This is the mode to stay in until the counts are genuinely zero.
* `enforce` fails on every policy HIGH or CRITICAL finding, whether or not a
  fixed version exists.

Raw scans are never gated and never read VEX; their evidence is what the
controller normalizes, classifies and turns into issues.

### Controller pin

Scan scripts and the `hardening-loop` CLI are installed from the controller at
the commit written into `CONTROLLER_REF` in `security-scan.yml` (and mirrored
in `evidence-negatives.yml`). Push, pull request and scheduled runs cannot use
anything else: the `install-scanners` action refuses a non-SHA ref outside
`workflow_dispatch` and fails if the checkout does not resolve to the pin. The
controller commit that produced a bundle is recorded in its manifest as
`controller_sha`. Bumping the pin is an ordinary reviewed pull request.

### Provenance

`build-image` disables BuildKit's in-index attestations so that the pushed
digest is a plain image manifest every job can address. Provenance is instead
attached to that exact digest by `scripts/ci/attest_provenance.sh`: a SLSA v1
predicate built from the run context and the buildx metadata, signed keylessly
with cosign under the run's OIDC identity, recorded in the Sigstore
transparency log and stored next to the image in GHCR. `scan-manifest` runs
`scripts/ci/verify_provenance.sh`, which requires an attestation signed by this
repository's `security-scan` workflow for the commit being built (checked on
the Fulcio certificate, which the workflow body cannot influence) whose
statement names exactly the digest, carries the SLSA v1 predicate type and
describes this run id and attempt. The signed envelopes, decoded statements,
attestation manifests, uploaded predicates and buildx metadata are filed under
`provenance/` in the bundle. Anyone can repeat the check:

```bash
cosign verify-attestation --type slsaprovenance1 \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  --certificate-identity 'https://github.com/<owner>/superset/.github/workflows/security-scan.yml@refs/heads/main' \
  ghcr.io/<owner>/superset@sha256:<digest>
```

## Evidence bundle

Each run's `scan-evidence-<sha>` artifact is the only thing the controller
ingests. It contains:

```
manifest.json           run, source, images, jobs, gates, attachments, controller_sha
SHA256SUMS              every file below, plus manifest.json
lean/raw/  lean/policy/  ci/raw/
                        job.json, sbom, trivy-vuln.json(.sarif), grype-vuln.json(.sarif)
gates/lean-policy.json  policy gate verdict
runtime/lean-smoke/     lean-smoke.json and the server / migration logs
runtime/app-runs/       per-check JSON records, HTTP artifacts, screenshots, logs
provenance/             cosign envelopes, decoded statements and attestation
                        manifests per digest; buildx/ metadata and predicates
registry/               image manifest and config as fetched from GHCR
```

The controller accepts a bundle only when it is the single unexpired evidence
artifact of a completed run, every checksum matches, and the manifest's
repository, branch, commit, run id and attempt, platform, required jobs,
scanner set and runtime results match what GitHub reports for that run and
descend from the baseline. A rejected bundle is persisted as rejected; a run
whose `lean-smoke` or `app-runs` failed is persisted as incomplete and can
never close a finding. You can apply the same checks offline:

```bash
hardening-loop evidence-verify ./scan-evidence-<sha> --run-id <id> --head-sha <sha> --git .
```

## Negative tests

None of these run on ordinary pushes; each is triggered by an operator.

* **`evidence-negatives`** (this repository, `workflow_dispatch`): takes the
  latest successful `main` bundle (or a given run id), confirms it is accepted
  untouched, then requires rejection after a raw scanner result is altered,
  after the manifest is edited, after an attached runtime record is altered,
  and when the same bundle is presented for another head commit, branch,
  repository or run id, with `manifest.json` missing, and with a scan job
  directory missing. Verdicts are uploaded as `evidence-negatives-<run id>`.
* **`ci-negative`** (controller repository, `workflow_dispatch`): opens draft
  pull requests against `main` here for a broken build, a broken runtime, a
  dependency regression (which edits a source input and regenerates the pins
  with `scripts/uv-pip-compile.sh`, never by hand), a scanner ignore file and
  an unapproved VEX document, and checks that `security-scan` fails the first
  four while `report` mode stays green with a larger policy count for the
  regression. It cleans its branches up afterwards. It lives in the controller
  because it needs a token allowed to push branches here.

## Labels

The controller creates any missing label on first use. Meaning matters more
than colour:

| label | set by | meaning |
|---|---|---|
| `hardening-loop` | controller | issue is managed by the loop; the title starts with `[hardening-loop]` |
| `kind:dependency-upgrade`, `kind:no-fix-reachability`, `kind:container-hardening`, `kind:scanner-disagreement`, `kind:helm-deploy-config` | controller | remediation path (kinds 1 to 5) |
| `severity:critical`, `severity:high`, `severity:medium`, `severity:low` | controller | highest severity among the grouped findings |
| `risk:high` | controller | every fixed version of the dependency is blocked by a `pyproject.toml` upper bound, so the upgrade needs a bound change too |
| `awaiting-dispatch-approval` | controller | the item will not be sent to Devin until a human adds `dispatch:approved` |
| `dispatch:approved` | human | authorizes one Devin session for this issue (HIGH/CRITICAL are approved by default policy; the label is also written by an operator launch from the dashboard) |
| `needs-human` | controller | the session stopped, exhausted its cap, produced no PR, or hit something it must not decide; read the last comment |
| `retry` | human | after fixing whatever blocked it, asks the controller to resume the same session within the remaining cap |
| `disposition:approved` | human | a kind-2 OpenVEX statement in `security/vex/proposed/` may be moved to `approved/` |
| `disagreement:resolved` | human | a kind-4 scanner disagreement has been decided; the decision is in the issue |

## What a human does

1. Review controller pull requests like any other change: CI must be green,
   Devin Review has commented on the exact head commit, and one approval is
   required by branch protection. Merge yourself; the controller never merges.
2. For kind 2, review the reachability argument and the proposed OpenVEX under
   `security/vex/proposed/`, add `disposition:approved` to the issue, and open
   a pull request that moves the document to `security/vex/approved/` with
   `x-approval.issue_url` and `x-approval.approved_by` filled in. `vex-lint`
   checks both.
3. Leave issues open. The controller closes an issue only when a later
   complete, accepted `main` bundle from every original scanner no longer
   contains any of the grouped findings.
4. Open findings the scanners missed with the **Hardening finding** issue form.

Rules that hold everywhere: generated `requirements/*.txt` are regenerated with
`scripts/uv-pip-compile.sh`, never edited; scanner ignore files are refused by
CI; raw evidence is never suppressed; credentials never appear in source or
logs.
