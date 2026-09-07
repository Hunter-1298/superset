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
# Every approved OpenVEX document names the GitHub issue in which a human approved
# the disposition. This check confirms each such issue really carries the
# `disposition:approved` label, so a document cannot be "approved" by editing JSON.
#
#   scripts/ci/check_vex_issue_dispositions.sh <issues.json>   ({"<vex file>": "<issue url>", ...})
#
# Requires GH_TOKEN with issues:read on the repository.
set -euo pipefail

ISSUES_JSON="${1:?issues json written by 'hardening-loop vex-lint --issues-out'}"
REQUIRED_LABEL="${REQUIRED_LABEL:-disposition:approved}"

mapfile -t ENTRIES < <(python3 -c '
import json, sys
for f, url in sorted(json.load(open(sys.argv[1])).items()):
    print(f"{f}\t{url}")
' "$ISSUES_JSON")

if [[ ${#ENTRIES[@]} -eq 0 ]]; then
  echo "no approved OpenVEX documents reference an issue; nothing to check"
  exit 0
fi

fail=0
for entry in "${ENTRIES[@]}"; do
  file="${entry%%$'\t'*}"
  url="${entry#*$'\t'}"
  # https://github.com/<owner>/<repo>/issues/<n>
  if [[ ! "$url" =~ ^https://github\.com/([^/]+)/([^/]+)/issues/([0-9]+)$ ]]; then
    echo "::error file=$file::x-approval.issue_url '$url' is not a GitHub issue URL" >&2
    fail=1
    continue
  fi
  owner="${BASH_REMATCH[1]}" repo="${BASH_REMATCH[2]}" number="${BASH_REMATCH[3]}"
  labels="$(gh api "repos/${owner}/${repo}/issues/${number}" --jq '[.labels[].name] | join("\n")')"
  if grep -qx -- "$REQUIRED_LABEL" <<< "$labels"; then
    echo "ok: $file -> $url has $REQUIRED_LABEL"
  else
    echo "::error file=$file::$url lacks the '$REQUIRED_LABEL' label (labels: $(tr '\n' ',' <<< "$labels"))" >&2
    fail=1
  fi
done
exit "$fail"
