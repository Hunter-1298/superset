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
# Pull an image by immutable registry digest and refuse to continue unless the
# pulled image was built from the expected commit, Dockerfile target and platform.
# Every downstream job (scans, smoke test, app-runs) goes through this check so a
# stale cache, a re-tagged image or a mutable tag can never be verified by mistake.
#
#   scripts/ci/pull_exact_image.sh <repo@sha256:digest> <target: lean|ci> <source-sha> [platform]
set -euo pipefail

IMAGE_REF="${1:?image reference (repo@sha256:...)}"
TARGET="${2:?image target (lean|ci)}"
SOURCE_SHA="${3:?expected source commit}"
PLATFORM="${4:-${PLATFORM:-linux/amd64}}"

case "$IMAGE_REF" in
  *@sha256:*) ;;
  *) echo "::error::refusing mutable image reference '$IMAGE_REF'; a registry digest is required" >&2; exit 2;;
esac

docker pull --quiet --platform "$PLATFORM" "$IMAGE_REF" > /dev/null

fail=0
check() {
  local what="$1" expected="$2" actual="$3"
  if [[ "$expected" != "$actual" ]]; then
    echo "::error::$IMAGE_REF: $what is '$actual', expected '$expected'" >&2
    fail=1
  else
    echo "ok: $what = $actual"
  fi
}

check "label org.opencontainers.image.revision" "$SOURCE_SHA" \
  "$(docker image inspect --format '{{index .Config.Labels "org.opencontainers.image.revision"}}' "$IMAGE_REF")"
check "label io.hardening-loop.image-target" "$TARGET" \
  "$(docker image inspect --format '{{index .Config.Labels "io.hardening-loop.image-target"}}' "$IMAGE_REF")"
check "label io.hardening-loop.platform" "$PLATFORM" \
  "$(docker image inspect --format '{{index .Config.Labels "io.hardening-loop.platform"}}' "$IMAGE_REF")"
check "os/arch" "$PLATFORM" \
  "$(docker image inspect --format '{{.Os}}/{{.Architecture}}' "$IMAGE_REF")"
check "repo digest present" "$IMAGE_REF" \
  "$(docker image inspect --format '{{join .RepoDigests "\n"}}' "$IMAGE_REF" | grep -x -- "$IMAGE_REF" || true)"

if [[ "$fail" -ne 0 ]]; then
  exit 1
fi
echo "verified $IMAGE_REF (target=$TARGET, revision=$SOURCE_SHA, platform=$PLATFORM, id=$(docker image inspect --format '{{.Id}}' "$IMAGE_REF"))"
