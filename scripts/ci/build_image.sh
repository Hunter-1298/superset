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
# Build ONE Dockerfile target for linux/amd64 and push it as a single-platform
# image (no provenance/SBOM attestation index, so the pushed digest is the plain
# image manifest every scanner and runtime job can address directly).
#
#   scripts/ci/build_image.sh <target: lean|ci> <tag> <cache-image> <metadata.json>
#
# Emits `digest=sha256:...` to $GITHUB_OUTPUT (when set) and prints it.
set -euo pipefail

TARGET="${1:?target (lean|ci)}"
TAG="${2:?image tag to push}"
CACHE_IMAGE="${3:?image repository used for the registry build cache}"
METADATA="${4:?metadata file}"
PLATFORM="${PLATFORM:-linux/amd64}"
SOURCE_SHA="${SOURCE_SHA:-$(git rev-parse HEAD)}"
SOURCE_URL="${SOURCE_URL:-${GITHUB_SERVER_URL:-https://github.com}/${GITHUB_REPOSITORY:-Hunter-1298/superset}}"

case "$TARGET" in lean|ci) ;; *) echo "target must be lean or ci, got $TARGET" >&2; exit 2;; esac

docker buildx build \
  --platform "$PLATFORM" \
  --target "$TARGET" \
  --push \
  --provenance=false \
  --sbom=false \
  --build-arg BUILD_TRANSLATIONS=false \
  --label "org.opencontainers.image.revision=${SOURCE_SHA}" \
  --label "org.opencontainers.image.source=${SOURCE_URL}" \
  --label "io.hardening-loop.image-target=${TARGET}" \
  --label "io.hardening-loop.platform=${PLATFORM}" \
  --cache-from "type=registry,ref=${CACHE_IMAGE}:buildcache-${TARGET}" \
  --cache-to "type=registry,ref=${CACHE_IMAGE}:buildcache-${TARGET},mode=max,ignore-error=true" \
  --metadata-file "$METADATA" \
  -t "$TAG" \
  .

DIGEST="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["containerimage.digest"])' "$METADATA")"
case "$DIGEST" in sha256:*) ;; *) echo "unexpected digest $DIGEST in $METADATA" >&2; exit 1;; esac
echo "pushed ${TAG} -> ${DIGEST}"
if [[ -n "${GITHUB_OUTPUT:-}" ]]; then
  echo "digest=${DIGEST}" >> "$GITHUB_OUTPUT"
fi
