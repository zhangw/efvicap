#!/usr/bin/env bash
set -euo pipefail

REMOTE="${REMOTE:-numa_dev}"
REMOTE_DIR="${REMOTE_DIR:-~/workspace/efvicap}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"

ssh "${REMOTE}" "mkdir -p ${REMOTE_DIR}"
rsync -az --delete \
  --exclude build \
  --exclude .git \
  "${PROJECT_DIR}/" "${REMOTE}:${REMOTE_DIR}/"

ssh "${REMOTE}" "cd ${REMOTE_DIR} && mkdir -p build && cd build && \
  cmake -DCMAKE_BUILD_TYPE=Release .. && make -j\$(nproc)"

echo "Build complete: ${REMOTE}:${REMOTE_DIR}/build/efvicap"
