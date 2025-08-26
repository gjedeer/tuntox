#!/bin/bash
set -euo pipefail

# Push a multi-arch manifest image set to Docker Hub
# Requires: `docker login` already done
# Does not build/extract local binaries (use build-multiarch.sh for that)

SRCDIR="$(pwd)"
GIT_HASH=$(git rev-parse --short HEAD)
GIT_TAG=$(git tag --contains "$GIT_HASH" || true)
PRINTABLE_VERSION=${GIT_TAG:-$GIT_HASH}

DOCKER_ID="gdr1/tuntox"

PLATFORMS=(
  linux/arm/v6
  linux/arm/v7
  linux/arm64
  linux/amd64
  linux/ppc64le
  linux/s390x
  linux/riscv64
  linux/386
)

docker buildx create --name pushbuilder --use 2>/dev/null || docker buildx use pushbuilder
docker buildx inspect --bootstrap

# Build + push all at once with manifest
docker buildx build \
  --platform "$(IFS=,; echo "${PLATFORMS[*]}")" \
  -t "$DOCKER_ID:latest" \
  -t "$DOCKER_ID:$PRINTABLE_VERSION" \
  --push \
  "$SRCDIR"

echo
echo "Multi-arch image pushed:"
echo "   $DOCKER_ID:latest"
echo "   $DOCKER_ID:$PRINTABLE_VERSION"
