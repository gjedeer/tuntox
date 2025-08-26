#!/bin/bash
set -euo pipefail

# Needs: docker buildx (comes with Docker CE >=19.03)

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

# Create a new builder with qemu support if not exists
docker buildx create --name multibuilder --use 2>/dev/null || docker buildx use multibuilder
docker buildx inspect --bootstrap

for PLATFORM in "${PLATFORMS[@]}"; do
    short=$(echo "$PLATFORM" | sed 's|linux/||; s|/|-|g')
    echo "=== Building for $PLATFORM ($short) ==="
    
    # Build (not pushing, but you could add --push to publish a multi-arch image)
    docker buildx build \
        --platform $PLATFORM \
        -t $DOCKER_ID:$short \
        --load \
        "$SRCDIR"
    
    # Extract the binary
    docker run --rm $DOCKER_ID:$short cat /usr/bin/tuntox > "tuntox-$PRINTABLE_VERSION-$short"
done
