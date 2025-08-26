#!/bin/bash
set -euo pipefail

# Build & extract per-arch binaries locally — NO PUSH
# Requires: docker buildx with qemu-user-static already installed (system-wide)

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

# Ensure builder exists
docker buildx create --name localbuilder --use 2>/dev/null || docker buildx use localbuilder
docker buildx inspect --bootstrap

# Iterate architectures, build & extract binaries
for PLATFORM in "${PLATFORMS[@]}"; do
    short=$(echo "$PLATFORM" | sed 's|linux/||; s|/|-|g')
    echo "=== Building & extracting binary for $PLATFORM ($short) ==="

    docker buildx build \
        --platform "$PLATFORM" \
        -t "$DOCKER_ID:$short" \
        --load \
        "$SRCDIR"

    docker run --rm "$DOCKER_ID:$short" cat /usr/bin/tuntox > "tuntox-$PRINTABLE_VERSION-$short"
    chmod +x "tuntox-$PRINTABLE_VERSION-$short"
done

echo
echo "✅ All binaries built locally:"
ls -1 tuntox-"$PRINTABLE_VERSION"-*
