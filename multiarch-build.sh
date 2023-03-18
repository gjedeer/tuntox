#!/bin/bash

# Needs https://github.com/tonistiigi/binfmt to work

SRCDIR="`pwd`"
BUILDDIR="$SRCDIR/multiarch-build"
SRC_DOCKERFILE="$SRCDIR/Dockerfile"

GIT_HASH=`git rev-parse --short HEAD`
GIT_TAG=`git tag --contains $GIT_HASH`
if [[ -z "$GIT_TAG" ]]; then
	PRINTABLE_VERSION=$GIT_HASH
else
	PRINTABLE_VERSION=$GIT_TAG
fi

DOCKER_ID="gdr1/tuntox"

if [ ! -d "$BUILDDIR" ]; then mkdir -p "$BUILDDIR"; fi

cp -R "$SRCDIR/scripts" "$BUILDDIR/"

for PLATFORM in arm32v6 arm32v7 arm64v8 amd64 arm32v5 ppc64le s390x mips64le riscv64 i386; do
	cd "$BUILDDIR"
	echo $PLATFORM;
	sed -e "s#alpine#$PLATFORM/alpine#g" <"$SRC_DOCKERFILE" >Dockerfile
	docker build -t $DOCKER_ID:$PLATFORM .
	docker run --rm -it $DOCKER_ID:$PLATFORM cat /usr/bin/tuntox >tuntox-$PRINTABLE_VERSION-linux-$PLATFORM
done
