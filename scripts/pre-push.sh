#!/bin/bash

## hook to check version match tag before push
## usage: ln -s ../../scripts/pre-push.sh .git/hooks/pre-push

VERSIONFILE="gitversion.h"
BRANCH="HEAD"

tagref=$(grep -Po 'refs/tags/([^ ]*) ' </dev/stdin | head -n1 | cut -c11- | tr -d '[:space:]')

if [[ "$tagref" == ""  ]]; then
    ## pushing without --tags , exit normally
    exit 0
fi

## versionline may looks like '#define GITVERSION "0.0.8"'
versionline=$(git cat-file blob $BRANCH:"$VERSIONFILE" | grep 'GITVERSION')
ver=$(echo "$versionline" | sed 's/^[^"]*"//;s/"[^"]*$//')

if [[ "$tagref" == "$ver" ]]; then
    ## tag matches ver
    exit 0
fi
echo "Tag name don't match version file. Preventing push."
echo "tag name: $tagref"
echo "version: $ver"
exit 1
