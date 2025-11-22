#!/bin/sh
echo "clean up captured data in $1, keep $2 newest entries"
set -eu


ls -1t "$1" | grep bin | tail -n +$2 | xargs -r rm --

