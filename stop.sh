#!/usr/bin/env bash

set -eu
set -o pipefail

container_name="ftmm"
container="$(docker ps --filter="name=$container_name" --latest --quiet)"
if [[ -n "$container" ]]; then
    echo "Found running instance $container, stopping..."
    cmd="docker stop -t 5 $container"
    echo "$cmd"
    $cmd
    cmd="docker rm -f $container"
    echo "$cmd"
    $cmd
else
    echo "No running instance found..."
fi

exit 0
