#!/usr/bin/env bash

# https://github.com/fuzztruction/fuzztruction/blob/main/env/stop.sh
set -eu
set -o pipefail

container_name="ftmm-exp"
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
