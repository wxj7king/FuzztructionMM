#!/usr/bin/env bash

# https://github.com/fuzztruction/fuzztruction/blob/main/env/start.sh
set -eu
set -o pipefail

text_red=$(tput setaf 1)
text_green=$(tput setaf 2)
text_bold=$(tput bold)
text_reset=$(tput sgr0)

function log_success {
    echo "${text_bold}${text_green}${1}${text_reset}"
}

container_name="ftmm-exp"
image_name="karakul7/ft-env-prebuilt:fix_1.1"
container="$(docker ps --filter="name=$container_name" --latest --quiet)"
if [[ -n "$container" ]]; then
    # Connec to already running container
    log_success "[+] Found running instance: $container, connecting..."
    cmd="docker start $container"
    log_success "[+] $cmd"
    $cmd > /dev/null
    # cmd="docker exec -i $HAS_TTY --workdir /home/user/fuzztruction $container zsh"
    cmd="docker exec -it --workdir /home/user/eval $container zsh"
    log_success "[+] $cmd"
    $cmd
    exit 0
fi

log_success "[+] Creating new container..."

mkdir ./eval_shared
mounts=""
mounts+=" -v $PWD/eval_shared:/home/user/eval_shared "

cmd="docker run -ti -d --privileged
    --mount type=tmpfs,destination=/tmp,tmpfs-mode=777
    $mounts
    --ulimit msgqueue=2097152000
    --shm-size=16G
    --net=host
    --name $container_name "

cmd+=" ${image_name}"
log_success "[+] $(echo $cmd | xargs)"
$cmd > /dev/null

log_success "[+] Rerun $0 to connect to the new container."
