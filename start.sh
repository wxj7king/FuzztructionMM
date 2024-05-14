#!/usr/bin/env bash

set -eu
set -o pipefail

text_red=$(tput setaf 1)    # Red
text_green=$(tput setaf 2)  # Green
text_bold=$(tput bold)      # Bold
text_reset=$(tput sgr0)     # Reset your text

function log_success {
    echo "${text_bold}${text_green}${1}${text_reset}"
}

container_name="ftmm"
image_name="${container_name}:latest"
container="$(docker ps --filter="name=$container_name" --latest --quiet)"
if [[ -n "$container" ]]; then
    # Connec to already running container
    log_success "[+] Found running instance: $container, connecting..."
    cmd="docker start $container"
    log_success "[+] $cmd"
    $cmd > /dev/null
    # if [[ -v NO_TTY ]]; then
    #     HAS_TTY=""
    # else
    #     HAS_TTY="-t"
    # fi
    # cmd="docker exec -i $HAS_TTY --workdir /home/user/fuzztruction $container zsh"
    cmd="docker exec -it $container zsh"
    log_success "[+] $cmd"
    $cmd
    exit 0
fi

log_success "[+] Creating new container..."

mounts=""
# mounts+=" -v $PWD:/home/user/shared "

cmd="docker run -ti -d --privileged
    $mounts
    --ulimit msgqueue=2097152000
    --shm-size=16G
    --net=host
    --name $container_name "

# if [[ ! -z "$SSH_AUTH_SOCK"  ]]; then
#     log_success "[+] Forwarding ssh agent ($SSH_AUTH_SOCK -> /ssh-agent)"
#     cmd+="-v $(readlink -f "$SSH_AUTH_SOCK"):/ssh-agent --env SSH_AUTH_SOCK=/ssh-agent"
# fi

cmd+=" ${image_name}"
log_success "[+] $(echo $cmd | xargs)"
$cmd > /dev/null

log_success "[+] Rerun $0 to connect to the new container."
