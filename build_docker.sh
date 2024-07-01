#!/usr/bin/env bash

# https://github.com/fuzztruction/fuzztruction/blob/main/env/build.sh
set -eu
set -o pipefail

text_red=$(tput setaf 1)
text_green=$(tput setaf 2)
text_bold=$(tput bold)
text_reset=$(tput sgr0)

function log_error {
    echo "${text_bold}${text_red}${1}${text_reset}"
}

function log_success {
    echo "${text_bold}${text_green}${1}${text_reset}"
}

log_success "[+] Building docker image"
docker build --build-arg USER_UID="$(id -u)" --build-arg USER_GID="$(id -g)" --target dev -t "ftmm:latest" .
if [[ $? -ne 0 ]]; then
    log_error "[+] Error while building the docker image."
    exit 1
else
    log_success "[+] Docker image successfully build."
fi

exit 0
