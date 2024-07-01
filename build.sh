#!/usr/bin/env bash

# set -eu
# set -o pipefail

text_red=$(tput setaf 1)
text_green=$(tput setaf 2)
text_bold=$(tput bold)
text_reset=$(tput sgr0)

function print_info {
    echo "${text_bold}${text_green}${1}${text_reset}"
}

pwd=$PWD

# Download Pintool
print_info "[+] Downloading Pintool..."
if [ ! -d "./pin-3.28-98749-g6643ecee5-gcc-linux" ]; then
    wget -nc https://software.intel.com/sites/landingpage/pintool/downloads/pin-3.28-98749-g6643ecee5-gcc-linux.tar.gz \
    && tar -xf ./pin-3.28-98749-g6643ecee5-gcc-linux.tar.gz && rm ./pin-3.28-98749-g6643ecee5-gcc-linux.tar.gz
fi

# Download AFL++
print_info "[+] Downloading and building AFL++..."
git clone https://github.com/AFLplusplus/AFLplusplus -b v4.08c
pushd AFLplusplus && make all && sudo make install && popd

# Build the fuzzer
print_info "[+] Building the fuzzer..."
pushd ./fuzzer
make -j
popd

# Build pintools
print_info "[+] Building pintools..."
pin_root="${pwd}/pin-3.28-98749-g6643ecee5-gcc-linux"
pushd ./pintool
chmod +x make.sh && pin_root=$pin_root ./make.sh
popd

# Build AFL++ custom mutator
print_info "[+] Building custom mutator of AFL++..."
aflpp_include="-I${pwd}/AFLplusplus/include"
pushd ./afl_custom_mutator
AFLPP_INCLUDE=$aflpp_include make
popd

# Generate config file for dependencies
print_info "[+] Generating config file for dependencies above..."
dep_config="{ \"deps\" : { "
dep_config+="\"aflpp\" : \"${pwd}/AFLplusplus\", "
dep_config+="\"pinbin\" : \"${pwd}/pin-3.28-98749-g6643ecee5-gcc-linux/pin\", "
dep_config+="\"pintool\" : \"${pwd}/pintool\", "
dep_config+="\"aflpp_custom\" : \"${pwd}/afl_custom_mutator\" "
dep_config+="}}"
echo $dep_config > ./dep_config.json && mv ./dep_config.json ./fuzzer

print_info "[+] All works have completed, you can start fuzzing by binary ./fuzzer/fuzzer!"
