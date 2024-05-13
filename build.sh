#!/bin/bash

text_red=$(tput setaf 1)    # Red
text_green=$(tput setaf 2)  # Green
text_bold=$(tput bold)      # Bold
text_reset=$(tput sgr0)     # Reset your text

function print_info {
    echo "${text_bold}${text_green}${1}${text_reset}"
}

# Download Pintool
print_info "[+] Downloading Pintool..."
wget -nc https://software.intel.com/sites/landingpage/pintool/downloads/pin-3.28-98749-g6643ecee5-gcc-linux.tar.gz \
&& tar -xf ./pin-3.28-98749-g6643ecee5-gcc-linux.tar.gz && rm ./pin-3.28-98749-g6643ecee5-gcc-linux.tar.gz

# Download AFL++
print_info "[+] Downloading and building AFL++..."
git clone https://github.com/AFLplusplus/AFLplusplus -b v4.08c && pushd AFLplusplus && make all && popd

# Build the fuzzer
print_info "[+] Building the fuzzer..."
pushd ./fuzzer
make -j
popd

# Build pintools
print_info "[+] Building pintools..."
pushd ./pintool
chmod +x make.sh && ./make.sh
popd

# Build AFL++ custom mutator
print_info "[+] Building custom mutator of AFL++..."
pushd ./afl_custom_mutator
make
popd

# Generate config file for dependencies
print_info "[+] Generating config file for dependencies above..."
pwd=$PWD
dep_config="{ \"deps\" : { "
dep_config+="\"aflpp\" : \"${pwd}/AFLplusplus\", "
dep_config+="\"pinbin\" : \"${pwd}/pin-3.28-98749-g6643ecee5-gcc-linux/pin\", "
dep_config+="\"pintool\" : \"${pwd}/pintool\", "
dep_config+="\"aflpp_custom\" : \"${pwd}/afl_custom_mutator\" "
dep_config+="}}"
echo $dep_config > ./dep_config.json && mv ./dep_config.json ./fuzzer

print_info "[+] All works have completed, you can start fuzzing by binary ./fuzzer/fuzzer!"
