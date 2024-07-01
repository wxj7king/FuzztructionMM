#!/usr/bin/env bash

# from https://github.com/fuzztruction/fuzztruction-experiments/blob/main/comparison-with-state-of-the-art/binaries/openssl/config.sh
set -eu

function get_source {
    mkdir -p src
    pushd src > /dev/null
    git clone --branch=OpenSSL_1_1_1l https://github.com/openssl/openssl.git || true
    popd > /dev/null
}

function build_vanilla {
    mkdir -p vanilla
    rm -rf vanilla/*
    cp -r src/openssl vanilla/
    pushd vanilla/openssl > /dev/null
    ./config -d shared no-threads
    make -j 4 || true
    make
    popd > /dev/null
}

function build_afl {
    mkdir -p afl
    rm -rf afl/*
    cp -r src/openssl afl/

    pushd afl/openssl > /dev/null
    export AFL_LLVM_LAF_SPLIT_SWITCHES=1
    export AFL_LLVM_LAF_TRANSFORM_COMPARES=1
    export AFL_LLVM_LAF_SPLIT_COMPARES=1

    ./config -d shared no-threads
    sed -i 's/CC=$(CROSS_COMPILE)gcc.*/CC=afl-clang-fast/g' Makefile
    sed -i 's/CXX=$(CROSS_COMPILE)g++.*/CXX=afl-clang-fast++/g' Makefile
    sed -i 's/CFLAGS=.*/CFLAGS=-O3 -g -fPIC -DFUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION -DFT_STATIC_SEED/g' Makefile
    sed -i 's/CXXFLAGS=.*/CXXFLAGS=-O3 -g -fPIC -DFUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION -DFT_STATIC_SEED/g' Makefile
    bear make -j 4 || true
    make
    popd > /dev/null
}

get_source
build_vanilla
build_afl