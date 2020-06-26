#!/bin/bash

# Bash "strict mode"
set -euo pipefail

function link {
    if [ ! -L $1 ]; then
        ln -s $2 $1
    fi
}

R3S_DIR=$(dirname $(realpath -s $0))
BUILD_DIR=`pwd`

BUILD_TYPES_DIR="$BUILD_DIR/builds"
DEBUG_BUILD="$BUILD_TYPES_DIR/debug"
RELEASE_BUILD="$BUILD_TYPES_DIR/release"

R3S_LIBS_DIR="$BUILD_DIR/libs"
R3S_INCLUDE_DIR="$BUILD_DIR/include"
R3S_EXAMPLES_DIR="$BUILD_DIR/examples"

if [[ -z "${Z3_DIR}" ]]; then
    echo "This project is dependent on the Z3 project."
    echo "Please set the environmental variable \"Z3_DIR\" with the path to that project."
    echo "Another alternative is to let this script grab the necessary dependencies."
    echo "If you want to let it grab its dependencies, run this script with the flag \"--grab-deps\"."
    
    exit 1
fi

# Build debug

mkdir -p $DEBUG_BUILD
cd $DEBUG_BUILD
CMAKE_PREFIX_PATH="$Z3_DIR/build" CMAKE_INCLUDE_PATH="$Z3_DIR/build/include/" cmake -DCMAKE_BUILD_TYPE=Debug -DBUILD_EXAMPLES=ON $R3S_DIR
make

# Build release

mkdir -p $RELEASE_BUILD
cd $RELEASE_BUILD
CMAKE_PREFIX_PATH="$Z3_DIR/build" CMAKE_INCLUDE_PATH="$Z3_DIR/build/include/" cmake -DCMAKE_BUILD_TYPE=Release $R3S_DIR
make

# Symlink results

mkdir -p $R3S_LIBS_DIR
link $R3S_LIBS_DIR/libr3sd.so $DEBUG_BUILD/lib/libr3sd.so
link $R3S_LIBS_DIR/libr3s.so $RELEASE_BUILD/lib/libr3s.so

mkdir -p $R3S_INCLUDE_DIR
link $R3S_INCLUDE_DIR/r3s.h $R3S_DIR/include/r3s.h

link $R3S_EXAMPLES_DIR $DEBUG_BUILD/bin/
