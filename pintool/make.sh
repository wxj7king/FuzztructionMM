#/bin/bash

export PIN_ROOT=/home/proj/proj/tools/pin-3.28-98749-g6643ecee5-gcc-linux/

if [ "$#" -eq 0 ]; then
    make
elif [ "$#" -eq 1 ]; then
    make $1
else
    exit 1
fi
