#/bin/bash

#export PIN_ROOT=/home/user/pin-3.28-98749-g6643ecee5-gcc-linux/
export PIN_ROOT=$pin_root

if [ "$#" -eq 0 ]; then
    make
elif [ "$#" -eq 1 ]; then
    make $1
else
    exit 1
fi