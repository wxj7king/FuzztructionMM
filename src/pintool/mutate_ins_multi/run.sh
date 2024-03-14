#/bin/bash

/home/proj/proj/tools/pin-3.28-98749-g6643ecee5-gcc-linux/pin -t obj-intel64/mutate_ins.so -- /home/proj/proj/openssl/apps/openssl genrsa -aes128 -passout pass:xxxxx -out rsak 512 > output
