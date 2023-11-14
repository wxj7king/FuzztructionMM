#/bin/bash

if [ -z $1 ] || [ -z $2 ] || [ -z $3 ]
then
	/home/proj/proj/tools/pin-3.28-98749-g6643ecee5-gcc-linux/pin -t obj-intel64/probe_tool.so -- /home/proj/proj/openssl/apps/openssl genrsa -aes128 -passout pass:xxxxx -out rsak 512
else
	/home/proj/proj/tools/pin-3.28-98749-g6643ecee5-gcc-linux/pin -t obj-intel64/probe_tool.so -nid $1 -bits $2 -primes $3 -- /home/proj/proj/openssl/apps/openssl genrsa -aes128 -passout pass:xxxxx -out rsak 512
fi
