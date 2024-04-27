import os

cmd = "LD_LIBRARY_PATH=/home/proj/proj/uninstrumented/openssl/ /home/proj/proj/tools/pin-3.28-98749-g6643ecee5-gcc-linux/pin -t /home/proj/proj/src/pintool/mutate_ins_one/obj-intel64/mutate_ins.so -addr 0x10ede1 -iter 41 -iter2mut 39 -mut 4 -off 0 -u8 @ -baddr 0x1c12f5 -- /home/proj/proj/uninstrumented/openssl/apps/openssl genrsa -aes128 -passout pass:xxxxx -out /tmp/rsak# 512"

for i in range(256):
    new_cmd = cmd.replace('@', str(i)).replace('#', str(i))
    print(new_cmd, end="\n")
    os.system(new_cmd)
