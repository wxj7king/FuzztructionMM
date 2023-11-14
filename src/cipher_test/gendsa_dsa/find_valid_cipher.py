#!/bin/bash
import subprocess
import sys
import os

keys_dir = "./dsa_keys/"
mkdir_cmd = "mkdir -p "
clean_cmd = "rm -rf "
p_values = ['0', '1']

if (len(sys.argv) != 2):
    print("usage: script.py [generate key? 1/0]")
    exit(-1)

if sys.argv[1] not in p_values:
    print("usage: script.py [generate key? 1/0]")
    exit(-1)

if sys.argv[1] == '1':
    ret = os.system(clean_cmd + keys_dir)
    if (ret != 0):
        print("rm error!")
        exit(-1)
        
    ret = os.system(mkdir_cmd + keys_dir)
    if (ret != 0):
        print("mkdir error!")
        exit(-1)


with open('./enc.conf', 'r') as rf:
    readall = rf.read()

ciphers = readall.split('\n')
print("all ciphers: \n")
print(ciphers)
valid_ciphers = []
i = 0
for cipher in ciphers:
    i += 1
    cmd = "/home/proj/proj/openssl/apps/openssl gendsa " + cipher + " -passout pass:xxxxx -out dsa_key /home/proj/proj/src/cipher_test/gendsa_dsa/dsaparam"
    result = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    out, err = result.communicate()
    out = out.decode("utf-8")
    err = err.decode("utf-8")
    #print("{}:\n".format(i))
    #print(out)
    #print(err)
    outall = (out + err)
    if "error" not in outall and "Unrecognized flag" not in outall:
        valid_ciphers.append(cipher)
        if sys.argv[1] == '1':
            cp_cmd = "cp dsa_key " + keys_dir + cipher.replace('-', '_')
            ret = os.system(cp_cmd)
            if (ret != 0):
                print("cp error!")
                exit(-1)

print("valid ciphers: \n")
print(valid_ciphers)

with open("./enc_valid.conf", "w") as wf:
    write_content = '\n'.join(valid_ciphers)
    wf.write(write_content)

