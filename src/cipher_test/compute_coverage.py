#!/bin/bash
import os
import subprocess

#test_case_dir = "/home/proj/proj/src/fuzzer/keys/"
test_case_dir = "/home/proj/proj/test/interesting_out/output_april_2/default/queue/"
#test_case_dir = "/home/proj/proj/src/cipher_test/rsa_keys/"
drcov_bin_path = "/home/proj/proj/tools/DynamoRIO-Linux-9.93.19580/bin64/drrun"
drcov_log_dir = "/tmp/drcov/"
target_path = "/home/proj/proj/uninstrumented/openssl/apps/openssl"
target_lib_dir = "/home/proj/proj/uninstrumented/openssl/"
new_env = {'LD_LIBRARY_PATH': "/home/proj/proj/uninstrumented/openssl/"}
mkdir_cmd = "mkdir -p "
clean_cmd = "rm -rf "
drcov_cmd = [
    drcov_bin_path,
    '-persist',
    '-t',
    'drcov',
    '-logdir',
    drcov_log_dir,
    '-dump_text',
    '--'
]

test_case_paths = []
drcov_log_paths = []
unique_bbs = set()

def parse_log(drcov_log_path):
    print(f"\033[92m[parse log]\033[00m processing: {drcov_log_path}")
    with open(drcov_log_path, 'r') as rf:
        read_lines = rf.readlines()
    
    target_lib_path1 = target_lib_dir + "libcrypto.so.1.1"
    target_lib_path2 = target_lib_dir + "libssl.so.1.1"
    # module id to preferred base addr
    effective_module = {}
    for line in read_lines:
        if target_path in line or target_lib_path1 in line or target_lib_path2 in line:
            d_key = line.split(',')[0].replace(' ', '')
            d_value = line.split(',')[6]
            effective_module[d_key] = d_value
            
        if 'module[' in line:
            module_id = line.split(':')[0].replace('module[', '').replace(']', '').replace(' ', '')
            if module_id in effective_module.keys():
                bb = effective_module[module_id] + ',' + line.split(':')[1].replace(' ', '')
                unique_bbs.add(bb)
                #unique_bbs.add(line)
    
    print(f"\033[92m[parse log]\033[00m finished :): {drcov_log_path}, current number of bbs: {len(unique_bbs)}")
        

    
def run_drcov(test_case_path):
    print(f"\033[92m[run drcov]\033[00m processing: {test_case_path}")
    openssl_cmd = [
        target_path,
        'rsa',
        '-check',
        '-in',
        test_case_path,
        '-passin',
        'pass:xxxxx'
    ]
    cmd = drcov_cmd + openssl_cmd
    print(cmd, end="\n")
    result = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=new_env)
    out, err = result.communicate()
    rc = result.returncode
    out = out.decode("utf-8")
    err = err.decode("utf-8")
    #if "RSA key ok" not in (out + err) or rc != 0:
    if rc != 0:
        print(f"drcov error: {out + err}")
        return -1
    else:
        return 0

    print(f"\033[92m[run drcov]\033[00m finished: {test_case_path}")

def main():
    # clean process
    ret = os.system(clean_cmd + drcov_log_dir)
    if (ret != 0):
        print("rm error!")
        exit(-1)

    # make drcov log
    ret = os.system(mkdir_cmd + drcov_log_dir)
    if (ret != 0):
        print("mkdir error!")
        exit(-1)
    
    # https://stackoverflow.com/questions/10377998/how-can-i-iterate-over-files-in-a-given-directory
    # iterate test cases dir
    directory = os.fsencode(test_case_dir)
    for file in os.listdir(directory):
        filename = os.fsdecode(file)
        #if "+cov" not in filename:
        #    continue
        test_case_path = test_case_dir + filename
        test_case_paths.append(test_case_path)
        run_drcov(test_case_path)
    #print(test_case_paths)

    directory = os.fsencode(drcov_log_dir)
    for file in os.listdir(directory):
        filename = os.fsdecode(file)
        drcov_log_path = drcov_log_dir + filename
        drcov_log_paths.append(drcov_log_path)
        parse_log(drcov_log_path)
        #break

    # clean process
    ret = os.system(clean_cmd + drcov_log_dir)
    if (ret != 0):
        print("rm error!")
        exit(-1)

    print(f"\033[91m[result]\033[00m the final number of bbs: {len(unique_bbs)}")

if __name__ == "__main__":
    main()
