#!/usr/bin/env python3

import sys
import os
import json
import logging
import subprocess
import yaml
import time

logger = logging.getLogger('eval')
log_path = '/home/user/eval_shared/eval.log'

targets = {
    'FTMM': [
        '/home/user/FuzztructionMM/experiments/binary_config/7z-7z-enc.json',
        '/home/user/FuzztructionMM/experiments/binary_config/genrsa_rsa.json',
        '/home/user/FuzztructionMM/experiments/binary_config/gendsa_dsa.json',
        '/home/user/FuzztructionMM/experiments/binary_config/mp4encrypt_mp42aac.json',
        '/home/user/FuzztructionMM/experiments/binary_config/mp4mux_mp42aac.json',
        '/home/user/FuzztructionMM/experiments/binary_config/sign_vfychain.json'
    ],

    'Fuzztruction': [
        '/home/user/fuzztruction/fuzztruction-experiments/comparison-with-state-of-the-art/configurations/7zip-enc_7zip-dec/7z-7z-enc.yml',
        '/home/user/fuzztruction/fuzztruction-experiments/comparison-with-state-of-the-art/configurations/genrsa_rsa/genrsa-rsa.yml',
        '/home/user/fuzztruction/fuzztruction-experiments/comparison-with-state-of-the-art/configurations/gendsa_dsa/gendsa-dsa.yml',
        '/home/user/fuzztruction/fuzztruction-experiments/comparison-with-state-of-the-art/configurations/mp4encrypt_mp42aac/mp4encrypt_mp42aac.yml',
        '/home/user/fuzztruction/fuzztruction-experiments/comparison-with-state-of-the-art/configurations/mp4mux_mp42aac/mp4mux_mp42aac.yml',
        '/home/user/fuzztruction/fuzztruction-experiments/comparison-with-state-of-the-art/configurations/sign_vfychain/sign-vfychain.yml'
    ]
}

def tracer(path, config, out_suffix, workers):

    tracing_cmd = [
        '/usr/bin/sudo',
        '/home/user/fuzztruction/target/debug/fuzztruction',
        config,
        '--suffix', out_suffix,
        'tracer',
        '-j', workers,
        '-i', path
    ]
    logger.info(f'Tracing cmd: {" ".join(tracing_cmd)}')
    trace_process = subprocess.Popen(tracing_cmd)
    trace_process.communicate()

def main():
    args = sys.argv
    if len(args) != 4:
        print(f'[!] Usage: {args[0]} <runtime-in-seconds> <workers-number> <repetition>')
        exit(1)
    runtime = args[1]
    workers = args[2]
    repetition = int(args[3])

    os.chdir('/home/user/FuzztructionMM/fuzzer/')

    logging.basicConfig(filename=log_path, level=logging.INFO)
    for i in range(repetition):
    # for i in range(1):
        # for target in targets['FTMM']:
        for j in range(len(targets['FTMM'])):
            target = targets['FTMM'][j]
            with open(target, 'r') as rf:
                config = json.load(rf)
                config['afl++']['dir_out'] += f'-FTMM-{i}'
            tmp_config_path = '/tmp/' + target.split('/')[-1]
            with open(tmp_config_path, 'w') as wf:
                json.dump(config, wf, indent = 4)
            
            os.makedirs(config['afl++']['dir_out'], exist_ok=True)
            cmd = [
                # '/usr/bin/sudo',
                '/home/user/FuzztructionMM/fuzzer/fuzzer',
                '-n', workers,
                '-b', '2',
                '-t', '5',
                '-f', tmp_config_path,
                '-r', '4',
                '-T', runtime
            ]
            logger.info(f'FTMM cmd: {" ".join(cmd)}')
            process = subprocess.Popen(cmd)
            process.communicate()
            time.sleep(3)
            FTMM_results_dir = config['afl++']['dir_out'] + '/master/queue'
            os.system(f'/usr/bin/sudo chmod -R 777 {config["afl++"]["dir_out"]}')
            tracer(FTMM_results_dir, targets['Fuzztruction'][j], f'FTMM-{runtime}s-{i+1}', workers)
        
        
        for target in targets['Fuzztruction']:
            with open(target, 'r') as rf:
                ft_config = yaml.safe_load(rf)
            cmd = [
                '/usr/bin/sudo',
                '/home/user/fuzztruction/target/debug/fuzztruction',
                target,
                '--suffix', f'Fuzztruction-{i}',
                '--purge',
                'fuzz',
                '-j', workers,
                '-t', f'{runtime}s'
            ]
            logger.info(f'Fuzztruction cmd: {" ".join(cmd)}')
            process = subprocess.Popen(cmd)
            process.communicate()
            time.sleep(3)
            Fuzztruction_results_dir = ft_config['work-directory'] + f'-Fuzztruction-{i}' + '/interesting'
            tracer(Fuzztruction_results_dir, target, f'Fuzztruction-{runtime}s-{i+1}', workers)

    os.system('/usr/bin/sudo /home/user/fuzztruction/target/debug/coverage /home/user/eval_shared')
    print(f'All targets complete! Plot by plot.py!')


if __name__ == "__main__":
    main()