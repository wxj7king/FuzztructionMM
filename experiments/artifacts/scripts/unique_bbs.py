#!/usr/bin/env python3

import sys
import json
from pathlib import Path
from os import listdir
import matplotlib.pyplot as plt
import numpy as np

num_runs = 5
targets = [
    "genrsa_rsa",
    "gendsa_dsa",
    "sign_vfychain",
    #"7zip_7zip",
    "7zip-enc_7zip-dec",
    "mp4mux_mp42aac",
    "mp4encrypt_mp42aac"
]

targets_to_xlabels = {
    "genrsa_rsa"              : "rsa",
    "gendsa_dsa"              : "dsa",
    "sign_vfychain"           : "vfychain",
    #"7zip_7zip"               : "7zip",
    "7zip-enc_7zip-dec"       : "7zip-dec",
    "mp4mux_mp42aac"          : "mp42aac",
    "mp4encrypt_mp42aac"      : "mp42aac-dec",
}

fuzzers = ["Fuzztruction", "FTMM"]
target2bbs = {}
target2unibbs = {}
bbs2info = {}
ftmm_target2unibbs_testcases = {}
ftmm_target2unibbs_class = {}
# def load_coverage_test():
#     path = "/home/wxj/thesis/evaluation_results/all_traces/genrsa_rsa-Fuzztruction-86400s-1/coverage.csv"
#     with open(path, "r", encoding="utf8") as f:
#         content = [l.strip() for l in f.readlines() if l.strip()]
#     total_bbs = 0
#     # skip column header
#     content = content[1:]
#     for l in content:
#         lhs, rhs = l.split(";", 1)
#         discovery_ts = int(lhs.strip())
#         num_new_unique_bbs = int(rhs.strip())
#         total_bbs += num_new_unique_bbs
        
#     print(f'bbs found: {total_bbs}')

def load_bbs(all_bbs, covered_bbs_path, fuzzer, target):
    with open(covered_bbs_path, 'r') as rf:
        bbs= json.load(rf)
        for bb in bbs:
            bb_str = f'{bb["module_name"]}@{str(hex(bb["offset"]))}'
            all_bbs.add(bb_str)
            if fuzzer == "FTMM":
                if bb_str not in bbs2info[target]:
                    bbs2info[target][bb_str] = []
                # bbs2info[target][bb_str].append([bb["found_ts_ms"], str(covered_bbs_path.parent.absolute())])
                bbs2info[target][bb_str].append([bb["found_ts_ms"], covered_bbs_path.parent.absolute()])


def load_data(traces_dir : Path, runtime : int, target : str):
    for fuzzer in fuzzers:
        all_bbs = set()
        for i in range(1, num_runs + 1):
            trace_dir = traces_dir / f'{target}-{fuzzer}-{runtime}s-{i}'
            if not trace_dir.exists():
                print(f"[!] Failed to find run directory {trace_dir.as_posix()}")
                continue
            covered_bbs_path = trace_dir / "covered_bbs.json"
            if not covered_bbs_path.exists():
                print(f"[!] directory {trace_dir.as_posix()} dose not contain covered_bbs.json")
                continue
            load_bbs(all_bbs, covered_bbs_path, fuzzer, target)
        target2bbs[target][fuzzer] = all_bbs

def compute_unique_bbs(target):
    fuzzer2bbs = target2bbs[target]
    for fuzzer in fuzzer2bbs:
        unique_bbs = set()
        if not fuzzer2bbs[fuzzer]:
            continue
        for fuzzer_r in fuzzers:
            if fuzzer == fuzzer_r or not fuzzer2bbs[fuzzer_r]:
                continue
            ret = fuzzer2bbs[fuzzer] - fuzzer2bbs[fuzzer_r]
            unique_bbs |= ret
        target2unibbs[target][fuzzer] = sorted(unique_bbs)

def statistic_bbs_unlock_mutation_ftmm(target : str):

    unique_bbs = target2unibbs[target]["FTMM"]
    
    for bb in unique_bbs:
        addr_dec = int(bb.split("@")[1], base=16)
        covered_tests = bbs2info[target][bb]
        if bb not in ftmm_target2unibbs_testcases[target]:
            ftmm_target2unibbs_testcases[target][bb] = []
        for found_ts_ms, covered_bbs_path in covered_tests:
            covered_bbs_path_traces = covered_bbs_path / "traces"
            for trace_file in listdir(covered_bbs_path_traces):
                if f'time:{found_ts_ms}' in trace_file:
                    ftmm_target2unibbs_testcases[target][bb].append(str(trace_file))
                    break
        
        # classify the bb
        data_mut = False
        branch_flip = False
        for test_case in ftmm_target2unibbs_testcases[target][bb]:
            if "branch" in test_case:
                branch_flip = True
            else:
                data_mut = True
        if data_mut and branch_flip:
            ftmm_target2unibbs_class[target]["hybrid"] += 1
        elif data_mut and not branch_flip:
            ftmm_target2unibbs_class[target]["data_mutation"] += 1
        elif not data_mut and branch_flip:
            ftmm_target2unibbs_class[target]["branch_flip"] += 1


def plot():
    fuzzer2unibbs = {}
    params = {
        "text.usetex" : True,
        "mathtext.fontset" : "cm",
        "font.family" : "monospace",
    }
    plt.rcParams.update(params)
    plt.figure(figsize=(6.4, 5.5))
    
    for target in target2unibbs:
        print(f'{target}: ')
        for fuzzer in target2unibbs[target]:
            if fuzzer not in fuzzer2unibbs:
                fuzzer2unibbs[fuzzer] = []
            print(f'{fuzzer}: {len(target2unibbs[target][fuzzer])}')
            fuzzer2unibbs[fuzzer].append(len(target2unibbs[target][fuzzer]))
    print(fuzzer2unibbs)
    # labels = list(target2unibbs.keys())
    labels = [targets_to_xlabels[key] for key in target2unibbs.keys()]
    x_axis = np.arange(len(labels))
    pos_fuzzer = 0
    
    for fuzzer in reversed(fuzzer2unibbs):
        if fuzzer == "FTMM":
            hybrid_values = [] 
            branch_values = []
            data_values = []
            for target in ftmm_target2unibbs_class:
                hybrid_values.append(ftmm_target2unibbs_class[target]["hybrid"])
                data_values.append(ftmm_target2unibbs_class[target]["data_mutation"])
                branch_values.append(ftmm_target2unibbs_class[target]["branch_flip"])
            hybrid_values = np.array(hybrid_values)
            data_values = np.array(data_values)
            branch_values = np.array(branch_values)
            plt.bar(x_axis + pos_fuzzer * 0.15, hybrid_values, 0.15, label = f'{fuzzer}-hybrid', log = True)
            plt.bar(x_axis + pos_fuzzer * 0.15, data_values, 0.15, label = f'{fuzzer}-data_mutation', log = True, bottom=hybrid_values)
            plt.bar(x_axis + pos_fuzzer * 0.15, branch_values, 0.15, label = f'{fuzzer}-branch_flip', log = True, bottom=hybrid_values + data_values)

        else:
            plt.bar(x_axis + pos_fuzzer * 0.15, fuzzer2unibbs[fuzzer], 0.15, label = fuzzer, log = True)
        for i in range(len(x_axis)):
            plt.text(i + pos_fuzzer * 0.15, fuzzer2unibbs[fuzzer][i], fuzzer2unibbs[fuzzer][i], ha='center')
        pos_fuzzer += 1
    plt.xticks(x_axis, labels, rotation=45)
    plt.ylabel('\#Unique Basic Blocks', fontsize="large")
    plt.subplots_adjust(bottom = 0.23)
    plt.legend(ncol=2, bbox_to_anchor=(1.02,1.03), loc='upper right', shadow=True, fancybox=True)
    
    name = "./unique_bbs.pdf"
    print(f"Figure is writing to file {name}")
    
    plt.savefig(name)


def main():
    args = sys.argv
    if (len(args) != 3):
        print(f'[!] Usage: {args[0]} <runtime-in-seconds> <directory-containing-all-runs>')
        exit(1)
    runtime = int(args[1])
    traces_dir = Path(args[2])

    for target in sorted(targets):
        print(f'processing {target}')
        target2bbs[target] = {}
        target2unibbs[target] = {}
        bbs2info[target] = {}
        ftmm_target2unibbs_testcases[target] = {}
        ftmm_target2unibbs_class[target] = {}
        ftmm_target2unibbs_class[target]["data_mutation"] = 0
        ftmm_target2unibbs_class[target]["branch_flip"] = 0
        ftmm_target2unibbs_class[target]["hybrid"] = 0

        load_data(traces_dir, runtime, target)
        compute_unique_bbs(target)
        statistic_bbs_unlock_mutation_ftmm(target)
        
    # for target in target2bbs:
    #     print(f'{target}: ')
    #     for fuzzer in target2bbs[target]:
    #         print(f'{fuzzer}: {len(target2bbs[target][fuzzer])}')
    #     print()
    # with open("deduplicated_bbs.json", 'w') as wf:
    #     json.dump(target2bbs, wf, indent = 4)
    
    name = "./unique_bbs.json"
    with open(name, 'w') as wf:
        json.dump(target2unibbs, wf, indent = 4)
        print(f"Unique basic blocks by each fuzzer and targets is writing to file {name}")
    
    name = "./unique_bbs_info.json"
    with open(name, 'w') as wf:
        json.dump(ftmm_target2unibbs_testcases, wf, indent = 4)
        print(f"Info of basic blocks by FTMM is writing to file {name}")

    plot()


if __name__ == "__main__":
    main()
    #load_coverage_test()