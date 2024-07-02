#!/usr/bin/env python3
"""
Plot coverage data. This is originally from Fuzztruction's plotting script, and we customize it for our evaluation
/home/user/fuzztruction/fuzztruction-experiments/comparison-with-state-of-the-art/scripts/plotting/plot.py

## Dependencies (Latex for font)
# sudo apt install texlive texlive-latex-extra texlive-fonts-recommended dvipng cm-super
"""
import matplotlib.pyplot as plt
from matplotlib.ticker import MultipleLocator
import numpy as np 
import scipy.stats as st 
from dataclasses import dataclass
from collections import defaultdict
from matplotlib.pyplot import Figure, Axes
from pathlib import Path
from statistics import mean, median
from typing import Dict, List, Tuple
import sys


# fuzzing run configuration
# * runtime in seconds
runtime = 24 * 3600
# * number of parallel runs
NUM_RUNS = 5

# Targets and their position as (column, row) in the plot
TARGETS_TO_POSITION = {
    # first row
    "genrsa_rsa"              : (0, 0),
    "gendsa_dsa"              : (1, 0),
    "sign_vfychain"           : (2, 0),
    # second row
    "7zip-enc_7zip-dec"       : (0, 1),
    "mp4mux_mp42aac"          : (1, 1),
    "mp4encrypt_mp42aac"      : (2, 1)
}

# TARGETS_TO_POSITION = {
#     # first row
#     "genrsa_rsa"              : (0, 0),
#     "gendsa_dsa"              : (1, 0),
#     "sign_vfychain"           : (2, 0),
#     "7zip_7zip"               : (3, 0),
#     # second row
#     "7zip-enc_7zip-dec"       : (0, 1),
#     "mp4mux_mp42aac"          : (1, 1),
#     "mp4encrypt_mp42aac"      : (2, 1),
# }

targets_to_plottitle = {
    "genrsa_rsa"              : "rsa",
    "gendsa_dsa"              : "dsa",
    "sign_vfychain"           : "vfychain",
    #"7zip_7zip"               : "7zip",
    "7zip-enc_7zip-dec"       : "7zip-dec",
    "mp4mux_mp42aac"          : "mp42aac",
    "mp4encrypt_mp42aac"      : "mp42aac-dec",
}

targets_to_final_mean = {}
targets_to_final_values = {}

# Plot configuration
# * colors used
# https://colorbrewer2.org/#type=qualitative&scheme=Set1&n=3
COLORS: Dict[str, str] = {
   "red"      : "#e41a1c",
   "blue"     : "#377eb8",
   "green"    : "#4daf4a",
}
# * space between markers
N = 45
# * number of fuzzers
NUM_FUZZERS = 3
# * per-fuzzer plot configuration, e.g., which color or marker to use
FUZZERS = {
    "Fuzztruction" : {
        "label" : "Fuzztruction",
        "color" : COLORS["green"],
        "marker" : "s",
        "markersize" : 4,
        "markevery" : (N, N*NUM_FUZZERS),
        "linestyle" : "solid",
    },
    "FTMM" : {
        "label" : "FTMM",
        "color" : COLORS["red"],
        "marker" : "^",
        "markersize" : 4,
        "markevery" : (N*3, N*NUM_FUZZERS),
        "linestyle" : "solid",
    }
}


@dataclass
class PlotData(object):
    """
    Holds data used to plot a fuzzing run
    """
    seconds: List[int]
    raw_bbs: List[List[int]]
    means: List[float]
    intervals: List[Tuple[int, int]]


def parse(path: Path) -> List[Tuple[int, int]]:
    with open(path, "r", encoding="utf8") as f:
        content = [l.strip() for l in f.readlines() if l.strip()]
    res: List[Tuple[int, int]] = []
    d: Dict[int, int] = defaultdict(int)
    assert len(content) >= 2, \
        f"Expected more than 1 lines, found {len(content)} in {path.as_posix()}"
    # skip column header
    content = content[1:]
    for l in content:
        lhs, rhs = l.split(";", 1)
        discovery_ts = int(lhs.strip())
        num_new_unique_bbs = int(rhs.strip())
        d[discovery_ts] = num_new_unique_bbs
    num_bbs_found = 0
    for cur_ts in range(runtime):
        num_bbs_found += d[cur_ts]
        res.append((cur_ts, num_bbs_found))
    assert num_bbs_found > 0, f"{path} reports no basic blocks found!"
    return res


def plot(data: Dict[str, PlotData], target: str, ax: Axes) -> None:
    """
    Plots data as a line (i.e., one fuzzer for one target)
    """
    # tick at each hour, label only every 4h
    xticks = list(map(lambda t: 3600 * t, range(runtime // 3600 + 1)))
    xtick_labels = [str(t) if t % 4 == 0 else "" for t in range(runtime//3600+1)]
    ax.set_xticks(xticks)
    ax.set_xticklabels(xtick_labels)
    ax.set_title(targets_to_plottitle[target])
    loc = MultipleLocator(3600 * 4)
    ax.xaxis.set_major_locator(loc)
    ax.grid()

    for name, fuzzer_data in data.items():
        ax.plot(
            fuzzer_data.seconds,
            fuzzer_data.means,
            **FUZZERS[name]
        )
        if fuzzer_data.intervals:
            lower = [l for (l, _) in fuzzer_data.intervals]
            upper = [h for (_, h) in fuzzer_data.intervals]
            assert len(lower) == len(upper), f"{target}:{name}: Upper and lower 60 percentile have different #data points"
            assert len(lower) == len(fuzzer_data.seconds), f"{target}:{name}: CI has too few data points"
            ax.fill_between(
                fuzzer_data.seconds, lower, upper, color=FUZZERS[name]["color"],
                alpha=.3
            )
        else:
            print(f"{target}:{name}: No ci data")
        targets_to_final_mean[target].append((name, fuzzer_data.means[-1]))

    # ax.set_ylim(ymin=0)
    ax.set_ylim(ymin=0, ymax=max(ax.yaxis.get_majorticklocs()))
    if (target == "genrsa_rsa"):
        ax.set_ylim(ymin=0, ymax=max(ax.yaxis.get_majorticklocs()-1000))
    ax.set_xlim(xmax=runtime)
    # print(ax.yaxis.get_majorticklocs())
    # remove top & right line
    ax.spines["right"].set_visible(False)
    ax.spines["top"].set_visible(False)


def plot_target_mean(raw_data: Dict[str, List[List[Tuple[int, int]]]],
                        target: str, ax: Axes) -> Figure:
    """
    Given raw data for a single target, plot each fuzzer for this target 
    """
    fuzzer_data: Dict[str, PlotData] = {}
    for fuzzer, runs in raw_data.items():
        print(f"{target}:{fuzzer}: plotting mean of {len(runs)} runs")
        all_raw_bbs: List[List[int]] = []
        means: List[float] = []
        intervals: List[Tuple[int, int]] = []
        seconds = list(range(runtime))

        if not runs:
            print(f"[!] {target}:{fuzzer}: No runs found")
            continue

        for sec in seconds:
            # plot only each minute
            if sec % 60 != 0:
                continue
            secs = {run[sec][0] for run in runs}
            # sanity check
            assert len(secs) == 1 and sec in secs, f"expected {sec}, got {secs}"
            raw_bbs = [run[sec][1] for run in runs]
            all_raw_bbs.append(raw_bbs)
            # medians.append(median(raw_bbs))
            means.append(mean(raw_bbs))
            # intervals are hardcoded for 5 runs (and skipped otherwise) 
            if len(raw_bbs) == 5:
                # select data in 60% interval 
                # lower, _, upper = sorted(raw_bbs)[1:-1]
                # calculate 95% CI
                interval = st.t.interval(confidence=0.95, df=len(raw_bbs)-1, loc=np.mean(raw_bbs), scale=st.sem(raw_bbs)) 
                intervals.append(interval)
            else:
                print(
                    f"[!] {target}{fuzzer}: Intervals work only if 5 runs are available " \
                    f"-- found only {len(raw_bbs)} runs"
                )
        targets_to_final_values[target][fuzzer] = all_raw_bbs[-1]
        
        fuzzer_data[fuzzer] = PlotData(
            # plot only each minute => need to prune seconds
            seconds=[s for s in seconds if s % 60 == 0],
            raw_bbs=all_raw_bbs,
            means=means,
            intervals=intervals
        )
    return plot(fuzzer_data, target=target, ax=ax)



def extract_data(base_dir: Path, target: str, fuzzer_names: List[str],
            num_runs: int) -> Dict[str, List[List[Tuple[int, int]]]]:
    """
    extract data in coverage.csv files for num_runs and fuzzer suffix
    """
    all_data: Dict[str, List[List[Tuple[int, int]]]] = {}
    for fuzzer in fuzzer_names:
        # check if we know this fuzzer (and have a plot configuration)
        assert fuzzer in FUZZERS, f"Fuzzer {fuzzer} is not a known fuzzer (known: {list(FUZZERS.keys())})"
        # identify all relevant directories
        run_dirs = []
        for i in range(1, num_runs+1):
            # match expected run dir
            run_dir = base_dir / f"{target}-{fuzzer}-{runtime}s-{i}"
            if not run_dir.exists():
                print(f"[!] Failed to find run directory {run_dir.as_posix()}")
                continue
            if not (run_dir / "coverage.csv").exists():
                print(f"[!] Directory {run_dir.as_posix()} does not contain a coverage.csv")
                continue
            run_dirs.append(run_dir)
        # read coverage.csv files and parse data
        data = [parse(dir / "coverage.csv") for dir in run_dirs]
        if len(data) != num_runs:
            print(f"[!] Expected {num_runs} runs but found {len(data)}")
        # save data
        all_data[fuzzer] = data
    return all_data


def plot_all_targets() -> None:
    """
    Plot means of all fuzzers for all targets
    """
    global runtime
    args = sys.argv
    if len(args) != 3:
        print(f'[!] Usage: {args[0]} <runtime-in-seconds> <directory-containing-all-runs>')
        exit(1)
    done_runs_dir = Path(args[2])
    runtime = int(args[1])

    params = {
        "text.usetex" : True,
        "mathtext.fontset" : "cm",
        "font.family" : "monospace",
    }

    plt.rcParams.update(params)

    # rows * columns must match the number of targets
    rows = 2
    columns = 3
    fig, axes = plt.subplots(rows, columns, figsize=(4.5*columns, 3*rows))
    # rows = 2
    # columns = 4
    # fig, axes = plt.subplots(rows, columns, figsize=(3.75*columns, 3*rows))
    targets = list(TARGETS_TO_POSITION.keys())

    print(f"Found {len(list(targets))} targets")
    assert len(targets) <= sum(map(len, axes)), f"More targets ({len(targets)}) than subplots ({sum(map(len, axes))})"

    # read data for each target
    for target in sorted(list(targets)):
        print(f"{target}: Processing..")
        plot_data = extract_data(
            done_runs_dir, target, ["Fuzztruction", "FTMM"], NUM_RUNS
        )

        col, row = TARGETS_TO_POSITION[target]
        targets_to_final_mean[target] = []
        targets_to_final_values[target] = {}
        plot_target_mean(plot_data, target=target, ax=axes[row][col])
        print()

    # report mean basic blocks
    for target in targets_to_final_mean:
        print(f'Taget: {target}')
        for fuzzer, mean in targets_to_final_mean[target]:
            print(f'{fuzzer}: mean: {mean}, raw: {targets_to_final_values[target][fuzzer]}')
        print()
    
    # collect all labels
    label2handle = {}
    for ax in fig.axes:
        handles, labels = ax.get_legend_handles_labels()
        for label, handle in zip(labels, handles):
            label2handle[label] = handle

    # handles, labels = plt.gca().get_legend_handles_labels()
    fig.legend(label2handle.values(), label2handle.keys(), loc='upper center', ncol = len(label2handle.keys()), bbox_to_anchor=(0.52,1.03))
    fig.supxlabel("Time (hours)", fontsize="large")
    fig.supylabel("\#Covered Basic Blocks", fontsize="large")
    # remove empty subfigures
    # axes[2,0].set_axis_off()
    # axes[2,2].set_axis_off()
    # axes[1,3].set_axis_off()

    fig.tight_layout()
    name = "./all_coverage.pdf"
    print(f"Writing to file {name}")
    plt.savefig(name, bbox_inches='tight')


if __name__ == "__main__":
    plot_all_targets()
