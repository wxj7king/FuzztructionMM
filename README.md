# FuzztructionMinusMinus

FuzztructionMinusMinus (FTMM) is a fuzzer that follows the core idea from [Fuzztruction](https://mschloegel.me/paper/bars2023fuzztruction.pdf) yet employs a simpler implementation and adds more program mutators. 

## Quick start
```bash
# Clone the repository
git clone https://github.com/wxj7king/FuzztructionMM.git
# Option 1: Build locally
# Build
cd FuzztructionMM && ./build.sh

# Option 2: Build and use a docker image
# Build a docke image
./build_docker.sh
# Spawn a container
./start.sh
# Run again to enter the container
./start.sh
# Build inside the container
./build.sh
# Stop the container outside.
# You can enter again by running ./start.sh
./stop.sh
```

## How to use FuzztructionMM
### Build a target
Firstly, you need to build the generator and consumer. Specifically, the generator needs to be instrumented by AFL++'s instrumentation, while the consumer only needs to be compiled normally. There is an example `OpenSSL` in [`experiments/targets/openssl`](./experiments/targets/openssl/), and you can use `build.sh` to build the `OpenSSL`. We will give an example of fuzzing the generator and consumer pair of `genrsa/rsa`. 
### Create a config file
Next, you need to create a config file for FuzztructionMM. The example of the config file for `genrsa/rsa` is [`experiments/binary_config/genrsa_rsa.json`](./experiments/binary_config/genrsa_rsa.json/).
### Let's fuzz!
Last, you can start fuzzing using the commands:
```bash
cd fuzzer && ./fuzzer -n 4 -f /home/user/FuzztructionMM/experiments/binary_config/genrsa_rsa.json -T 300
# You may need some settings for AFL++
echo core >/proc/sys/kernel/core_pattern
```
This command will spawn 4 workers for fuzzing with a timeout of 5 minutes. The `log` is produced under `/tmp`. The AFL++'s work directory is specified in the config file, and you can inspect the fuzzing results after termination.

## Artifacts
All the scripts for the pre-built docker are under the [`experiments/artifacts`](./experiments/artifacts/) directory. 
### Environment preparation
```bash
# Get the pre-built Docker image
./pull_image.sh
# Spawn a container and enter
./start.sh && ./start.sh
# Stop the container
./stop.sh
```
After entering the container, there are some relevant directories: 
| Path | Usage |
|:--|----|
| `/home/user/eval` | Scripts for evaluation.  |
| `/home/user/eval_shared` | Experiments results and data. It is mounted from the host directory `./eval_shared`. |
| `/home/user/ftmm_targets` | Seeds for generators. |
|  `/home/user/fuzztruction` | Prototype of Fuzztruction. |
|  `/home/user/FuzztructionMM` | Prototype of FuzztructionMM. |

### Evaluation
All the scripts for evaluation are under the `/home/user/eval` folder. 
#### Run experiments
Use the `eval_run.py` to perform fuzzing on all targets.
```bash
cd /home/user/eval
# Perform fuzzing 5 times over a timeout of 24 hours.
# Spawn 32 workers for Fuzztruction/FuzztructionMM
sudo ./eval_run.py 86400 32
```
#### Plot figures
```bash
# Plot the coverage figure.
sudo ./plot.py 86400 /home/user/eval_shared
# Plot the unique covered basic blocks
sudo ./unique_bbs.py 86400 /home/user/eval_shared
```
