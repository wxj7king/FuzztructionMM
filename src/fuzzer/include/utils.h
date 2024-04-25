#ifndef UTILS_H
#define UTILS_H

#include <mutex>
#include <map>
#include <set>
#include <vector>
#include <stdint.h>

#define MQNAME "/FTMM_MQ"
#define POSIX_SHM_NAME "FTMM_AFL_SHM"
#define MAX_ITERATION 512

/// defined types
typedef struct patch_point{
    uint64_t addr;
    uint8_t reg_size;
    uint64_t next_mov_b4_jmp;
} Patchpoint;
typedef struct test_case{
    char filename[255];
    char filehash[65];
    Patchpoint patch_point;
    int mut_type;
    int worker_id;
    size_t multi_num;
}TestCase;
typedef std::vector<Patchpoint> Patchpoints;
typedef struct pps2fuzz{
    Patchpoints unfuzzed_pps;
    Patchpoints interest_pps;
    Patchpoints random_pps;
}Pps2fuzz;

typedef std::map<std::string, Patchpoint> Hash2pp;
typedef std::set<std::string> StringSet;
typedef std::map<std::string, std::string> PintoolArgs;
typedef struct thread_arg{
    int tid;
}ThreadArg;
typedef struct posix_shm_para{
    int shmfd;
    unsigned char *shm_base_ptr;
    size_t size_in_bytes;
}PosixShmPara;
typedef struct pps_lock{
    Patchpoints pps;
    std::mutex mutex;
}Patchpointslock;
typedef struct addr2iter{
    std::map<uint64_t, uint64_t> map;
    std::map<uint64_t, bool> chk_ptr_map;
    std::mutex mutex;
}Addr2iter;

inline auto pps_compare = [](const Patchpoint a, const Patchpoint b){ return a.addr < b.addr; };
typedef struct pps_set_lock {
    std::set<Patchpoint, decltype(pps_compare)> set;
    std::mutex mutex;
}PpsSetLock;

typedef struct patch_points_multi{
    Patchpoints pps;
    size_t original_num;
    std::string str() const {
        std::string pps_str = "";
        if (pps.empty()) return pps_str;
        for (const auto &pp : pps)
        {
            pps_str += (std::to_string(pp.addr) + ",");
        }
        pps_str.pop_back();
        return pps_str;
    }
}PatchpointsMulti;
inline auto pps_compare_multi = [](const PatchpointsMulti a, const PatchpointsMulti b){ return a.str() < b.str(); };
typedef struct pps_multi_set_lock {
    std::set<PatchpointsMulti, decltype(pps_compare_multi)> set;
    std::mutex mutex;
}PpsMultiSetLock;

typedef std::map<std::string, PatchpointsMulti> Hash2ppsMulti;

typedef struct pps2fuzz_multi{
    PatchpointsMulti unfuzzed_pps;
    PatchpointsMulti interest_pps;
}Pps2fuzzMulti;

typedef struct new_selection_config{
    size_t unfuzzed_num;
    size_t interest_num;
    size_t random_num;
}NewSelectionConfig;

typedef struct bin_config{
    std::vector<std::string> env;
    std::string bin_path;
    std::vector<std::string> args;
}BinConfig;

typedef struct afl_config{
    std::string dir_in;
    std::string dir_out;
}AflConfig;


#endif