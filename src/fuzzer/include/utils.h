#ifndef UTILS_H
#define UTILS_H

#include <mutex>
#include <map>
#include <set>
#include <vector>
#include <stdint.h>

#define MQNAME "/FTMM_MQ"
#define SHM_NAME "/FTMM_SHM"
#define MAX_FILE_SIZE 1024 * 1024
#define MAX_REG_SIZE 16
#define HAVOC_FUSION_STEPS 16
#define MAX_HAVOC_STEPS 8
#define MAX_ITERATION 1024

/// TODO: make configurable
// #define MAX_RANDOM_STEPS 32
// #define MAX_NUM_ONE_MUT 1024
// #define NUM_THREAD 8
// #define SOURCE_TIMEOUT 3

/// defined types
typedef struct patch_point{
    uint64_t addr;
    uint8_t reg_size;
} Patchpoint;
typedef struct test_case{
    char filename[255];
    char filehash[65];
    Patchpoint patch_point;
    int mut_type;
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
typedef struct masks{
    uint64_t num_iter;
    uint64_t addr;
    uint64_t cur_iter;
    unsigned char masks[(MAX_ITERATION + 1) * MAX_REG_SIZE];
}Masks;
typedef struct shm_para{
    key_t key;
    int shm_id;
    unsigned char *shm_base_ptr;
    size_t size_in_bytes;
}Shm_para;
typedef struct pps_lock{
    Patchpoints pps;
    std::mutex mutex;
}Patchpointslock;
typedef struct addr2iter{
    std::map<uint64_t, uint64_t> map;
    std::mutex mutex;
}Addr2iter;
typedef struct interestpp2masks{
    std::map< uint64_t, std::vector<Masks> > map;
    std::mutex mutex;
}Interestpp2masks;

/// the second of the pair is a map from a hash to a mask
typedef std::map < uint64_t, std::map<std::string, Masks> > Pp2masks;

inline auto pps_compare = [](const Patchpoint a, const Patchpoint b){ return a.addr < b.addr; };
typedef struct pps_set_lock {
    std::set<Patchpoint, decltype(pps_compare)> set;
    std::mutex mutex;
}PpsSetLock;
typedef struct new_selection_config{
    size_t unfuzzed_num;
    size_t interest_num;
    size_t random_num;
}NewSelectionConfig;


#endif