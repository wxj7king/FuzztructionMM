#ifndef WORKER_H
#define WORKER_H

#include "include/utils.h"
#include <mqueue.h>

class Worker{

public:
    typedef std::vector<pid_t> SourcePids;

    static inline Patchpointslock source_pps;
    static inline Patchpointslock source_unfuzzed_pps;
    static inline Addr2iter addr2iter;
    static inline Interestpp2masks addr2masks_global;
    static inline PpsSetLock interest_pps;
    static inline std::mutex log_mtx;
    static inline SourcePids source_pids;

    static inline Shm_para shm_para;
    static inline std::string ftmm_dir;
    static inline struct mq_attr my_mqattr;
    static inline std::string log_path;
    static inline NewSelectionConfig new_selection_config;

    static inline size_t MAX_RANDOM_STEPS;
    static inline size_t MAX_NUM_ONE_MUT;
    static inline size_t NUM_THREAD;
    static inline size_t SOURCE_TIMEOUT;

    // func
    Worker(int _id, int _level);
    ~Worker();

    static std::string sha256(const std::string &file_path);
    static void output_log(const std::string& msg);
    static size_t get_iter(std::string out_dir, std::string addr_str);

    void generate_testcases();
    TestCase fuzz_one(PintoolArgs& pintool_args, Patchpoint &pp);
    void mutations_1(Patchpoint &pp, int mut_type, size_t max_steps);
    void mutations_2(Patchpoint &pp, int mut_type, size_t max_steps);
    void bit_flip(PintoolArgs& pintool_args, Patchpoint& pp);
    void byte_flip(PintoolArgs& pintool_args, Patchpoint& pp);
    void random_byte(PintoolArgs& pintool_args, Patchpoint& pp, int rand_type);
    void u8add(PintoolArgs& pintool_args, Patchpoint& pp);
    void combine(PintoolArgs& pintool_args, Patchpoint& pp);
    void havoc(PintoolArgs& pintool_args, Patchpoint& pp);
    void fuzz_candidates_1();
    void fuzz_candidates_2();
    void save_interest_pps();
    void start();

private:
    int id;
    mqd_t mqd;
    int level;
    std::string work_dir;
    Pps2fuzz selected_pps;
    Hash2pp hash2pp;
    /// interesting input files for the sink in the afl output dir
    StringSet afl_files;
    /// hashes of files in 'afl_files' 
    StringSet afl_files_hashes;
    /// temp map for saving masks of a patch point
    Pp2masks addr2masks;
    Masks *masks_ptr;

};


#endif