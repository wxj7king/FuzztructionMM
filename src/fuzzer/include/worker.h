#ifndef WORKER_H
#define WORKER_H

#include "include/utils.h"
#include <mqueue.h>

class Worker{

public:
    inline static Patchpointslock source_pps;
    inline static Patchpointslock source_unfuzzed_pps;
    inline static Addr2iter addr2iter;
    inline static Interestpp2masks addr2masks_global;
    inline static Shm_para shm_para;
    inline static std::string ftmm_dir;
    inline static PpsSetLock interest_pps;
    inline static struct mq_attr my_mqattr;
    inline static std::mutex log_mtx;
    inline static std::string log_path;
    inline static NewSelectionConfig new_selection_config;
    inline static bool fuzz_stop = false;
    inline static pid_t source_pids[NUM_THREAD] = {-1};

    // func
    explicit Worker(int _id, int _level);

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