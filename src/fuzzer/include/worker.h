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
    static inline PpsSetLock interest_pps;
    static inline std::mutex log_mtx;
    static inline SourcePids source_pids;
    static inline PosixShmPara posix_shm;
    static inline std::string ftmm_dir;
    static inline struct mq_attr my_mqattr;
    static inline std::string log_path;
    static inline NewSelectionConfig new_selection_config;
    static inline size_t max_random_steps;
    static inline size_t max_num_one_mut;
    static inline size_t num_thread;
    static inline size_t source_timeout;
    static inline BinConfig source_config;
    static inline int schedule_mode;

    // func
    Worker(int _id);
    ~Worker();

    static std::string sha256(const std::string &file_path);
    static void output_log(const std::string& msg);
    static size_t get_iter(std::string out_dir, std::string addr_str, bool check_ptr, bool &is_pointer);

    void generate_testcases();
    bool pp_valid_check(Patchpoint &pp);
    TestCase fuzz_one(PintoolArgs& pintool_args, Patchpoint &pp);
    void mutations_one(Patchpoint &pp, int mut_type);
    void mutations_multi(Patchpoints &pps, int mut_type);
    void fuzz_candidates_1();
    void fuzz_candidates_2();
    void save_interest_pps();
    void start();

private:
    int id;
    mqd_t mqd;
    int level;
    size_t cur_mut_counter;
    std::string work_dir;
    Pps2fuzz selected_pps;
    Hash2pp hash2pp;
    /// interesting input files for the sink in the afl output dir
    StringSet afl_files;
    /// hashes of files in 'afl_files' 
    StringSet afl_files_hashes;

};


#endif