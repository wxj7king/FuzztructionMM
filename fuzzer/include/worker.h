#ifndef WORKER_H
#define WORKER_H

#include "include/utils.h"
#include <mqueue.h>

class Worker{

public:
    typedef std::vector<pid_t> SourcePids;
    static inline Patchpointslock source_pps;
    static inline Patchpointslock source_unfuzzed_pps;
    static inline Patchpointslock source_pps_branch;
    static inline Patchpointslock source_unfuzzed_pps_branch;
    static inline Addr2iter addr2iter;
    static inline Addr2iter addr2iter_branch;
    static inline PpsSetLock interest_pps;
    static inline PpsMultiSetLock interest_pps_multi;
    static inline std::mutex log_mtx;
    static inline bool stop_soon;
    static inline std::chrono::time_point<std::chrono::high_resolution_clock> start_time;
    static inline size_t fuzzer_timeout;
    static inline PosixShmPara posix_shm;
    static inline std::string ftmm_dir;
    static inline struct mq_attr my_mqattr;
    static inline std::string log_path;
    static inline NewSelectionConfig new_selection_config;
    static inline size_t max_random_steps;
    static inline size_t max_num_one_mut;
    static inline size_t num_thread;
    static inline size_t generator_timeout;
    static inline size_t max_pps_one_mut;
    static inline size_t max_pps_one_mut_branch;
    static inline BinConfig source_config;
    static inline AflConfig afl_config;
    static inline int schedule_mode;
    static inline struct GlobalReadPtr
    {
        size_t ptr;
        size_t curr_multi_pps_num;
        bool random_flag;
        std::mutex mtx;
    }global_read_ptr;

    static inline struct GlobalMutCount{
        size_t count;
        std::mutex mtx;
    }global_mutations_count;
    static inline std::string pintool_path;
    static inline std::string pinbin_path;

    // func
    Worker(int _id);
    ~Worker();

    static std::string sha256(const std::string &file_path);
    static void output_log(const std::string& msg);
    static size_t get_iter(std::string out_dir, std::string addr_str, bool check_ptr, bool &is_pointer);
    static size_t get_elapsed_seconds();

    void generate_testcases();
    void generate_testcases_multi();
    void generate_testcases_branch();
    bool pp_valid_check(const Patchpoint &pp);
    TestCase fuzz_one(PintoolArgs& pintool_args, const Patchpoint &pp);
    void mutations_one(const Patchpoint &pp, int mut_type);
    void mutations_multi(const Patchpoints &pps, int mut_type);
    void mutations_branch(const Patchpoints &pps);
    void fuzz_candidates_one();
    void fuzz_candidates_multi();
    void fuzz_candidates_branch();
    void save_interest_pps();
    void start();
    void set_level(int l);

private:
    int id;
    mqd_t mqd;
    int level;
    int branch_flip_type;
    size_t cur_mut_count;
    size_t total_mutations_count;
    std::string work_dir;
    Pps2fuzz selected_pps;
    Pps2fuzzMulti selected_pps_multi;
    Hash2pp hash2pp;
    Hash2ppsMulti hash2pps_multi;
    /// interesting input files for the sink in the afl output dir
    StringSet afl_files;
    /// hashes of files in 'afl_files' 
    StringSet afl_files_hashes;
    size_t unfuzzed_count;

};


#endif