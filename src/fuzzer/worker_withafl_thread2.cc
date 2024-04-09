#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdint.h>
#include <mqueue.h>
#include <string.h>
#include <assert.h>
#include <sys/wait.h>
#include <sys/resource.h>
#include <vector>
#include <queue>
#include <map>
#include <set>
#include <string>
#include <memory>
#include <filesystem>
#include <chrono>
#include <sstream>
#include <fstream>
#include <random>
#include <iostream>
#include <algorithm>
#include <mutex>
#include <condition_variable>
#include <openssl/evp.h>
#include <openssl/sha.h>
#include <sys/ipc.h>
#include <sys/shm.h>

#define MQNAME "/TEST_MQ"
#define SHM_NAME "/FTMM_SHM"
#define MAX_FILE_SIZE 16 * 1024
#define NUM_THREAD 8
#define SOURCE_TIMEOUT 3

#define RANDOM_MAX_STEPS 32
#define MAX_INTEREST_SIZE 1024 * 1024
#define MAX_ITERATION 1024
#define MAX_REG_SIZE 16
#define MAX_NUM_ONE_MUT 1184
typedef struct patch_point{
    uint64_t addr;
    uint8_t reg_size;
} Patchpoint;
typedef struct test_case{
    char filename[255];
    Patchpoint patch_point;
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
    int pid;
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

template <typename T>
class MyQueue {
    public:
        std::queue<T> queue;
        std::mutex mutex;
};
class Addr2iter{
    public:
        std::map<uint64_t, uint64_t> map;
        std::mutex mutex;
};

class Interestpp2masks{
    public:
        std::map< uint64_t, std::vector<Masks> > map;
        std::mutex mutex;
};


// global variables
struct new_ts_config{
    size_t unfuzzed_num;
    size_t interest_num;
    size_t random_num;
    size_t combine_num;
}new_ts_config;
enum MUTATION_TYPE{
    BYTE_FLIP = 0,
    BIT_FLIP,
    RANDOM_BYTE,
    RANDOM_BYTE0,
    U8ADD,
    INJECT_VAL,
    COMBINE
};
struct mq_attr my_mqattr;
pid_t afl_pid;
pid_t worker_pid;
Patchpointslock source_pps;
Patchpointslock source_unfuzzed_pps;
std::mutex log_mtx;
static volatile int timeout_flag;
pthread_t threads[NUM_THREAD];
ThreadArg targs[NUM_THREAD];
std::string out_dirs[NUM_THREAD];
std::string log_path = "";
static MyQueue<Patchpoint> interest_pps;
Addr2iter addr2iter;
Interestpp2masks addr2masks_global;
Shm_para shm_para;
std::string work_dir = "/tmp/ftmm_workdir";

// funcs
void timeout_handler(int sig){
    timeout_flag = 1;
}

std::string sha256(const std::string &file_path){
    unsigned char hash[SHA256_DIGEST_LENGTH];
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    unsigned int md_len;
    if(!ctx){
        perror("EVP_MD_CTX_new()");
        return "";
    }
    if(!EVP_DigestInit_ex(ctx, EVP_sha256(), nullptr)){
        perror("EVP_DigestInit_ex()");
        EVP_MD_CTX_free(ctx);
        return "";
    }
    std::ifstream fp(file_path, std::ios::binary);
    if (!fp){
        perror("open file");
        return "";
    }

    char read_buf[4096];
    while(fp.good()){
        fp.read(read_buf, 4096);
        if(!EVP_DigestUpdate(ctx, read_buf, fp.gcount())){
            perror("EVP_DigestUpdate()");
            EVP_MD_CTX_free(ctx);
            fp.close();
            return "";
        }
    }
    fp.close();
    if (!EVP_DigestFinal_ex(ctx, hash, &md_len)){
        perror("EVP_DigestFinal_ex()");
        EVP_MD_CTX_free(ctx);
        return "";
    }

    EVP_MD_CTX_free(ctx);
    std::ostringstream oss;
    for (size_t i = 0; i < md_len; i++){
        oss << std::hex << std::setw(2) << std::setfill('0') << (int)hash[i];
    }
    std::string ret = oss.str();
    return ret;
}

void output_log(const std::string& msg, const std::string& log_path){
    std::lock_guard<std::mutex> lock(log_mtx);
    std::ofstream log_file(log_path, std::ios::app);
    if (log_file.is_open()){
        log_file << msg << std::endl;
        log_file.close();
    }else{
        perror("Unable to open log file\n");
    }
    return;
}

bool find_patchpoints(std::string out_dir, Patchpointslock& patch_points){
    std::string source_out = out_dir + "/tmp_source";
    std::string find_ins_out = out_dir + "/tmp_pintool";
    //out_dir = out_dir + "/tmp_rsak";
    //std::string cmd = "LD_LIBRARY_PATH=/home/proj/proj/uninstrumented/openssl/ /home/proj/proj/tools/pin-3.28-98749-g6643ecee5-gcc-linux/pin -t /home/proj/proj/src/pintool/find_inst_sites2/obj-intel64/find_inst_sites.so -- /home/proj/proj/uninstrumented/openssl/apps/openssl genrsa -aes128 -passout pass:xxxxx -out @ 512 2>/dev/null";
    std::ostringstream oss;
    oss << "LD_LIBRARY_PATH=/home/proj/proj/uninstrumented/openssl/" << " ";
    oss << "/home/proj/proj/tools/pin-3.28-98749-g6643ecee5-gcc-linux/pin" << " ";
    oss << "-t" << " ";
    oss << "/home/proj/proj/src/pintool/find_inst_sites3/obj-intel64/find_inst_sites.so" << " ";
    oss << "-o" << " ";
    oss << find_ins_out << " ";
    oss << "--" << " ";
    oss << "/home/proj/proj/uninstrumented/openssl/apps/openssl" << " ";
    oss << "genrsa" << " ";
    oss << "-aes128" << " ";
    oss << "-passout" << " ";
    oss << "pass:xxxxx" << " ";
    oss << "-out" << " ";
    oss << source_out << " ";
    oss << "512" << " ";
    oss << "2>/dev/null" << " ";
    std::string cmd = oss.str();
    // printf("cmd: %s\n", cmd.c_str());

    if (system(cmd.c_str()) != 0) return false;
    std::ifstream file(find_ins_out);
    if (file.is_open()){
        std::string line;
        while (std::getline(file, line))
        {
            Patchpoint pp;
            size_t del_idx = line.find(',');
            pp.addr = std::stoul(line.substr(0, del_idx), nullptr, 16); 
            pp.reg_size = (uint8_t)std::stoul(line.substr(del_idx + 1, line.length()));
            // printf("%lx, %u\n", pp.addr, pp.reg_size);
            if (pp.reg_size == 0) continue;
            patch_points.pps.push_back(pp);
        }
        file.close();
    }else{
        return false;
    }

    if (!std::filesystem::remove(source_out)) printf("find pps: delete file source_out failed: %s\n", source_out.c_str());
    if (!std::filesystem::remove(find_ins_out)) printf("find pps: delete file find_ins_out failed: %s\n", find_ins_out.c_str());
    
    return true;
}

size_t get_iter(std::string out_dir, std::string addr_str){
    out_dir = out_dir + "/tmp_get_iter";
    std::ostringstream oss;
    oss << "LD_LIBRARY_PATH=/home/proj/proj/uninstrumented/openssl/" << " ";
    oss << "/home/proj/proj/tools/pin-3.28-98749-g6643ecee5-gcc-linux/pin" << " ";
    oss << "-t" << " ";
    oss << "/home/proj/proj/src/pintool/get_iter_num/obj-intel64/get_iter_num.so" << " ";
    oss << "-addr" << " ";
    oss << addr_str << " ";
    oss << "--" << " ";
    oss << "/home/proj/proj/uninstrumented/openssl/apps/openssl" << " ";
    oss << "genrsa" << " ";
    oss << "-aes128" << " ";
    oss << "-passout" << " ";
    oss << "pass:xxxxx" << " ";
    oss << "-out" << " ";
    oss << out_dir << " ";
    oss << "512" << " ";
    oss << "2>/dev/null" << " ";
    std::string cmd = oss.str();
    char buffer[128] = {};
    std::string result = "";
    size_t addr, iter_num = 0;

    std::shared_ptr<FILE> pipe(popen(cmd.c_str(), "r"), pclose);
    if (!pipe) throw std::runtime_error("popen() failed!");
    while (!feof(pipe.get())) {
        if (fgets(buffer, 128, pipe.get()) != NULL){
            result = buffer;
            size_t del_idx = result.find(',');
            addr = std::stoul(result.substr(0, del_idx), nullptr, 16); 
            iter_num = std::stoul(result.substr(del_idx + 1, result.length()));
            //printf("0x%lx, %lu\n", addr, hits);
        }
    }
    if (std::filesystem::exists(out_dir)){
        if (!std::filesystem::remove(out_dir)) perror("get_iter: delete file failed\n");
    }
    
    return iter_num;
}

void generate_testcases(Patchpointslock &source_pps, Patchpointslock &unfuzzed_pps, Pps2fuzz &selected_pps){
    selected_pps.interest_pps.clear();
    selected_pps.unfuzzed_pps.clear();
    selected_pps.random_pps.clear();

    size_t res = new_ts_config.interest_num + new_ts_config.random_num + new_ts_config.unfuzzed_num;
    size_t real_select;
    std::ostringstream oss;

    if (!unfuzzed_pps.pps.empty()){
        std::lock_guard<std::mutex> lock(unfuzzed_pps.mutex);
        real_select = std::min(unfuzzed_pps.pps.size(), new_ts_config.unfuzzed_num);
        for (size_t i = 0; i < real_select; i++){
            selected_pps.unfuzzed_pps.push_back(unfuzzed_pps.pps[i]);
            res--;
        }
        unfuzzed_pps.pps.erase(unfuzzed_pps.pps.begin(), unfuzzed_pps.pps.begin() + real_select);
        oss << "[*] Selected " << selected_pps.unfuzzed_pps.size() << "/" << new_ts_config.unfuzzed_num << " unfuzzed pps\t";
    }else{
        oss << "[*] Selected " << "0/0" << " unfuzzed pps\t";
    }

    {
        std::lock_guard<std::mutex> lock(interest_pps.mutex);
        real_select = std::min(interest_pps.queue.size(), new_ts_config.interest_num);
        for (size_t i = 0; i < real_select; i++){
            Patchpoint tmp_pp = interest_pps.queue.front();
            selected_pps.interest_pps.push_back(tmp_pp);
            interest_pps.queue.pop();
            interest_pps.queue.push(tmp_pp);
            res--;
        }
    }
    oss << selected_pps.interest_pps.size() << "/" << new_ts_config.interest_num << " interesting pps\t";
    
    std::random_device rd;
    std::mt19937 gen(rd()); // Mersenne Twister engine

    {   
        std::lock_guard<std::mutex> lock(source_pps.mutex);
        std::uniform_int_distribution<size_t> dist_idx(0, source_pps.pps.size() - 1);
        real_select = std::min(source_pps.pps.size(), res);
        for (size_t i = 0; i < real_select; i++){
            selected_pps.random_pps.push_back(source_pps.pps[dist_idx(gen)]);
        }
    }

    oss << selected_pps.random_pps.size() << "/" << new_ts_config.random_num << " random pps";

    output_log(oss.str(), log_path);
    //printf("%s\n", oss.str().c_str());
}

TestCase fuzz_one(int id, PintoolArgs& pintool_args ,Hash2pp &hash2pp, Patchpoint &pp, int level){
    auto now = std::chrono::system_clock::now();
    auto duration = now.time_since_epoch();
    auto millis = std::chrono::duration_cast<std::chrono::milliseconds>(duration).count();
    std::string timestamp = std::to_string(millis);
    std::string out_file = out_dirs[id] + "/rsak_" + std::to_string(id) + "_" + timestamp;
    std::vector<const char*> source_argv;
    std::vector<const char*> source_envp;
    // argv and envp
    source_argv.push_back("/home/proj/proj/tools/pin-3.28-98749-g6643ecee5-gcc-linux/pin");
    source_argv.push_back("-t");
    //source_argv.push_back("/home/proj/proj/src/pintool/mutate_ins2/obj-intel64/mutate_ins.so");
    if (level == 1) source_argv.push_back("/home/proj/proj/src/pintool/mutate_ins_multi2/obj-intel64/mutate_ins.so");
    else if (level == 2) source_argv.push_back("/home/proj/proj/src/pintool/mutate_ins_multi3/obj-intel64/mutate_ins.so");

    for (const auto& arg : pintool_args){
        source_argv.push_back(arg.first.c_str());
        source_argv.push_back(arg.second.c_str());
    }
    // source_argv.push_back("-addr");
    // source_argv.push_back(addrs_str.c_str());
    // source_argv.push_back("-mut");
    // source_argv.push_back(muts_str.c_str());
    source_argv.push_back("--");
    
    source_argv.push_back("/home/proj/proj/uninstrumented/openssl/apps/openssl");
    source_argv.push_back("genrsa");
    source_argv.push_back("-aes128");
    source_argv.push_back("-passout");
    source_argv.push_back("pass:xxxxx");
    source_argv.push_back("-out");
    source_argv.push_back(out_file.c_str());
    source_argv.push_back("512");
    source_argv.push_back(0);
    source_envp.push_back("LD_LIBRARY_PATH=/home/proj/proj/uninstrumented/openssl/");
    source_envp.push_back(0);

    // printf("%d: cmd: ", id);
    // std::vector<const char*>::iterator it;
    // for(it = source_argv.begin(); it != source_argv.end(); it++){
    //     printf("%s ", *it);
    // }
    // printf("\n");
    
    int pid = fork();
    if (pid == -1){
        perror("fork failed!");
        exit(-1);
    }else if(pid == 0){
        // discard output
        int null_fd = open("/dev/null", O_WRONLY);
        if (null_fd < 0) perror("failed to open /dev/null!");
        dup2(null_fd, STDOUT_FILENO);
        dup2(null_fd, STDERR_FILENO);
        close(null_fd);
        // set limit to the file size of output 
        struct rlimit limit;
        limit.rlim_cur = MAX_FILE_SIZE;
        limit.rlim_max = MAX_FILE_SIZE;
        // assert(setrlimit(RLIMIT_FSIZE, &limit) == 0);
        if (setrlimit(RLIMIT_FSIZE, &limit) != 0) perror("setrlimit() failed!\n");
        // restrict output dir?
        // assert(chdir(out_dirs[id].c_str()) == 0);
        if (chdir(out_dirs[id].c_str()) != 0) perror("chdir() failed!\n");
        // set timeout
        signal(SIGALRM, timeout_handler);
        alarm(SOURCE_TIMEOUT);
        execve(source_argv[0], const_cast<char* const*>(source_argv.data()), const_cast<char* const*>(source_envp.data()));
        perror("execve failed!");
        exit(-1);
    }

    int status;
    waitpid(pid, &status, 0);
    // if(ret != 0){
    //     std::cout << "system function error\n";
    //     return 0;
    // }
    int fail = 1;
    std::ifstream mutated_output(out_file);
    if (WIFSIGNALED(status) && WTERMSIG(status) == SIGALRM){
        printf("timeout occured!\n");
        kill(pid, SIGKILL);
        waitpid(pid, &status, 0);
        fail = 1;
    }else if (!mutated_output){
        //std::cout << "mutated output file open failed\n";
        fail = 1;
    }else if(std::filesystem::file_size(out_file) == 0){
        //std::cout << "mutated output file is empty\n";
        if(!std::filesystem::remove(out_file)) printf("failed to delete file '%s'\n", out_file.c_str());
        fail = 1;
    }else{
        //std::cout << "mutated output file is exist!\n";
        fail = 0;
    }

    TestCase testcase;
    if (fail){
        memset(testcase.filename, 0, sizeof(testcase.filename));
    }else{
        std::string file_hash = sha256(out_file);
        std::string out_file_hash = out_dirs[id] + "/" + file_hash;
        if (std::rename(out_file.c_str(), out_file_hash.c_str()) == 0){
            strncpy(testcase.filename, out_file_hash.c_str(), sizeof(testcase.filename));
        }else{
            perror("rename()");
            strncpy(testcase.filename, out_file.c_str(), sizeof(testcase.filename));
        }
        //printf("new_filename: %s\n", testcase.filename);
        testcase.filename[sizeof(testcase.filename) - 1] = 0;
        // testcase.patch_point.addr = addr;
        hash2pp[file_hash] = pp;

    }
    return testcase;

}

void mutations_1(mqd_t &mqd, int id, Patchpoint &pp, Hash2pp &hash2pp, int mut_type, size_t max_steps){
    PintoolArgs pintool_args;
    pintool_args["-addr"] = std::to_string(pp.addr);
    pintool_args["-mut"] = std::to_string(mut_type);

    for (size_t i = 0; i < max_steps; i ++){
        TestCase ts = fuzz_one(id, pintool_args, hash2pp, pp, 1);
        mq_send(mqd, (const char *)&ts, sizeof(TestCase), 1);
    }
    
}

void bit_flip(mqd_t &mqd, int id, PintoolArgs& pintool_args, Hash2pp& hash2pp, Masks *masks_ptr, Patchpoint& pp, Interestpp2masks &addr2masks){
    uint64_t num_iter_apply = addr2iter.map[pp.addr];
    masks_ptr->num_iter = num_iter_apply;
    masks_ptr->addr = pp.addr;
    unsigned char* mask_ptr = masks_ptr->masks;
    size_t last_byte_idx = 0;
    size_t num_mut_cap = std::min(num_iter_apply * pp.reg_size * 8, (uint64_t)MAX_NUM_ONE_MUT);
    for (size_t idx_flip = 0; idx_flip < num_mut_cap; idx_flip++)
    {
        mask_ptr[last_byte_idx] = 0;
        last_byte_idx = idx_flip / 8;
        // flip bit
        mask_ptr[idx_flip / 8] = 1 << (idx_flip % 8);
        masks_ptr->cur_iter = 0;
        //printf("bit flip, idx: %ld\n", idx_flip);

        // mutate
        TestCase ts = fuzz_one(id, pintool_args, hash2pp, pp, 2);
        mq_send(mqd, (const char *)&ts, sizeof(TestCase), 1);
        if (addr2masks.map.count(pp.addr) == 0) {
            std::vector<Masks> msk_empty;
            addr2masks.map[pp.addr] = msk_empty;
        }
        std::string fname = ts.filename;
        if (fname != ""){
            addr2masks.map[pp.addr].push_back(*masks_ptr);
        }
    }
    
}

void byte_flip(mqd_t &mqd, int id, PintoolArgs& pintool_args, Hash2pp& hash2pp, Masks *masks_ptr, Patchpoint& pp, Interestpp2masks &addr2masks){
    uint64_t num_iter_apply = addr2iter.map[pp.addr];
    masks_ptr->num_iter = num_iter_apply;
    masks_ptr->addr = pp.addr;
    unsigned char* mask_ptr = masks_ptr->masks;
    size_t last_byte_idx = 0;
    size_t num_mut_cap = std::min(num_iter_apply * pp.reg_size, (uint64_t)MAX_NUM_ONE_MUT);

    for (size_t idx_flip = 0; idx_flip < num_mut_cap; idx_flip++)
    {
        mask_ptr[last_byte_idx] = 0;
        last_byte_idx = idx_flip;
        // flip byte
        mask_ptr[idx_flip] = 0xff;
        masks_ptr->cur_iter = 0;
        //printf("byte flip, idx: %ld\n", idx_flip);

        // mutate
        TestCase ts = fuzz_one(id, pintool_args, hash2pp, pp, 2);
        mq_send(mqd, (const char *)&ts, sizeof(TestCase), 1);
        if (addr2masks.map.count(pp.addr) == 0) {
            std::vector<Masks> msk_empty;
            addr2masks.map[pp.addr] = msk_empty;
        }
        std::string fname = ts.filename;
        if (fname != ""){
            addr2masks.map[pp.addr].push_back(*masks_ptr);
        }
        
    }
    
}

void random_byte(mqd_t &mqd, int id, PintoolArgs& pintool_args, Hash2pp& hash2pp, Masks *masks_ptr, Patchpoint& pp, int rand_type, Interestpp2masks &addr2masks){
    uint64_t num_iter_apply = addr2iter.map[pp.addr];
    masks_ptr->num_iter = num_iter_apply;
    masks_ptr->addr = pp.addr;
    unsigned char* mask_ptr = masks_ptr->masks;
    size_t last_byte_idx = 0;

    size_t idx_rand = 0;
    std::random_device rd;
    std::mt19937 gen(rd()); // Mersenne Twister engine
    std::uniform_int_distribution<uint8_t> dist_u8;
    std::uniform_int_distribution<uint64_t> dist_idx(0, (num_iter_apply * pp.reg_size) - 1);
    
    for (size_t i = 0; i < RANDOM_MAX_STEPS; i++)
    {   
        mask_ptr[last_byte_idx] = 0;
        if (rand_type == RANDOM_BYTE) idx_rand = dist_idx(gen);
        last_byte_idx = idx_rand;
        mask_ptr[idx_rand] = dist_u8(gen);
        masks_ptr->cur_iter = 0;
        //printf("random byte, idx: %ld, val: %u\n", idx_rand, mask_ptr[idx_rand]);

        // mutate
        TestCase ts = fuzz_one(id, pintool_args, hash2pp, pp, 2);
        mq_send(mqd, (const char *)&ts, sizeof(TestCase), 1);
        if (addr2masks.map.count(pp.addr) == 0) {
            std::vector<Masks> msk_empty;
            addr2masks.map[pp.addr] = msk_empty;
        }
        std::string fname = ts.filename;
        if (fname != ""){
            addr2masks.map[pp.addr].push_back(*masks_ptr);
        }

    }
    
}

void u8add(mqd_t &mqd, int id, PintoolArgs& pintool_args, Hash2pp& hash2pp, Masks *masks_ptr, Patchpoint& pp, Interestpp2masks &addr2masks){
    uint64_t num_iter_apply = addr2iter.map[pp.addr];
    if (num_iter_apply * pp.reg_size > 4) return;
    
    masks_ptr->num_iter = num_iter_apply;
    masks_ptr->addr = pp.addr;
    unsigned char* mask_ptr = masks_ptr->masks;
    size_t last_byte_idx = 0;
    uint8_t adder = 0;
    
    for (size_t idx = 0; idx < num_iter_apply * pp.reg_size * 256; idx++)
    {   
        mask_ptr[last_byte_idx] = 0;
        last_byte_idx = idx / 256;
        mask_ptr[last_byte_idx] = adder;
        adder++;
        if (adder % 256 == 0){
            adder = 0;
        }
        masks_ptr->cur_iter = 0;
        //printf("u8 add, idx: %ld, val: %u\n", last_byte_idx, mask_ptr[last_byte_idx]);

        // mutate
        TestCase ts = fuzz_one(id, pintool_args, hash2pp, pp, 2);
        mq_send(mqd, (const char *)&ts, sizeof(TestCase), 1);
        if (addr2masks.map.count(pp.addr) == 0) {
            std::vector<Masks> msk_empty;
            addr2masks.map[pp.addr] = msk_empty;
        }
        std::string fname = ts.filename;
        if (fname != ""){
            addr2masks.map[pp.addr].push_back(*masks_ptr);
        }
    }
    
}

void combine(mqd_t &mqd, int id, PintoolArgs& pintool_args, Hash2pp& hash2pp, Masks *masks_ptr, Patchpoint& pp, Interestpp2masks &addr2masks){
    size_t num_masks = addr2masks_global.map[pp.addr].size();
    if (num_masks <= 1) return;
    std::vector<Masks> &tmp_masks = addr2masks_global.map[pp.addr];
    uint64_t num_iter_apply = addr2iter.map[pp.addr];
    masks_ptr->num_iter = num_iter_apply;
    masks_ptr->addr = pp.addr;
    unsigned char* mask_ptr = masks_ptr->masks;
    std::random_device rd;
    std::mt19937 gen(rd()); // Mersenne Twister engine
    std::uniform_int_distribution<size_t> dist_idx;
    size_t base_idx = dist_idx(gen) % num_masks;

    for (size_t idx = 0; idx < num_masks; idx++)
    {   
        if (idx == base_idx) continue;

        // combine
        for (size_t j = 0; j < num_iter_apply * pp.reg_size; j++)
        {
            mask_ptr[j] = tmp_masks[base_idx].masks[j] ^ tmp_masks[idx].masks[j];
        }
        printf("combine: base_idx: %ld, idx: %ld\n", base_idx, idx);
        masks_ptr->cur_iter = 0;

        // mutate
        TestCase ts = fuzz_one(id, pintool_args, hash2pp, pp, 2);
        mq_send(mqd, (const char *)&ts, sizeof(TestCase), 1);
        if (addr2masks.map.count(pp.addr) == 0) {
            std::vector<Masks> msk_empty;
            addr2masks.map[pp.addr] = msk_empty;
        }
        std::string fname = ts.filename;
        if (fname != ""){
            addr2masks.map[pp.addr].push_back(*masks_ptr);
        }
    }
    
}

void mutations_2(mqd_t &mqd, int id, Patchpoint &pp, Hash2pp &hash2pp, int mut_type, size_t max_steps, Interestpp2masks &addr2masks){
    Masks *masks_ptr = (Masks *)shm_para.shm_base_ptr;
    masks_ptr += id;
    PintoolArgs pintool_args;
    
    uint64_t num_iter;
    if (addr2iter.map.count(pp.addr) == 0) {
        auto it = std::find_if(source_pps.pps.begin(), source_pps.pps.end(), [=](const Patchpoint& tmp_pp){return tmp_pp.addr == pp.addr;});
        if (it == source_pps.pps.end()) return;

        num_iter = get_iter(work_dir, std::to_string(pp.addr));
        //printf("pp: %p, iter: %ld\n", (void *)pp.addr, num_iter);
        if (num_iter == 0) {
            std::lock_guard<std::mutex> lock(source_pps.mutex);
            source_pps.pps.erase(it);
            return;
        }
        std::lock_guard<std::mutex> lock(addr2iter.mutex);
        if (addr2iter.map.count(pp.addr) == 0) addr2iter.map[pp.addr] = std::min(num_iter, (uint64_t)MAX_ITERATION);
    }
    num_iter = addr2iter.map[pp.addr];
    pintool_args["-offset"] = std::to_string(id);
    pintool_args["-num_t"] = std::to_string(NUM_THREAD);
    
    for (size_t i = 0; i < max_steps; i ++){
        memset(masks_ptr, 0, sizeof(Masks));
        switch (mut_type)
        {
        case BIT_FLIP:
            bit_flip(mqd, id, pintool_args, hash2pp, masks_ptr, pp, addr2masks);
            break;
        case BYTE_FLIP:
            byte_flip(mqd, id, pintool_args, hash2pp, masks_ptr, pp, addr2masks);
            break;
        case RANDOM_BYTE0:
            random_byte(mqd, id, pintool_args, hash2pp, masks_ptr, pp, RANDOM_BYTE0, addr2masks);
            break;
        case RANDOM_BYTE:
            random_byte(mqd, id, pintool_args, hash2pp, masks_ptr, pp, RANDOM_BYTE, addr2masks);
            break;
        case U8ADD:
            u8add(mqd, id, pintool_args, hash2pp, masks_ptr, pp, addr2masks);
            break;
        case COMBINE:
            combine(mqd, id, pintool_args, hash2pp, masks_ptr, pp, addr2masks);
            break;
        default:
            break;
        }
    }
    
}

void fuzz_candidates_1(mqd_t &mqd, int id, Pps2fuzz &selected_pps, Hash2pp &hash2pp){
    // unfuzzed patchpoints
    for (size_t i = 0; i < selected_pps.unfuzzed_pps.size(); i++){
        mutations_1(mqd, id, selected_pps.unfuzzed_pps[i], hash2pp, BYTE_FLIP, 1);
        mutations_1(mqd, id, selected_pps.unfuzzed_pps[i], hash2pp, BIT_FLIP, 1);
        mutations_1(mqd, id, selected_pps.unfuzzed_pps[i], hash2pp, U8ADD, 1);
    }
    //printf("%d: after unfuzzed\n", id);
    // interesting patchpoints
    for (size_t i = 0; i < selected_pps.interest_pps.size(); i++){
        mutations_1(mqd, id, selected_pps.interest_pps[i], hash2pp, RANDOM_BYTE0, 1);
        mutations_1(mqd, id, selected_pps.interest_pps[i], hash2pp, RANDOM_BYTE, 1);
        mutations_1(mqd, id, selected_pps.interest_pps[i], hash2pp, INJECT_VAL, 1);
        mutations_1(mqd, id, selected_pps.interest_pps[i], hash2pp, COMBINE, 1);
    }
    //printf("%d: after interest\n", id);
    // random patchpoints
    for (size_t i = 0; i < selected_pps.random_pps.size(); i++){
        mutations_1(mqd, id, selected_pps.random_pps[i], hash2pp, RANDOM_BYTE0, 1);
        mutations_1(mqd, id, selected_pps.random_pps[i], hash2pp, RANDOM_BYTE, 1);
        mutations_1(mqd, id, selected_pps.random_pps[i], hash2pp, INJECT_VAL, 1);
        mutations_1(mqd, id, selected_pps.random_pps[i], hash2pp, COMBINE, 1);
        
    }
    //printf("%d: after random\n", id);
    
}

void fuzz_candidates_2(mqd_t &mqd, int id, Pps2fuzz &selected_pps, Hash2pp &hash2pp, Interestpp2masks &addr2masks){
    // unfuzzed patchpoints
    for (size_t i = 0; i < selected_pps.unfuzzed_pps.size(); i++){
        //printf("mutate unfuzzed pps: %p\n", (void *)selected_pps.unfuzzed_pps[i].addr);
        mutations_2(mqd, id, selected_pps.unfuzzed_pps[i], hash2pp, BYTE_FLIP, 1, addr2masks);
        mutations_2(mqd, id, selected_pps.unfuzzed_pps[i], hash2pp, BIT_FLIP, 1, addr2masks);
        mutations_2(mqd, id, selected_pps.unfuzzed_pps[i], hash2pp, U8ADD, 1, addr2masks);
    }
    //printf("%d: after unfuzzed\n", id);
    // interesting patchpoints
    for (size_t i = 0; i < selected_pps.interest_pps.size(); i++){
        //printf("mutate interest pps: %p\n", (void *)selected_pps.interest_pps[i].addr);
        mutations_2(mqd, id, selected_pps.interest_pps[i], hash2pp, RANDOM_BYTE0, 1, addr2masks);
        mutations_2(mqd, id, selected_pps.interest_pps[i], hash2pp, RANDOM_BYTE, 1, addr2masks);
        mutations_2(mqd, id, selected_pps.interest_pps[i], hash2pp, COMBINE, 1, addr2masks);
    }
    //printf("%d: after interest\n", id);
    // random patchpoints
    for (size_t i = 0; i < selected_pps.random_pps.size(); i++){
        //printf("mutate random pps: %p\n", (void *)selected_pps.random_pps[i].addr);
        mutations_2(mqd, id, selected_pps.random_pps[i], hash2pp, RANDOM_BYTE0, 1, addr2masks);
        mutations_2(mqd, id, selected_pps.random_pps[i], hash2pp, RANDOM_BYTE, 1, addr2masks);
    }

}

void save_interest_pps(Hash2pp &hash2pp, StringSet &afl_files, StringSet &afl_files_hashes, Interestpp2masks &addr2masks, int level){
    std::filesystem::path afl_output_dir = "/home/proj/proj/test/afl_test1/output/default/queue/";
    std::string orig_file = "orig";
    for (const auto& file : std::filesystem::directory_iterator(afl_output_dir)){
        if (std::filesystem::is_regular_file(file.path()) && file.path().string().find(orig_file) == std::string::npos){
            if (afl_files.find(file.path().string()) != afl_files.end()){
                continue;
            }
            std::string file_hash = sha256(file.path().string());
            if (file_hash != ""){
                afl_files.insert(file.path().string());
                afl_files_hashes.insert(file_hash);
            }
        }
    }
    
    {
        std::lock_guard<std::mutex> lock(interest_pps.mutex);
        for (const auto& pair : hash2pp){
            if (afl_files_hashes.find(pair.first) != afl_files_hashes.end()){
                Patchpoint tmp_pp = pair.second;
                //printf("find interesting pps: %s, %s\n", pair.first.c_str(), addrs_str.c_str());
                std::ostringstream oss;
                oss << "[*] Find interesting pp: " << pair.first.c_str() << ", " << std::to_string(tmp_pp.addr).c_str();
                output_log(oss.str(), log_path);
                //printf("%s\n", oss.str().c_str());
                if (interest_pps.queue.size() > MAX_INTEREST_SIZE) interest_pps.queue.pop();
                interest_pps.queue.push(tmp_pp);

                if (level == 2){
                    std::lock_guard<std::mutex> lock(addr2masks_global.mutex);
                    if (addr2masks_global.map.count(tmp_pp.addr) == 0) {
                        std::vector<Masks> msk_empty;
                        addr2masks_global.map[tmp_pp.addr] = msk_empty;
                    }
                    if (addr2masks.map[tmp_pp.addr].size() > 0){
                        for (const auto &mask : addr2masks.map[tmp_pp.addr]){
                            addr2masks_global.map[tmp_pp.addr].push_back(mask);
                        }
                        addr2masks.map[tmp_pp.addr].clear();
                    }
                }
            }
        }
    }

    hash2pp.clear();
}


void *thread_worker(void* arg){
    ThreadArg *targ = (ThreadArg *)arg;
    std::string &out_dir = out_dirs[targ->tid];
    out_dir = work_dir + "/ftm_workerDir_" + std::to_string(targ->tid);
    if (!std::filesystem::exists(out_dir)){
        if (!std::filesystem::create_directories(out_dir)) {
            printf("failed to create directory in process %d\n", targ->tid);
            return nullptr;
        }
    }

    sigset_t block;
    sigemptyset(&block);
    sigaddset(&block, SIGINT);
    pthread_sigmask(SIG_BLOCK, &block, NULL);
    //printf("created dir: %s\n", out_dirs[targ->tid].c_str());
    // Patchpoints pps = find_patchpoints(out_dir);
    // Patchpoints unfuzzed_pps = pps;
    // std::random_device rd;
    // std::mt19937 gen(rd());
    // std::shuffle(unfuzzed_pps.begin(), unfuzzed_pps.end(), gen);

    Pps2fuzz pps2fuzz;
    Hash2pp hash2pp;
    StringSet afl_files;
    StringSet afl_files_hashes;
    Interestpp2masks addr2masks;
    
    mqd_t mqd = mq_open (MQNAME, O_CREAT | O_RDWR,  0600, &my_mqattr);
    if (mqd == -1){
        perror ("mq_open");
        return nullptr;
    }
    
    //sprintf(ts.filename, "From child process %d", id);
    while(1){
        generate_testcases(source_pps, source_unfuzzed_pps, pps2fuzz);
        //printf("%d: after generate testcases\n", targ->tid);
        //fuzz_candidates_1(mqd, targ->tid, pps2fuzz, hash2pp);
        fuzz_candidates_2(mqd, targ->tid, pps2fuzz, hash2pp, addr2masks);
        //printf("%d: after fuzz candidates\n", targ->tid);
        save_interest_pps(hash2pp, afl_files, afl_files_hashes, addr2masks, 2);
        //printf("%d: after save\n", targ->tid);
        
    }
    printf("oops! seems reached outside of the loop\n");
    mq_close(mqd);
    return nullptr;
}

void signal_handler(int sig){
    kill(afl_pid, SIGKILL);
    kill(worker_pid, SIGINT);
    // for (int i = 0; i < NUM_THREAD; i++){
    //     //out_dir = "/tmp/ftm_workerDir_" + std::to_string(i);
    //     //std::cout << out_dirs[i] << std::endl;
    //     if(!std::filesystem::remove_all(out_dirs[i])) printf("failed to delete dir '%s'\n", out_dirs[i].c_str());
    // }
    shmdt(shm_para.shm_base_ptr);
    mq_unlink(MQNAME);
    shmctl(shm_para.shm_id, IPC_RMID, NULL);
    printf("\nFuzztruction--: Have a nice day!\n");
    exit(0);
}

void worker_sig_handler(int sig){
    for (int i = 0; i < NUM_THREAD; i++){
        //std::cout << out_dirs[i] << std::endl;
        if (std::filesystem::exists(out_dirs[i])){
            if(!std::filesystem::remove_all(out_dirs[i])) printf("failed to delete dir '%s'\n", out_dirs[i].c_str());
        }
        
    }
    printf("worker process exited by ctrl-c\n");
    _exit(0);
}

void child_process(){
    std::string out_dir = work_dir;
    if (!find_patchpoints(out_dir, source_pps)) {
        perror("find_patchpoints() failed!\n");
        return;
    }
    // return;
    source_unfuzzed_pps.pps = source_pps.pps;
    // std::random_device rd;
    // std::mt19937 gen(rd());
    // std::shuffle(unfuzzed_pps.begin(), unfuzzed_pps.end(), gen);

    for (int i = 0; i < NUM_THREAD; i++){
        targs[i].tid = i;
        int rc = pthread_create(&threads[i], NULL, thread_worker, (void *)&targs[i]);
        if (rc) {
            perror("pthread_create()");
            _exit(-1);
        }
    }

    for (int i = 0; i < NUM_THREAD; i++){
        int rc = pthread_join(threads[i], NULL);
        if (rc) {
            perror("pthread_join()");
            _exit(-1);
        }
        printf("thread %ld exited!\n", threads[i]);

    }
}

bool init(){
    my_mqattr.mq_flags = 0;
    my_mqattr.mq_maxmsg = 10;
    my_mqattr.mq_msgsize = sizeof(TestCase);
    my_mqattr.mq_curmsgs = 0;

    new_ts_config.interest_num = 10;
    new_ts_config.unfuzzed_num = 10;
    new_ts_config.random_num = 10;
    new_ts_config.combine_num = 10;

    auto now = std::chrono::system_clock::now();
    auto duration = now.time_since_epoch();
    auto millis = std::chrono::duration_cast<std::chrono::milliseconds>(duration).count();
    std::string timestamp = std::to_string(millis);
    std::string log_dir = work_dir + "/ftm_log";
    log_path = log_dir + "/log_" + timestamp;
    if (!std::filesystem::exists(log_dir)){
        if (!std::filesystem::create_directories(log_dir)) {
            printf("failed to create directory: %s\n", log_dir.c_str());
            return false;
        }
    }

    shm_para.size_in_bytes = NUM_THREAD * sizeof(Masks);
    shm_para.key = ftok(SHM_NAME, 'A');
    shm_para.shm_id = shmget(shm_para.key, shm_para.size_in_bytes, IPC_CREAT | IPC_EXCL | 0666);
    if (shm_para.shm_id == -1){
        if (errno == EEXIST) {
            std::cout << "shared memory exists\n";
            std::cout << "recreate it\n";
            int tmp_id = shmget(shm_para.key, 0, 0);
            if (tmp_id == -1) {
                std::cerr << "shm_get failed again\n";
                return false;
            }
            if (shmctl(tmp_id, IPC_RMID, NULL) == -1){
                std::cerr << "delete failedN";
                return false;
            }
            shm_para.shm_id = shmget(shm_para.key, shm_para.size_in_bytes, IPC_CREAT | IPC_EXCL | 0666);
            if (shm_para.shm_id == -1){
                std::cerr << "recreate failed\n";
                return false;
            }
            std::cout << "recreate success\n";
        }
        else {
            std::cerr << "shared memory get failed\n";
            return false;
        }
    }
    shm_para.shm_base_ptr = (unsigned char *)shmat(shm_para.shm_id, NULL, 0);
    if (shm_para.shm_base_ptr == (void *)-1){
        std::cerr << "shmat() failed!\n";
        return false;
    }
    printf("shared memory created successfully! Size: %ld Bytes\n", shm_para.size_in_bytes);

    return true;
}

void clean_workdir(){
    for (int i = 0; i < NUM_THREAD; i++){
        if (std::filesystem::exists(out_dirs[i])){
            if(!std::filesystem::remove_all(out_dirs[i])) printf("failed to delete dir '%s'\n", out_dirs[i].c_str());
        }
    }
}

int main(){
    
    if (!init()) return -1;
    worker_pid = fork();
    if (worker_pid < 0){
        perror("fork()");
        return -1;
    }else if(worker_pid == 0){
        signal(SIGINT, worker_sig_handler);
        child_process();
        _exit(0);
    }
    // wait(NULL);
    // return 1;

    signal(SIGINT, signal_handler);
    std::vector<const char*> afl_envp;
    std::vector<const char*> afl_argv;

    afl_argv.push_back("/usr/local/bin/afl-fuzz");
    afl_argv.push_back("-i");
    afl_argv.push_back("/home/proj/proj/test/afl_test1/input");
    afl_argv.push_back("-o");
    afl_argv.push_back("/home/proj/proj/test/afl_test1/output");
    afl_argv.push_back("--");
    afl_argv.push_back("/home/proj/proj/openssl/apps/openssl");
    afl_argv.push_back("rsa");
    afl_argv.push_back("-check");
    afl_argv.push_back("-in");
    afl_argv.push_back("@@");
    afl_argv.push_back("-passin");
    afl_argv.push_back("pass:xxxxx");
    afl_argv.push_back(0);
    afl_envp.push_back("AFL_CUSTOM_MUTATOR_LIBRARY=/home/proj/proj/src/afl_customut/inject_ts_multi.so");
    afl_envp.push_back(0);

    afl_pid = fork();
    int status;
    if (afl_pid < 0){
        perror("fork()");
        return -1;
    }else if(afl_pid == 0){
        // int null_fd = open("/dev/null", O_WRONLY);
        // if (null_fd < 0) perror("failed to open /dev/null!");
        // dup2(null_fd, STDOUT_FILENO);
        // dup2(null_fd, STDERR_FILENO);
        // close(null_fd);

        execve(afl_argv[0], const_cast<char* const*>(afl_argv.data()), const_cast<char* const*>(afl_envp.data()));
        perror("execve failed!\n");
    }
    
    // child_process();
    waitpid(worker_pid, &status, 0);
    if (WIFEXITED(status)) printf("worker process with PID %ld exited with status 0x%x.\n", (long)worker_pid, WEXITSTATUS(status));
    else if (WIFSIGNALED(status)) printf("worker process with PID %ld has been terminated by signal %d .\n", (long)worker_pid, WTERMSIG(status));

    // waitpid(afl_pid, &status, 0);
    // if (WIFEXITED(status)) printf("worker process with PID %ld exited with status 0x%x.\n", (long)afl_pid, WEXITSTATUS(status));
    // else printf("afl not exited?!\n");
    kill(afl_pid, SIGKILL);
    clean_workdir();
    return 0;

}
