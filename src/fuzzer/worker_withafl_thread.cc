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
#include <openssl/evp.h>
#include <openssl/sha.h>

#define MQNAME "/TEST_MQ"
#define MAX_FILE_SIZE 16 * 1024
#define MAX_INJECTVAL 4096
#define NUM_THREAD 8
#define NUM_TESTCASE 3
#define TIMEOUT 5
#define RANDOM_MAX_TRIES 1
typedef struct patch_point{
    uint64_t addr;
    uint64_t injectValue;
    uint8_t reg_size;
} Patchpoint;
typedef struct test_case{
    char filename[255];
    Patchpoint patch_point;
}TestCase;
typedef std::vector<Patchpoint> Patchpoints;
//typedef std::vector<Patchpoints> 
typedef struct pps2fuzz{
    std::vector<Patchpoints> unfuzzed_pps;
    std::vector<Patchpoints> interest_pps;
    std::vector<Patchpoints> random_pps;
}Pps2fuzz;
typedef std::queue<Patchpoints> InterestPps;
typedef std::map<std::string, Patchpoints> Hash2pps;
typedef std::set<std::string> StringSet;
typedef struct thread_arg{
    int pid;
    int tid;
}ThreadArg;

// global variables
struct new_ts_config{
    size_t unfuzzed_num;
    size_t interest_num;
    size_t random_num;
}new_ts_config;
enum MUTATION_TYPE{
    BYTE_FLIP = 1,
    BIT_FLIP = 2,
    RANDOM_BYTE = 3,
    INJECT_VAL = 4,
    U8ADD = 5,
    RANDOM_BYTE0 = 6
};
int interest_val[] = {0, 1, 2};
struct mq_attr my_mqattr;
pid_t afl_pid;
pid_t worker_pid;
Patchpoints pps;
Patchpoints unfuzzed_pps;
std::mutex mtx1;
std::mutex log_mtx;
static volatile int timeout_flag;
pthread_t threads[NUM_THREAD];
ThreadArg targs[NUM_THREAD];
std::string out_dirs[NUM_THREAD];
std::string log_path = "";

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

Patchpoints find_patchpoints(std::string out_dir){
    Patchpoints patch_points;
    out_dir = out_dir + "/tmp_rsak";
    //std::string cmd = "LD_LIBRARY_PATH=/home/proj/proj/uninstrumented/openssl/ /home/proj/proj/tools/pin-3.28-98749-g6643ecee5-gcc-linux/pin -t /home/proj/proj/src/pintool/find_inst_sites2/obj-intel64/find_inst_sites.so -- /home/proj/proj/uninstrumented/openssl/apps/openssl genrsa -aes128 -passout pass:xxxxx -out @ 512 2>/dev/null";
    std::ostringstream oss;
    oss << "LD_LIBRARY_PATH=/home/proj/proj/uninstrumented/openssl/" << " ";
    oss << "/home/proj/proj/tools/pin-3.28-98749-g6643ecee5-gcc-linux/pin" << " ";
    oss << "-t" << " ";
    oss << "/home/proj/proj/src/pintool/find_inst_sites2/obj-intel64/find_inst_sites.so" << " ";
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

    // printf("cmd: %s\n", cmd.c_str());
    char buffer[128] = {};
    std::string result = "";

    std::shared_ptr<FILE> pipe(popen(cmd.c_str(), "r"), pclose);
    if (!pipe) throw std::runtime_error("popen() failed!");
    while (!feof(pipe.get())) {
        if (fgets(buffer, 128, pipe.get()) != NULL){
            Patchpoint pp;
            result = buffer;
            size_t del_idx = result.find(',');
            pp.addr = std::stoul(result.substr(0, del_idx), nullptr, 16); 
            pp.reg_size = (uint8_t)std::stoul(result.substr(del_idx + 1, result.length()));
            //printf("%lx, %u, %s\n", pp.addr, pp.reg_size, buffer);
            patch_points.push_back(pp);
        }
    }
    if (!std::filesystem::remove(out_dir)) perror("delete file failed\n");
    //flip_branch(patch_points);
    return patch_points;

}

void generate_testcases(Patchpoints &pps, Patchpoints &unfuzzed_pps, Pps2fuzz &selected_pps, InterestPps &interest_pps){
    selected_pps.interest_pps.clear();
    selected_pps.unfuzzed_pps.clear();
    selected_pps.random_pps.clear();

    size_t select_sum = new_ts_config.interest_num + new_ts_config.random_num + new_ts_config.unfuzzed_num;
    size_t res = select_sum;
    size_t counter = 0;
    Patchpoints tmp_pps;

    size_t select_unfuzzed = new_ts_config.unfuzzed_num * NUM_TESTCASE;
    size_t real_select;
    {
        std::lock_guard<std::mutex> lock(mtx1);
        real_select = std::min(unfuzzed_pps.size(), select_unfuzzed);
        for (size_t i = 0; i < real_select; i++){
            counter++;
            tmp_pps.push_back(unfuzzed_pps[i]);
            if (counter == NUM_TESTCASE || i == real_select - 1){
                selected_pps.unfuzzed_pps.push_back(tmp_pps);
                tmp_pps.clear();
                counter = 0;
                res--;
            }
        }
        if (!unfuzzed_pps.empty()) unfuzzed_pps.erase(unfuzzed_pps.begin(), unfuzzed_pps.begin() + real_select);
    }

    assert(counter == 0);

    size_t select_interest = new_ts_config.interest_num;
    real_select = std::min(interest_pps.size(), select_interest);
    for (size_t i = 0; i < real_select; i++){
        selected_pps.interest_pps.push_back(interest_pps.front());
        interest_pps.pop();
        res--;
    }

    std::random_device rd;
    std::mt19937 gen(rd()); // Mersenne Twister engine
    std::uniform_int_distribution<int> dist_idx(0, pps.size());
    size_t rand_ppidx;
    // FIXME: duplication between pps and unfuzzed_pps?
    real_select = std::min(pps.size(), res * NUM_TESTCASE);
    for (size_t i = 0; i < real_select; i++){
        counter++;
        rand_ppidx = dist_idx(gen);
        tmp_pps.push_back(pps[rand_ppidx]);
        if (counter == NUM_TESTCASE || i == real_select - 1){
            selected_pps.random_pps.push_back(tmp_pps);
            tmp_pps.clear();
            counter = 0;
            res--;
        }
    }

    assert(counter == 0);

    std::ostringstream oss;
    oss << "[*] Selected " << selected_pps.unfuzzed_pps.size() * NUM_TESTCASE << "/" << select_unfuzzed << " unfuzzed pps\t";
    oss << selected_pps.interest_pps.size() * NUM_TESTCASE<< "/" << select_interest * NUM_TESTCASE << " interesting pps\t";
    oss << selected_pps.random_pps.size() * NUM_TESTCASE<< "/" << res << " random pps";
    output_log(oss.str(), log_path);
    //printf("%s\n", oss.str().c_str());

}

TestCase fuzz_one(int id, std::string &addrs_str, std::string &injectValues_str, std::string &muts_str, std::string &idxes_str, Hash2pps &hash2pps, Patchpoints &pps, int level){
    // if number of pps < NUM_TESTCASE, and it's interesting, then append empty pps
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
    if (level == 1) source_argv.push_back("/home/proj/proj/src/pintool/mutate_ins_multi/obj-intel64/mutate_ins.so");
    else if (level == 2) source_argv.push_back("/home/proj/proj/src/pintool/mutate_ins_multi2/obj-intel64/mutate_ins.so");
    assert(level == 1 || level == 2);
    source_argv.push_back("-addr");
    source_argv.push_back(addrs_str.c_str());
    //source_argv.push_back("27601,926063,720785");
    source_argv.push_back("-val");
    source_argv.push_back(injectValues_str.c_str());
    //source_argv.push_back("78,114,144");
    source_argv.push_back("-mut");
    source_argv.push_back(muts_str.c_str());
    //source_argv.push_back("3,3,3");
    source_argv.push_back("-idx");
    source_argv.push_back(idxes_str.c_str());
    //source_argv.push_back("2,7,4");
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

    // printf("tid: %d, addr: %s, injectvalue: %s, %s\n", id, source_argv[4], source_argv[6], source_argv[8]);
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
        assert(setrlimit(RLIMIT_FSIZE, &limit) == 0);
        // restrict output dir?
        //assert(chdir(out_dirs[id].c_str()));
        // set timeout
        signal(SIGALRM, timeout_handler);
        alarm(TIMEOUT);
        execve(source_argv[0], const_cast<char* const*>(source_argv.data()), const_cast<char* const*>(source_envp.data()));
        perror("execve failed!");
        exit(-1);
    }

    // signal(SIGALRM, timeout_handler);
    // alarm(TIMEOUT);
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
        // testcase.patch_point.injectValue = injectValue;
        hash2pps[file_hash] = pps;

    }
    return testcase;

}

void byte_flip(mqd_t &mqd, int id, Patchpoints &pps, Hash2pps &hash2pps, int level){
    uint8_t max_reg_size = 0;
    std::string addrs_str = "", injectValues_str = "", muts_str = "", idxes_str = "";
    for (size_t i = 0; i < pps.size(); i ++){
        if (pps[i].reg_size > max_reg_size) max_reg_size = pps[i].reg_size;
        addrs_str += (std::to_string(pps[i].addr) + ",");
        injectValues_str += (std::to_string(0) + ",");
        muts_str += (std::to_string(BYTE_FLIP) + ",");
    }
    addrs_str.pop_back();
    injectValues_str.pop_back();
    muts_str.pop_back();

    if (level == 1)
    {
        for (size_t i = 0; i < max_reg_size; i ++){
            idxes_str = "";
            for(size_t j = 0; j < pps.size(); j ++){
                if (pps[j].reg_size != 0) idxes_str += (std::to_string(i % pps[j].reg_size) + ",");
                else idxes_str += (std::to_string(0) + ",");
            }
            idxes_str.pop_back();
            TestCase ts = fuzz_one(id, addrs_str, injectValues_str, muts_str, idxes_str, hash2pps, pps, level);
            mq_send(mqd, (const char *)&ts, sizeof(TestCase), 1);
        }
    }else if (level == 2){
        for(size_t j = 0; j < pps.size(); j ++){
            idxes_str += (std::to_string(0) + ",");
        }
        idxes_str.pop_back();
        TestCase ts = fuzz_one(id, addrs_str, injectValues_str, muts_str, idxes_str, hash2pps, pps, level);
        mq_send(mqd, (const char *)&ts, sizeof(TestCase), 1);
    }
}

void bit_flip(mqd_t &mqd, int id, Patchpoints &pps, Hash2pps &hash2pps, int level){
    uint8_t max_reg_size_bits = 0;
    std::string addrs_str = "", injectValues_str = "", muts_str = "", idxes_str = "";
    for (size_t i = 0; i < pps.size(); i ++){
        if (pps[i].reg_size > max_reg_size_bits) max_reg_size_bits = pps[i].reg_size;
        addrs_str += (std::to_string(pps[i].addr) + ",");
        injectValues_str += (std::to_string(0) + ",");
        muts_str += (std::to_string(BIT_FLIP) + ",");
    }
    addrs_str.pop_back();
    injectValues_str.pop_back();
    muts_str.pop_back();
    max_reg_size_bits *= 8;

    if (level == 1){
        for (size_t i = 0; i < max_reg_size_bits; i ++){
        //for (size_t i = 0; i < 8; i ++){
            idxes_str = "";
            for(size_t j = 0; j < pps.size(); j ++){
                if (pps[j].reg_size != 0) idxes_str += (std::to_string(i % (pps[j].reg_size * 8)) + ",");
                else idxes_str += (std::to_string(0) + ",");
            }
            idxes_str.pop_back();
            TestCase ts = fuzz_one(id, addrs_str, injectValues_str, muts_str, idxes_str, hash2pps, pps, level);
            mq_send(mqd, (const char *)&ts, sizeof(TestCase), 1);
        }
    }else if (level == 2){
        for(size_t j = 0; j < pps.size(); j ++){
            idxes_str += (std::to_string(0) + ",");
        }
        idxes_str.pop_back();
        TestCase ts = fuzz_one(id, addrs_str, injectValues_str, muts_str, idxes_str, hash2pps, pps, level);
        mq_send(mqd, (const char *)&ts, sizeof(TestCase), 1);
    }
}

void random_byte(mqd_t &mqd, int id, Patchpoints &pps, Hash2pps &hash2pps, int level, int random_type, size_t max_steps){
    uint8_t max_reg_size = 0;
    std::string addrs_str = "", injectValues_str = "", muts_str = "", idxes_str = "";
    
    for (size_t i = 0; i < pps.size(); i ++){
        if (pps[i].reg_size > max_reg_size) max_reg_size = pps[i].reg_size;
        addrs_str += (std::to_string(pps[i].addr) + ",");
        if (level == 1) muts_str += (std::to_string(RANDOM_BYTE) + ",");
        else muts_str += (std::to_string(random_type) + ",");
    }
    addrs_str.pop_back();
    muts_str.pop_back();

    if (level == 1){
        std::random_device rd;
        std::mt19937 gen(rd()); // Mersenne Twister engine
        std::uniform_int_distribution<uint8_t> dist_byte;
        std::uniform_int_distribution<int> dist_idx(0, max_reg_size);

        for (size_t i = 0; i < max_steps; i ++){
            injectValues_str = "";
            idxes_str = "";
            for (size_t j = 0; j < pps.size(); j ++){
                if (pps[j].reg_size != 0 && random_type == RANDOM_BYTE) idxes_str += (std::to_string(dist_idx(gen) % pps[j].reg_size) + ",");
                else idxes_str += (std::to_string(0) + ",");
                injectValues_str += (std::to_string(dist_byte(gen)) + ",");
            }
            idxes_str.pop_back();
            injectValues_str.pop_back();
            TestCase ts = fuzz_one(id, addrs_str, injectValues_str, muts_str, idxes_str, hash2pps, pps, level);
            mq_send(mqd, (const char *)&ts, sizeof(TestCase), 1);
        }
    }else if (level == 2){
        for (size_t j = 0; j < pps.size(); j ++){
            idxes_str += (std::to_string(0) + ",");
            injectValues_str += (std::to_string(0) + ",");
        }
        idxes_str.pop_back();
        injectValues_str.pop_back();

        for (size_t i = 0; i < max_steps; i ++){
            TestCase ts = fuzz_one(id, addrs_str, injectValues_str, muts_str, idxes_str, hash2pps, pps, level);
            mq_send(mqd, (const char *)&ts, sizeof(TestCase), 1);
        }
    }
    
}

void u8_add(mqd_t &mqd, int id, Patchpoints &pps, Hash2pps &hash2pps){
    std::string addrs_str = "", injectValues_str = "", muts_str = "", idxes_str = "";
    for (size_t i = 0; i < pps.size(); i ++){
        addrs_str += (std::to_string(pps[i].addr) + ",");
        injectValues_str += (std::to_string(0) + ",");
        muts_str += (std::to_string(U8ADD) + ",");
        idxes_str += (std::to_string(0) + ",");
    }
    addrs_str.pop_back();
    injectValues_str.pop_back();
    muts_str.pop_back();
    idxes_str.pop_back();
    TestCase ts = fuzz_one(id, addrs_str, injectValues_str, muts_str, idxes_str, hash2pps, pps, 2);
    mq_send(mqd, (const char *)&ts, sizeof(TestCase), 1);

}

// void mix_mutations(mqd_t &mqd, int id, Patchpoints &pps, Hash2pps &hash2pps){

// }

void fuzz_candidates(mqd_t &mqd, int id, Pps2fuzz &selected_pps, Hash2pps &hash2pps, int level){
    // unfuzzed patchpoints
    for (size_t i = 0; i < selected_pps.unfuzzed_pps.size(); i++){
        byte_flip(mqd, id, selected_pps.unfuzzed_pps[i], hash2pps, level);
        bit_flip(mqd, id, selected_pps.unfuzzed_pps[i], hash2pps, level);
        random_byte(mqd, id, selected_pps.unfuzzed_pps[i], hash2pps, level, RANDOM_BYTE, RANDOM_MAX_TRIES);
        random_byte(mqd, id, selected_pps.unfuzzed_pps[i], hash2pps, level, RANDOM_BYTE0, RANDOM_MAX_TRIES);
        u8_add(mqd, id, selected_pps.unfuzzed_pps[i], hash2pps);

        //inject_value();
    }
    //printf("%d: after unfuzzed\n", id);
    // interesting patchpoints
    for (size_t i = 0; i < selected_pps.interest_pps.size(); i++){
        random_byte(mqd, id, selected_pps.interest_pps[i], hash2pps, level, RANDOM_BYTE, RANDOM_MAX_TRIES);
        random_byte(mqd, id, selected_pps.interest_pps[i], hash2pps, level, RANDOM_BYTE0, RANDOM_MAX_TRIES);
    }
    //printf("%d: after interest\n", id);
    // random patchpoints
    for (size_t i = 0; i < selected_pps.random_pps.size(); i++){
        byte_flip(mqd, id, selected_pps.random_pps[i], hash2pps, level);
        bit_flip(mqd, id, selected_pps.random_pps[i], hash2pps, level);
        random_byte(mqd, id, selected_pps.random_pps[i], hash2pps, level, RANDOM_BYTE, RANDOM_MAX_TRIES);
        random_byte(mqd, id, selected_pps.random_pps[i], hash2pps, level, RANDOM_BYTE0, RANDOM_MAX_TRIES);
        u8_add(mqd, id, selected_pps.random_pps[i], hash2pps);
    }
    //printf("%d: after random\n", id);
    
}

// std::vector<std::string> get_tokens(std::string args, std::string del){
//     size_t pos_s = 0;
//     size_t pos_e;
//     std::string token;
//     std::vector<std::string> vec;
//     while((pos_e = args.find(del, pos_s)) != std::string::npos){
//         token = args.substr(pos_s, pos_e - pos_s);
//         pos_s = pos_e + del.length();
//         vec.push_back(token);
//     }
//     vec.push_back(args.substr(pos_s));
//     return vec;

//     // std::istringstream iss(args);
//     // std::string token;
//     // std::vector<std::string> tokens;
//     // while(std::getline(iss, token, ',')){
//     //     tokens.push_back(token);
//     // }
//     // return tokens;
// }

void save_interest_pps(InterestPps &interest_pps, Hash2pps &hash2pps, StringSet &afl_files, StringSet &afl_files_hashes){
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
    
    int pps_cnt = 0;
    for (const auto& pair : hash2pps){
        if (afl_files_hashes.find(pair.first) != afl_files_hashes.end()){
            Patchpoints tmp_pps = pair.second;
            std::string addrs_str  = "";
            for (size_t i = 0; i < tmp_pps.size(); i++)
            {  
                addrs_str += (std::to_string(tmp_pps[i].addr) + ",");
            }
            addrs_str.pop_back();
            //printf("find interesting pps: %s, %s\n", pair.first.c_str(), addrs_str.c_str());
            std::ostringstream oss;
            oss << "[*] Find interesting pps: " << pair.first.c_str() << ", " << addrs_str.c_str();
            output_log(oss.str(), log_path);
            //printf("%s\n", oss.str().c_str());

            interest_pps.push(tmp_pps);

        }
    }

    hash2pps.clear();
    // std::ostringstream oss;
    // oss << "[*] Saved " << pps_cnt <<" interesting pps; " << "current interesting pps: " << insterest_pps.size();
    // output_log(oss.str(), log_path);

}


void *thread_worker(void* arg){
    ThreadArg *targ = (ThreadArg *)arg;
    std::string &out_dir = out_dirs[targ->tid];
    out_dir = "/tmp/ftm_workerDir_" + std::to_string(targ->tid);
    if (!std::filesystem::exists(out_dir)){
        if (!std::filesystem::create_directory(out_dir)) {
            printf("failed to create directory in process %d\n", targ->tid);
            return nullptr;
        }
    }
    //printf("created dir: %s\n", out_dirs[targ->tid].c_str());
    // Patchpoints pps = find_patchpoints(out_dir);
    // Patchpoints unfuzzed_pps = pps;
    // std::random_device rd;
    // std::mt19937 gen(rd());
    // std::shuffle(unfuzzed_pps.begin(), unfuzzed_pps.end(), gen);

    InterestPps insterest_pps;
    Pps2fuzz pps2fuzz;
    Hash2pps hash2pps;
    StringSet afl_files;
    StringSet afl_files_hashes;
    
    mqd_t mqd = mq_open (MQNAME, O_CREAT | O_RDWR,  0600, &my_mqattr);
    if (mqd == -1){
        perror ("mq_open");
        return nullptr;
    }
    
    //sprintf(ts.filename, "From child process %d", id);
    while(1){
        generate_testcases(pps, unfuzzed_pps, pps2fuzz, insterest_pps);
        //printf("%d: after generate testcases\n", targ->tid);
        //TestCase ts = generate_testcase(targ->tid, pps);
        fuzz_candidates(mqd, targ->tid, pps2fuzz, hash2pps, 2);
        //printf("%d: after fuzz candidates\n", targ->tid);
        //mq_send(mqd, (const char *)&ts, sizeof(TestCase), 1);
        //printf("%d: before save\n", targ->tid);
        save_interest_pps(insterest_pps, hash2pps, afl_files, afl_files_hashes);
        //printf("%d: after save\n", targ->tid);
        
    }
    printf("oops! seems reached outside of the loop\n");
    mq_close(mqd);
    //mq_unlink(MQNAME);
    if (out_dir != ""){
        if(!std::filesystem::remove_all(out_dir)) printf("failed to delete dir '%s'\n", out_dir.c_str());
    }
    return nullptr;
}

void signal_handler(int sig){
    // for (int i = 0; i < NUM_PROC; i++){
    //     kill(pids[i], SIGKILL);
    // }
    kill(afl_pid, SIGKILL);
    kill(worker_pid, SIGINT);
    // for (int i = 0; i < NUM_THREAD; i++){
    //     //out_dir = "/tmp/ftm_workerDir_" + std::to_string(i);
    //     //std::cout << out_dirs[i] << std::endl;
    //     if(!std::filesystem::remove_all(out_dirs[i])) printf("failed to delete dir '%s'\n", out_dirs[i].c_str());
    // }
    
    mq_unlink(MQNAME);
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
    printf("worker process exited!\n");
    _exit(0);
}

void child_process(){
    std::string out_dir = "/tmp";
    pps = find_patchpoints(out_dir);
    unfuzzed_pps = pps;
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

void init(){
    my_mqattr.mq_flags = 0;
    my_mqattr.mq_maxmsg = 10;
    my_mqattr.mq_msgsize = sizeof(TestCase);
    my_mqattr.mq_curmsgs = 0;

    new_ts_config.interest_num = 10;
    new_ts_config.unfuzzed_num = 10;
    new_ts_config.random_num = 10;

    auto now = std::chrono::system_clock::now();
    auto duration = now.time_since_epoch();
    auto millis = std::chrono::duration_cast<std::chrono::milliseconds>(duration).count();
    std::string timestamp = std::to_string(millis);
    log_path = "/tmp/ftm_log/log_" + timestamp;
    std::string log_dir = "/tmp/ftm_log";
    if (!std::filesystem::exists(log_dir)){
        if (!std::filesystem::create_directory(log_dir)) {
            printf("failed to create directory: %s\n", log_dir.c_str());
            exit(-1);
        }
    }

    return;
}

int main(){
    
    init();
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

    waitpid(afl_pid, &status, 0);
    if (WIFEXITED(status)) printf("worker process with PID %ld exited with status 0x%x.\n", (long)afl_pid, WEXITSTATUS(status));
    else printf("afl not exited?!\n");
    return 0;

}
