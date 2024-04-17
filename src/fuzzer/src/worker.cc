#include "include/worker.h"

#include <iostream>
#include <fstream>
#include <sstream>
#include <memory>
#include <random>
#include <chrono>
#include <filesystem>
#include <fcntl.h>
#include <string.h>

#include <sys/wait.h>
#include <sys/resource.h>
#include <openssl/evp.h>
#include <openssl/sha.h>

enum MUTATION_TYPE{
    BYTE_FLIP = 0,
    BIT_FLIP,
    RANDOM_BYTE,
    RANDOM_BYTE0,
    U8ADD,
    INJECT_VAL,
    COMBINE,
    HAVOC
};

Worker::Worker(int _id, int _level) : id(_id), level(_level) { 
    masks_ptr = nullptr;
}
Worker::~Worker(){}

std::string Worker::sha256(const std::string &file_path){
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

void Worker::output_log(const std::string& msg){
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

size_t Worker::get_iter(std::string out_dir, std::string addr_str){
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
    size_t iter_num = 0;

    std::shared_ptr<FILE> pipe(popen(cmd.c_str(), "r"), pclose);
    if (!pipe) throw std::runtime_error("popen() failed!");
    while (fgets(buffer, 128, pipe.get()) != nullptr) {
        result = buffer;
        size_t del_idx = result.find(',');
        iter_num = std::stoul(result.substr(del_idx + 1, result.length()));
        //printf("0x%s, %lu\n", addr.c_str(), hits);
    }

    if (!std::filesystem::remove(out_dir)) perror("get_iter: delete file failed\n");
    return iter_num;
}

void Worker::generate_testcases(){
    selected_pps.interest_pps.clear();
    selected_pps.unfuzzed_pps.clear();
    selected_pps.random_pps.clear();

    size_t res = new_selection_config.interest_num + new_selection_config.random_num + new_selection_config.unfuzzed_num;
    size_t real_select;
    std::random_device rd;
    std::mt19937 gen(rd()); // Mersenne Twister engine
    std::ostringstream oss;

    if (!source_unfuzzed_pps.pps.empty()){
        std::lock_guard<std::mutex> lock(source_unfuzzed_pps.mutex);
        real_select = std::min(source_unfuzzed_pps.pps.size(), new_selection_config.unfuzzed_num);
        for (size_t i = 0; i < real_select; i++){
            selected_pps.unfuzzed_pps.push_back(source_unfuzzed_pps.pps[i]);
            res--;
        }
        source_unfuzzed_pps.pps.erase(source_unfuzzed_pps.pps.begin(), source_unfuzzed_pps.pps.begin() + real_select);
        oss << "[*] Selected " << selected_pps.unfuzzed_pps.size() << "/" << new_selection_config.unfuzzed_num << " unfuzzed pps\t";
    }else{
        oss << "[*] Selected " << "0/0" << " unfuzzed pps\t";
    }

    {
        std::lock_guard<std::mutex> lock(interest_pps.mutex);
        real_select = std::min(interest_pps.set.size(), new_selection_config.interest_num);
        std::vector<Patchpoint> tmp_vec(interest_pps.set.begin(), interest_pps.set.end());
        std::shuffle(tmp_vec.begin(), tmp_vec.end(), gen);
        for (size_t i = 0; i < real_select; i++){
            selected_pps.interest_pps.push_back(tmp_vec[i]);
            res--;
        }
    }
    oss << selected_pps.interest_pps.size() << "/" << new_selection_config.interest_num << " interesting pps\t";
    
    if (source_unfuzzed_pps.pps.empty())
    {   
        std::lock_guard<std::mutex> lock(source_pps.mutex);
        std::uniform_int_distribution<size_t> dist_idx(0, source_pps.pps.size() - 1);
        real_select = std::min(source_pps.pps.size(), res);
        for (size_t i = 0; i < real_select; i++){
            selected_pps.random_pps.push_back(source_pps.pps[dist_idx(gen)]);
        }
    }

    oss << selected_pps.random_pps.size() << "/" << new_selection_config.random_num << " random pps";

    output_log(oss.str());
    //printf("%s\n", oss.str().c_str());
}

TestCase Worker::fuzz_one(PintoolArgs& pintool_args, Patchpoint &pp){
    auto now = std::chrono::system_clock::now();
    auto duration = now.time_since_epoch();
    auto millis = std::chrono::duration_cast<std::chrono::milliseconds>(duration).count();
    std::string timestamp = std::to_string(millis);
    std::string out_file = work_dir + "/rsak_" + std::to_string(id) + "_" + timestamp;
    std::vector<const char*> source_argv;
    std::vector<const char*> source_envp;
    TestCase testcase;
    memset(testcase.filename, 0, sizeof(testcase.filename));

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
    source_pids[id] = pid;

    if (pid == -1){
        perror("fork failed!\n");
        return testcase;
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
        if (chdir(work_dir.c_str()) != 0) perror("chdir() failed!\n");
        // set timeout
        alarm(SOURCE_TIMEOUT);
        execve(source_argv[0], const_cast<char* const*>(source_argv.data()), const_cast<char* const*>(source_envp.data()));
        perror("execve failed!");
        exit(EXIT_FAILURE);
    }

    int status;
    waitpid(pid, &status, 0);
    if (WIFSIGNALED(status) && WTERMSIG(status) == SIGALRM){
        printf("timeout occured!\n");
        kill(pid, SIGKILL);
        waitpid(pid, &status, 0);
    }
    source_pids[id] = -1;

    bool fail = false;
    std::ifstream mutated_output(out_file);
    if (!mutated_output){
        //std::cout << "mutated output file open failed\n";
        fail = true;
    }else if(std::filesystem::file_size(out_file) == 0){
        //std::cout << "mutated output file is empty\n";
        if(!std::filesystem::remove(out_file)) printf("failed to delete file '%s'\n", out_file.c_str());
        fail = true;
    }else{
        //std::cout << "mutated output file is exist!\n";
        fail = false;
    }
    
    if (!fail){
        std::string file_hash = sha256(out_file);
        // std::string out_file_hash = out_dirs[id] + "/" + file_hash;
        // if (std::rename(out_file.c_str(), out_file_hash.c_str()) == 0){
        //     strncpy(testcase.filename, out_file_hash.c_str(), sizeof(testcase.filename));
        // }else{
        //     perror("rename()");
        //     strncpy(testcase.filename, out_file.c_str(), sizeof(testcase.filename));
        // }
        //printf("new_filename: %s\n", testcase.filename);
        strncpy(testcase.filename, out_file.c_str(), sizeof(testcase.filename));
        testcase.filename[sizeof(testcase.filename) - 1] = 0;
        strncpy(testcase.filehash, file_hash.c_str(), 64);
        testcase.filehash[64] = 0;
        testcase.patch_point.addr = pp.addr;
        testcase.patch_point.reg_size = pp.reg_size;
        hash2pp[file_hash] = pp;
    }
    return testcase;
}

void Worker::mutations_1(Patchpoint &pp, int mut_type, size_t max_steps){
    PintoolArgs pintool_args;
    pintool_args["-addr"] = std::to_string(pp.addr);
    pintool_args["-mut"] = std::to_string(mut_type);

    for (size_t i = 0; i < max_steps; i ++){
        TestCase ts = fuzz_one(pintool_args, pp);
        mq_send(mqd, (const char *)&ts, sizeof(TestCase), 1);
    }
}

void Worker::bit_flip(PintoolArgs& pintool_args, Patchpoint& pp){
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
        TestCase ts = fuzz_one(pintool_args, pp);
        mq_send(mqd, (const char *)&ts, sizeof(TestCase), 1);
        std::string fname = ts.filename;
        if (fname != ""){
            if (addr2masks.count(pp.addr) == 0) {
                std::map<std::string, Masks> hash2msk_empty;
                addr2masks[pp.addr] = hash2msk_empty;
            }
            addr2masks[pp.addr][ts.filehash] = *masks_ptr;
        }
    }
    
}

void Worker::byte_flip(PintoolArgs& pintool_args, Patchpoint& pp){
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
        TestCase ts = fuzz_one(pintool_args, pp);
        mq_send(mqd, (const char *)&ts, sizeof(TestCase), 1);
        std::string fname = ts.filename;
        if (fname != ""){
            if (addr2masks.count(pp.addr) == 0) {
                std::map<std::string, Masks> hash2msk_empty;
                addr2masks[pp.addr] = hash2msk_empty;
            }
            addr2masks[pp.addr][ts.filehash] = *masks_ptr;
        }
        
    }
    
}

void Worker::random_byte(PintoolArgs& pintool_args, Patchpoint& pp, int rand_type){
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
    
    for (size_t i = 0; i < MAX_RANDOM_STEPS; i++)
    {   
        mask_ptr[last_byte_idx] = 0;
        idx_rand = dist_idx(gen);
        if (rand_type == RANDOM_BYTE0) idx_rand = (idx_rand / pp.reg_size) * pp.reg_size;
        last_byte_idx = idx_rand;
        mask_ptr[idx_rand] = dist_u8(gen);
        masks_ptr->cur_iter = 0;
        //printf("random byte, idx: %ld, val: %u\n", idx_rand, mask_ptr[idx_rand]);

        // mutate
        TestCase ts = fuzz_one(pintool_args, pp);
        mq_send(mqd, (const char *)&ts, sizeof(TestCase), 1);
        std::string fname = ts.filename;
        if (fname != ""){
            if (addr2masks.count(pp.addr) == 0) {
                std::map<std::string, Masks> hash2msk_empty;
                addr2masks[pp.addr] = hash2msk_empty;
            }
            addr2masks[pp.addr][ts.filehash] = *masks_ptr;
        }

    }
    
}

void Worker::u8add(PintoolArgs& pintool_args, Patchpoint& pp){
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
        TestCase ts = fuzz_one(pintool_args, pp);
        mq_send(mqd, (const char *)&ts, sizeof(TestCase), 1);
        std::string fname = ts.filename;
        if (fname != ""){
            if (addr2masks.count(pp.addr) == 0) {
                std::map<std::string, Masks> hash2msk_empty;
                addr2masks[pp.addr] = hash2msk_empty;
            }
            addr2masks[pp.addr][ts.filehash] = *masks_ptr;
        }
    }
    
}

void Worker::combine(PintoolArgs& pintool_args, Patchpoint& pp){
    size_t num_masks;
    std::vector<Masks> tmp_masks;
    {   
        std::lock_guard<std::mutex> lock(addr2masks_global.mutex);
        num_masks = addr2masks_global.map[pp.addr].size();
        tmp_masks = addr2masks_global.map[pp.addr];
    }
    if (num_masks <= 1) return;
    
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
        std::ostringstream oss;
        oss << "combine: " << std::hex << ", " << "addr: " << pp.addr << ", " << "base_idx: " << base_idx << ", " << "idx: " << idx;
        output_log(oss.str());
        //printf("combine: addr: %p, base_idx: %ld, idx: %ld\n", pp.addr, base_idx, idx);
        masks_ptr->cur_iter = 0;

        // mutate
        TestCase ts = fuzz_one(pintool_args, pp);
        mq_send(mqd, (const char *)&ts, sizeof(TestCase), 1);
        std::string fname = ts.filename;
        if (fname != ""){
            if (addr2masks.count(pp.addr) == 0) {
                std::map<std::string, Masks> hash2msk_empty;
                addr2masks[pp.addr] = hash2msk_empty;
            }
            addr2masks[pp.addr][ts.filehash] = *masks_ptr;
        }
    }
    
}

void Worker::havoc(PintoolArgs& pintool_args, Patchpoint& pp){
    uint64_t num_iter_apply = addr2iter.map[pp.addr];
    masks_ptr->num_iter = num_iter_apply;
    masks_ptr->addr = pp.addr;
    unsigned char* mask_ptr = masks_ptr->masks;

    size_t idx_rand = 0, mut_rand;
    std::random_device rd;
    std::mt19937 gen(rd()); // Mersenne Twister engine
    std::uniform_int_distribution<uint8_t> dist_u8;
    std::uniform_int_distribution<uint64_t> dist_idx(0, (num_iter_apply * pp.reg_size) - 1);
    std::uniform_int_distribution<uint64_t> dist_mut(0, 2);
    
    for (size_t i = 0; i < MAX_HAVOC_STEPS; i++)
    {   
        memset(mask_ptr, 0, (MAX_ITERATION + 1) * MAX_REG_SIZE);
        for (size_t j = 0; j < HAVOC_FUSION_STEPS; j++)
        { 
            mut_rand = dist_mut(gen);
            idx_rand = dist_idx(gen);
            if (mut_rand == 0){// rand byte flip
                mask_ptr[idx_rand] ^= 0xff;
            }else if (mut_rand == 1){// rand bit flip
                mask_ptr[idx_rand / 8] ^= 1 << (idx_rand % 8);
            }else if (mut_rand == 2){// rand byte
                mask_ptr[idx_rand] = dist_u8(gen);
            }
            masks_ptr->cur_iter = 0;
            //printf("random byte, idx: %ld, val: %u\n", idx_rand, mask_ptr[idx_rand]);

            // mutate
            TestCase ts = fuzz_one(pintool_args, pp);
            mq_send(mqd, (const char *)&ts, sizeof(TestCase), 1);
            std::string fname = ts.filename;
            if (fname != ""){
                if (addr2masks.count(pp.addr) == 0) {
                    std::map<std::string, Masks> hash2msk_empty;
                    addr2masks[pp.addr] = hash2msk_empty;
                }
                addr2masks[pp.addr][ts.filehash] = *masks_ptr;
            }else{
                // revert mutation that will cause a crash
                memset(mask_ptr, 0, (MAX_ITERATION + 1) * MAX_REG_SIZE);
            }
        }
    }
    
}

void Worker::mutations_2(Patchpoint &pp, int mut_type, size_t max_steps){
    PintoolArgs pintool_args;
    uint64_t num_iter;

    if (addr2iter.map.count(pp.addr) == 0) {
        Patchpoints::iterator it;
        {   
            std::lock_guard<std::mutex> lock(source_pps.mutex);
            it = std::find_if(source_pps.pps.begin(), source_pps.pps.end(), [=](const Patchpoint& tmp_pp){return tmp_pp.addr == pp.addr;});
            if (it == source_pps.pps.end()) return;
        }

        num_iter = get_iter(work_dir, std::to_string(pp.addr));
        //printf("pp: %p, iter: %ld\n", (void *)pp.addr, num_iter);
        if (num_iter == 0) {
            std::lock_guard<std::mutex> lock(source_pps.mutex);
            if (it != source_pps.pps.end()) if ((*it).addr == pp.addr) source_pps.pps.erase(it);
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
            bit_flip(pintool_args, pp);
            break;
        case BYTE_FLIP:
            byte_flip(pintool_args, pp);
            break;
        case RANDOM_BYTE0:
            random_byte(pintool_args, pp, RANDOM_BYTE0);
            break;
        case RANDOM_BYTE:
            random_byte(pintool_args, pp, RANDOM_BYTE);
            break;
        case U8ADD:
            u8add(pintool_args, pp);
            break;
        case COMBINE:
            combine(pintool_args, pp);
            break;
        case HAVOC:
            havoc(pintool_args, pp);
            break;
        default:
            break;
        }
    }
    
}

void Worker::fuzz_candidates_1(){
    // unfuzzed patchpoints
    for (size_t i = 0; i < selected_pps.unfuzzed_pps.size(); i++){
        mutations_1(selected_pps.unfuzzed_pps[i], BYTE_FLIP, 1);
        mutations_1(selected_pps.unfuzzed_pps[i], BIT_FLIP, 1);
        mutations_1(selected_pps.unfuzzed_pps[i], U8ADD, 1);
    }
    //printf("%d: after unfuzzed\n", id);
    // interesting patchpoints
    for (size_t i = 0; i < selected_pps.interest_pps.size(); i++){
        mutations_1(selected_pps.interest_pps[i], RANDOM_BYTE0, 1);
        mutations_1(selected_pps.interest_pps[i], RANDOM_BYTE, 1);
        mutations_1(selected_pps.interest_pps[i], INJECT_VAL, 1);
        mutations_1(selected_pps.interest_pps[i], COMBINE, 1);
    }
    //printf("%d: after interest\n", id);
    // random patchpoints
    for (size_t i = 0; i < selected_pps.random_pps.size(); i++){
        mutations_1(selected_pps.random_pps[i], RANDOM_BYTE0, 1);
        mutations_1(selected_pps.random_pps[i], RANDOM_BYTE, 1);
        mutations_1(selected_pps.random_pps[i], INJECT_VAL, 1);
        mutations_1(selected_pps.random_pps[i], COMBINE, 1);
        
    }
    //printf("%d: after random\n", id);
    
}

void Worker::fuzz_candidates_2(){
    // unfuzzed patchpoints
    for (size_t i = 0; i < selected_pps.unfuzzed_pps.size(); i++){
        //printf("mutate unfuzzed pps: %p\n", (void *)selected_pps.unfuzzed_pps[i].addr);
        //mutations_2(selected_pps.unfuzzed_pps[i], BYTE_FLIP, 1);
        //mutations_2(selected_pps.unfuzzed_pps[i], BIT_FLIP, 1);
        //mutations_2(selected_pps.unfuzzed_pps[i], U8ADD, 1);
        mutations_2(selected_pps.unfuzzed_pps[i], RANDOM_BYTE, 1);
        mutations_2(selected_pps.unfuzzed_pps[i], RANDOM_BYTE0, 1);
    }
    //printf("%d: after unfuzzed\n", id);
    // interesting patchpoints
    for (size_t i = 0; i < selected_pps.interest_pps.size(); i++){
        //printf("mutate interest pps: %p\n", (void *)selected_pps.interest_pps[i].addr);
        mutations_2(selected_pps.interest_pps[i], RANDOM_BYTE0, 1);
        mutations_2(selected_pps.interest_pps[i], RANDOM_BYTE, 1);
        mutations_2(selected_pps.interest_pps[i], COMBINE, 1);
        mutations_2(selected_pps.interest_pps[i], HAVOC, 1);
    }
    //printf("%d: after interest\n", id);
    // random patchpoints
    for (size_t i = 0; i < selected_pps.random_pps.size(); i++){
        //printf("mutate random pps: %p\n", (void *)selected_pps.random_pps[i].addr);
        mutations_2(selected_pps.random_pps[i], RANDOM_BYTE0, 1);
        mutations_2(selected_pps.random_pps[i], RANDOM_BYTE, 1);
        mutations_2(selected_pps.random_pps[i], HAVOC, 1);
    }

}

void Worker::save_interest_pps(){
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
                output_log(oss.str());
                //printf("%s\n", oss.str().c_str());
                interest_pps.set.insert(tmp_pp);

                if (level == 2){
                    std::lock_guard<std::mutex> lock(addr2masks_global.mutex);
                    if (addr2masks_global.map.count(tmp_pp.addr) == 0) {
                        std::vector<Masks> msk_empty;
                        addr2masks_global.map[tmp_pp.addr] = msk_empty;
                    }
                    addr2masks_global.map[tmp_pp.addr].push_back(addr2masks[tmp_pp.addr][pair.first]);
                }
            }
        }
    }
    addr2masks.clear();
    hash2pp.clear();
}

void Worker::start(){
    // create worker dir in ftmm_dir
    work_dir = ftmm_dir + "/ftm_workerDir_" + std::to_string(id);
    if (!std::filesystem::exists(work_dir)){
        if (!std::filesystem::create_directories(work_dir)) {
            printf("failed to create directory in process %d\n", id);
            return;
        }
    }

    // point to its Masks entry in shared memory
    masks_ptr = (Masks *)shm_para.shm_base_ptr;
    masks_ptr += id;

    // block SIGINT signal
    sigset_t block;
    sigemptyset(&block);
    sigaddset(&block, SIGINT);
    pthread_sigmask(SIG_BLOCK, &block, NULL);

    // open message queue
    mqd = mq_open (MQNAME, O_CREAT | O_RDWR,  0600, &my_mqattr);
    if (mqd == -1){
        perror ("mq_open");
        return;
    }

    // main loop of worker
    while(1){
        generate_testcases();
        //printf("%d: after generate testcases\n", id);
        if (level == 1) fuzz_candidates_1();
        else if(level == 2) fuzz_candidates_2();
        //printf("%d: after fuzz candidates\n", id);
        save_interest_pps();
        //printf("%d: after save\n", id);
        
    }
    
    mq_close(mqd);
    printf("Worker %d exited!\n", id);
    return;
}