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
    HAVOC,
    BYTE_FLIP_MULTI,
    BIT_FLIP_MULTI,
    RANDOM_BYTE_MULTI,
    RANDOM_BYTE0_MULTI,
    U8ADD_MULTI,
    HAVOC_MULTI
};

Worker::Worker(int _id) : id(_id) { 

    cur_mut_counter = 0;
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

size_t Worker::get_iter(std::string out_dir, std::string addr_str, bool check_ptr, bool &is_pointer){
    std::string source_out = out_dir + "/tmp_get_iter";
    std::string get_iter_out = out_dir + "/tmp_pintool";
    std::ostringstream oss;

    for (const auto &e : source_config.env)
    {
        oss << e << " ";
    }
    oss << "/home/proj/proj/tools/pin-3.28-98749-g6643ecee5-gcc-linux/pin" << " ";
    oss << "-t" << " ";
    oss << "/home/proj/proj/src/pintool/get_iter_num/obj-intel64/get_iter_num.so" << " ";
    oss << "-addr" << " ";
    oss << addr_str << " ";
    oss << "-o" << " ";
    oss << get_iter_out << " ";
    oss << "-p" << " ";
    if (check_ptr) oss << "1" << " ";
    else oss << "0" << " ";
    oss << "--" << " ";
    oss << source_config.bin_path << " ";
    for (const auto &a : source_config.args)
    {   
        if (a == "@@"){
            oss << source_out << " ";
        }else{
            oss << a << " ";
        }
    }
    oss << ">/dev/null 2>&1" << " ";

    std::string cmd = oss.str();
    //printf("get_iter cmd: %s\n", cmd.c_str());
    if (system(cmd.c_str()) != 0) return 0;
    std::ifstream file(get_iter_out);
    std::string result = "";
    std::getline(file, result);
    size_t del_idx = 0;

    result = result.substr(result.find(',') + 1, result.length());
    del_idx = result.find(',');
    size_t iter_num = std::stoul(result.substr(0, del_idx));
    size_t p_count = std::stoul(result.substr(del_idx + 1, result.length()));
    printf("%s,%p,%lu,%lu\n", result.c_str(), (void *)std::stoul(addr_str), iter_num, p_count);
    if (p_count != 0) is_pointer = true;
    else is_pointer = false;

    if (!std::filesystem::remove(source_out)) std::cerr << "get_iter: delete file failed\n";
    if (!std::filesystem::remove(get_iter_out)) std::cerr << "get_iter: delete file failed\n";
    return iter_num;
}

bool Worker::pp_valid_check(Patchpoint &pp){
    size_t num_iter = 0;
    bool check_ptr = false, is_pointer = false;

    std::lock_guard<std::mutex> lock(addr2iter.mutex);
    if (addr2iter.map.count(pp.addr) == 0) {
        if (pp.reg_size == 8) check_ptr = true;
        num_iter = get_iter(work_dir, std::to_string(pp.addr), check_ptr, is_pointer);
        //printf("pp: %p, iter: %ld\n", (void *)pp.addr, num_iter);
        addr2iter.map[pp.addr] = std::min(num_iter, (uint64_t)MAX_ITERATION);
        addr2iter.chk_ptr_map[pp.addr] = is_pointer;
    }
    /// hit is not 0 and the value is not a pointer
    return (addr2iter.map[pp.addr] != 0) && (addr2iter.chk_ptr_map[pp.addr] == false);
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
        oss << "[*] Id: " << id << " Selected " << selected_pps.unfuzzed_pps.size() << "/" << new_selection_config.unfuzzed_num << " unfuzzed pps, ";
    }else{
        oss << "[*] Id: " << id << " Selected " << "0/0" << " unfuzzed pps, ";
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
    oss << selected_pps.interest_pps.size() << "/" << new_selection_config.interest_num << " interesting pps, ";
    
    if (source_unfuzzed_pps.pps.empty())
    {   
        std::lock_guard<std::mutex> lock(source_pps.mutex);
        //std::uniform_int_distribution<size_t> dist_idx(0, source_pps.pps.size() - 1);
        real_select = std::min(source_pps.pps.size(), res);
        Patchpoints tmp_source_pps = source_pps.pps;
        std::shuffle(tmp_source_pps.begin(), tmp_source_pps.end(), gen);
        
        for (size_t i = 0; i < real_select; i++){
            selected_pps.random_pps.push_back(tmp_source_pps[i]);
            //selected_pps.random_pps.push_back(source_pps.pps[dist_idx(gen)]);
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
    if (level == 1) source_argv.push_back("/home/proj/proj/src/pintool/mutate_ins_one/obj-intel64/mutate_ins.so");
    else if (level == 2) source_argv.push_back("/home/proj/proj/src/pintool/mutate_ins_multi2/obj-intel64/mutate_ins.so");
    for (const auto& arg : pintool_args){
        source_argv.push_back(arg.first.c_str());
        source_argv.push_back(arg.second.c_str());
    }
    source_argv.push_back("--");
    source_argv.push_back(source_config.bin_path.c_str());
    for (const auto &a : source_config.args)
    {
        if (a == "@@"){
            source_argv.push_back(out_file.c_str());
        }else{
            source_argv.push_back(a.c_str());
        }
    }
    source_argv.push_back(0);
    // fill envp
    for (const auto &e : source_config.env)
    {
        source_envp.push_back(e.c_str());
    }
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
        alarm(source_timeout);
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
        //std::cout << "mutated output file exists!\n";
        fail = false;
    }
    
    if (!fail){
        std::string file_hash = sha256(out_file);
        strncpy(testcase.filename, out_file.c_str(), sizeof(testcase.filename));
        testcase.filename[sizeof(testcase.filename) - 1] = 0;
        strncpy(testcase.filehash, file_hash.c_str(), 64);
        testcase.filehash[64] = '0';
        testcase.patch_point.addr = pp.addr;
        testcase.patch_point.reg_size = pp.reg_size;
        hash2pp[file_hash] = pp;
    }
    testcase.worker_id = id;
    cur_mut_counter++;

    return testcase;
}

void Worker::mutations_one(Patchpoint &pp, int mut_type){
    PintoolArgs pintool_args;
    uint64_t num_iter = addr2iter.map[pp.addr];
    pintool_args["-addr"] = std::to_string(pp.addr);
    pintool_args["-mut"] = std::to_string(mut_type);
    pintool_args["-iter"] = std::to_string(num_iter);
    std::vector<size_t> iters;
    /// fast mode: only consider first and last iteration
    /// the value of iteration is zero based
    if (schedule_mode == 1){// fast
        iters.push_back(0);
        if (num_iter > 1){
            iters.push_back(num_iter - 1);
        }
    }else if (schedule_mode == 2){
        for (size_t i = 0; i < num_iter; i++)
            iters.push_back(i);
    }else{
        abort();
    }

    switch (mut_type)
    {
        case BIT_FLIP:

            for (size_t j = 0; j < iters.size(); j++)
            { 
                pintool_args["-iter2mut"] = std::to_string(iters[j]);
                for (size_t i = 0; i < pp.reg_size * 8; i++)
                {   
                    pintool_args["-off"] = std::to_string(i);
                    pintool_args["-baddr"] = "0";
                    TestCase ts = fuzz_one(pintool_args, pp);
                    ts.mut_type = mut_type;
                    mq_send(mqd, (const char *)&ts, sizeof(TestCase), 1);

                    /// combine branch flip
                    if (pp.next_mov_b4_jmp != 0){
                        pintool_args["-baddr"] = std::to_string(pp.next_mov_b4_jmp);
                        TestCase ts = fuzz_one(pintool_args, pp);
                        ts.mut_type = mut_type;
                        mq_send(mqd, (const char *)&ts, sizeof(TestCase), 1);
                    }
                    
                }
            }
            
            break;
        case BYTE_FLIP:
            for (size_t j = 0; j < iters.size(); j++)
            { 
                pintool_args["-iter2mut"] = std::to_string(iters[j]);
                for (size_t i = 0; i < pp.reg_size; i++)
                {
                    pintool_args["-off"] = std::to_string(i);
                    pintool_args["-baddr"] = "0";
                    TestCase ts = fuzz_one(pintool_args, pp);
                    ts.mut_type = mut_type;
                    mq_send(mqd, (const char *)&ts, sizeof(TestCase), 1);

                    /// combine branch flip
                    if (pp.next_mov_b4_jmp != 0){
                        pintool_args["-baddr"] = std::to_string(pp.next_mov_b4_jmp);
                        TestCase ts = fuzz_one(pintool_args, pp);
                        ts.mut_type = mut_type;
                        mq_send(mqd, (const char *)&ts, sizeof(TestCase), 1);
                    }
                
                }
            }
            break;
        case RANDOM_BYTE0:
            for (size_t i = 0; i < max_random_steps; i++)
            {
                pintool_args["-baddr"] = "0";
                TestCase ts = fuzz_one(pintool_args, pp);
                ts.mut_type = mut_type;
                mq_send(mqd, (const char *)&ts, sizeof(TestCase), 1);

                if (pp.next_mov_b4_jmp != 0){
                    pintool_args["-baddr"] = std::to_string(pp.next_mov_b4_jmp);
                    TestCase ts = fuzz_one(pintool_args, pp);
                    ts.mut_type = mut_type;
                    mq_send(mqd, (const char *)&ts, sizeof(TestCase), 1);
                }
            }
            break;
        case RANDOM_BYTE:
            // random index and random byte
            for (size_t i = 0; i < max_random_steps; i++)
            {
                pintool_args["-baddr"] = "0";
                TestCase ts = fuzz_one(pintool_args, pp);
                ts.mut_type = mut_type;
                mq_send(mqd, (const char *)&ts, sizeof(TestCase), 1);

                if (pp.next_mov_b4_jmp != 0){
                    pintool_args["-baddr"] = std::to_string(pp.next_mov_b4_jmp);
                    TestCase ts = fuzz_one(pintool_args, pp);
                    ts.mut_type = mut_type;
                    mq_send(mqd, (const char *)&ts, sizeof(TestCase), 1);
                }
            }
            // specified index and random byte
            
            for (size_t i = 1; i < std::min(4, pp.reg_size); i++)
            {   
                pintool_args["-off"] = std::to_string(i);
                for (size_t j = 0; j < max_random_steps; j++)
                {
                    pintool_args["-baddr"] = "0";
                    TestCase ts = fuzz_one(pintool_args, pp);
                    ts.mut_type = mut_type;
                    mq_send(mqd, (const char *)&ts, sizeof(TestCase), 1);

                    if (pp.next_mov_b4_jmp != 0){
                        pintool_args["-baddr"] = std::to_string(pp.next_mov_b4_jmp);
                        TestCase ts = fuzz_one(pintool_args, pp);
                        ts.mut_type = mut_type;
                        mq_send(mqd, (const char *)&ts, sizeof(TestCase), 1);
                    }
                }
            }
            break;
        case U8ADD:
            for (size_t j = 0; j < iters.size(); j++)
            {
                pintool_args["-iter2mut"] = std::to_string(iters[j]);
                /// apply only lower two bytes
                for (size_t i = 0; i < std::min(2, pp.reg_size); i++)
                {
                    pintool_args["-off"] = std::to_string(i);
                    for (size_t j = 0; j < 256; j++)
                    {
                        pintool_args["-baddr"] = "0";
                        pintool_args["-u8"] = std::to_string(j);
                        TestCase ts = fuzz_one(pintool_args, pp);
                        ts.mut_type = mut_type;
                        mq_send(mqd, (const char *)&ts, sizeof(TestCase), 1);

                        if (pp.next_mov_b4_jmp != 0){
                            pintool_args["-baddr"] = std::to_string(pp.next_mov_b4_jmp);
                            TestCase ts = fuzz_one(pintool_args, pp);
                            ts.mut_type = mut_type;
                            mq_send(mqd, (const char *)&ts, sizeof(TestCase), 1);
                        }

                    }
                }
            }
            break;

        case HAVOC:
            for (size_t i = 0; i < max_random_steps; i++)
            {   
                pintool_args["-baddr"] = "0";
                TestCase ts = fuzz_one(pintool_args, pp);
                ts.mut_type = mut_type;
                mq_send(mqd, (const char *)&ts, sizeof(TestCase), 1);
                if (pp.next_mov_b4_jmp != 0){
                    pintool_args["-baddr"] = std::to_string(pp.next_mov_b4_jmp);
                    TestCase ts = fuzz_one(pintool_args, pp);
                    ts.mut_type = mut_type;
                    mq_send(mqd, (const char *)&ts, sizeof(TestCase), 1);
                }
            }
            break;
        default:
            perror("invalid mutation type.\n");
            abort();
    }

}

void Worker::mutations_multi(Patchpoints &pps, int mut_type){
    PintoolArgs pintool_args;
    uint64_t num_iter = addr2iter.map[pp.addr];
    std::string addrs_str = "", muts_off_str = "", muts_str = "", u8s_str = "";
    uint8_t max_reg_size = 0;
    for (size_t i = 0; i < pps.size(); i ++){
        if (pps[i].reg_size > max_reg_size) max_reg_size = pps[i].reg_size;
        addrs_str += (std::to_string(pps[i].addr) + ",");
        muts_str += (std::to_string(mut_type) + ",");
    }
    addrs_str.pop_back();
    muts_str.pop_back();

    pintool_args["-addr"] = addrs_str;
    pintool_args["-mut"] = muts_str;
    
    switch (mut_type)
    {
        case BIT_FLIP_MULTI:
            for (size_t i = 0; i < pps.size(); i ++)
                u8s_str += "0,";
            u8s_str.pop_back();
            pintool_args["-u8"] = u8s_str;
            for (size_t i = 0; i < max_reg_size * 8; i++)
            {   
                muts_off_str = "";
                for (size_t j = 0; j < pps.size(); j ++)
                    /// wrap to zero if the offset is larger than its
                    muts_off_str += (std::to_string(i % (pps[j].reg_size * 8)) + ",");
                muts_off_str.pop_back();
                pintool_args["-off"] = muts_off_str;
                // mutate
                TestCase ts = fuzz_one(pintool_args, pps[0]);
                ts.mut_type = mut_type;
                mq_send(mqd, (const char *)&ts, sizeof(TestCase), 1);
            }
            
            break;
        case BYTE_FLIP_MULTI:
            for (size_t i = 0; i < pps.size(); i ++)
                u8s_str += "0,";
            u8s_str.pop_back();
            pintool_args["-u8"] = u8s_str;
            for (size_t i = 0; i < max_reg_size; i++)
            {   
                muts_off_str = "";
                for (size_t j = 0; j < pps.size(); j ++)
                    /// wrap to zero if the offset is larger than its
                    muts_off_str += (std::to_string(i % (pps[j].reg_size)) + ",");
                muts_off_str.pop_back();
                pintool_args["-off"] = muts_off_str;
                // mutate
                TestCase ts = fuzz_one(pintool_args, pps[0]);
                ts.mut_type = mut_type;
                mq_send(mqd, (const char *)&ts, sizeof(TestCase), 1);
            }

            break;
        case RANDOM_BYTE0_MULTI:
            for (size_t i = 0; i < pps.size(); i ++){
                u8s_str += "0,";
                muts_off_str += "0,";
            }
            muts_off_str.pop_back();
            u8s_str.pop_back();
            pintool_args["-u8"] = u8s_str;
            pintool_args["-off"] = muts_off_str;
            for (size_t i = 0; i < max_random_steps; i++)
            {
                TestCase ts = fuzz_one(pintool_args, pps[0]);
                ts.mut_type = mut_type;
                mq_send(mqd, (const char *)&ts, sizeof(TestCase), 1);
            }

            break;
        case RANDOM_BYTE_MULTI:
            for (size_t i = 0; i < pps.size(); i ++){
                u8s_str += "0,";
                muts_off_str += "0,";
            }
            muts_off_str.pop_back();
            u8s_str.pop_back();
            pintool_args["-u8"] = u8s_str;
            pintool_args["-off"] = muts_off_str;
            for (size_t i = 0; i < max_random_steps; i++)
            {
                TestCase ts = fuzz_one(pintool_args, pps[0]);
                ts.mut_type = mut_type;
                mq_send(mqd, (const char *)&ts, sizeof(TestCase), 1);
            }

            break;
        case U8ADD_MULTI:
            for (size_t i = 0; i < std::min(2, max_reg_size); i++)
            {
                muts_off_str = "";
                for (size_t j = 0; j < pps.size(); j ++)
                    muts_off_str += (std::to_string(i % (pps[j].reg_size)) + ",");
                muts_off_str.pop_back();
                pintool_args["-off"] = muts_off_str;

                for (size_t j = 0; j < 256; j++)
                {
                    u8s_str = "";
                    for (size_t k = 0; k < pps.size(); k ++)
                        u8s_str += (std::to_string(j) + ",");
                    u8s_str.pop_back();
                    pintool_args["-u8"] = u8s_str;
            
                    TestCase ts = fuzz_one(pintool_args, pps[0]);
                    ts.mut_type = mut_type;
                    mq_send(mqd, (const char *)&ts, sizeof(TestCase), 1);
                
                }
            }
            
            break;

        case HAVOC_MULTI:
            for (size_t i = 0; i < pps.size(); i ++){
                u8s_str += "0,";
                muts_off_str += "0,";
            }
            muts_off_str.pop_back();
            u8s_str.pop_back();
            pintool_args["-u8"] = u8s_str;
            pintool_args["-off"] = muts_off_str;
            for (size_t i = 0; i < max_random_steps; i++)
            {
                TestCase ts = fuzz_one(pintool_args, pps[0]);
                ts.mut_type = mut_type;
                mq_send(mqd, (const char *)&ts, sizeof(TestCase), 1);
            }
            break;
        default:
            perror("invalid mutation type.\n");
            abort();
    }

    
}

void Worker::fuzz_candidates_1(){
    // unfuzzed patchpoints
    for (size_t i = 0; i < selected_pps.unfuzzed_pps.size(); i++){
        if ( !pp_valid_check(selected_pps.unfuzzed_pps[i]) ) continue;
        //mutations_one(selected_pps.unfuzzed_pps[i], BYTE_FLIP);
        //mutations_one(selected_pps.unfuzzed_pps[i], BIT_FLIP);
        mutations_one(selected_pps.unfuzzed_pps[i], U8ADD);
    }
    // interesting patchpoints
    for (size_t i = 0; i < selected_pps.interest_pps.size(); i++){
        mutations_one(selected_pps.interest_pps[i], RANDOM_BYTE0);
        //mutations_one(selected_pps.interest_pps[i], RANDOM_BYTE);
        //mutations_one(selected_pps.interest_pps[i], HAVOC);
    }
    // random patchpoints
    for (size_t i = 0; i < selected_pps.random_pps.size(); i++){
        if ( !pp_valid_check(selected_pps.random_pps[i]) ) continue;
        mutations_one(selected_pps.random_pps[i], RANDOM_BYTE0);
        //mutations_one(selected_pps.random_pps[i], RANDOM_BYTE);
        //mutations_one(selected_pps.random_pps[i], HAVOC);
    }
    
}

void Worker::fuzz_candidates_2(){
    // unfuzzed patchpoints
    for (size_t i = 0; i < selected_pps.unfuzzed_pps.size(); i++){
        //printf("mutate unfuzzed pps: %p\n", (void *)selected_pps.unfuzzed_pps[i].addr);
        mutations_multi(selected_pps.unfuzzed_pps[i], BYTE_FLIP_MULTI);
        //mutations_multi(selected_pps.unfuzzed_pps[i], BIT_FLIP_MULTI);
        //mutations_multi(selected_pps.unfuzzed_pps[i], U8ADD_MULTI);
    }
    //printf("%d: after unfuzzed\n", id);
    // interesting patchpoints
    for (size_t i = 0; i < selected_pps.interest_pps.size(); i++){
        //printf("mutate interest pps: %p\n", (void *)selected_pps.interest_pps[i].addr);
        mutations_multi(selected_pps.interest_pps[i], RANDOM_BYTE0_MULTI);
        mutations_multi(selected_pps.interest_pps[i], RANDOM_BYTE_MULTI);
        mutations_multi(selected_pps.interest_pps[i], HAVOC_MULTI);
    }
    //printf("%d: after interest\n", id);
    // random patchpoints
    for (size_t i = 0; i < selected_pps.random_pps.size(); i++){
        //printf("mutate random pps: %p\n", (void *)selected_pps.random_pps[i].addr);
        mutations_multi(selected_pps.random_pps[i], RANDOM_BYTE0_MULTI);
        mutations_multi(selected_pps.random_pps[i], RANDOM_BYTE_MULTI);
        mutations_multi(selected_pps.random_pps[i], HAVOC_MULTI);
    }

}

void Worker::save_interest_pps(){
    size_t *count_ptr = (size_t *)posix_shm.shm_base_ptr;
    size_t max_wait_s = 60;
    // wait for afl++ used all testcases this worker produced
    while (count_ptr[id] != cur_mut_counter && max_wait_s > 0)
    {   
        printf("inconsistence in %d, count in shm:%ld, count in worker%ld\n", id, count_ptr[id], cur_mut_counter);
        sleep(1);
        max_wait_s--;
    }
    count_ptr[id] = 0;
    cur_mut_counter = 0;
    
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

            }
        }
    }
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

    // block SIGINT signal
    sigset_t block;
    sigemptyset(&block);
    sigaddset(&block, SIGINT);
    pthread_sigmask(SIG_BLOCK, &block, NULL);

    // open message queue
    mqd = mq_open (MQNAME, O_RDWR,  0600, &my_mqattr);
    if (mqd == -1){
        perror ("mq_open");
        return;
    }

    // evenly dispatch different mutation approaches
    if (id % 2 == 0) level = 1;
    else level = 2;

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