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
#include <unistd.h>

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
    HAVOC_MULTI,
    BRANCH_FLIP,
    BRANCH_FLIP_NEXT,
    BRANCH_FLIP_MULTI
};

Worker::Worker(int _id) : id(_id) { 
    cur_mut_count = 0;
    unfuzzed_count = 0;
    total_mutations_count = 0;
}
Worker::~Worker(){}

void Worker::set_level(int l){
    level = l;
}

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

    //char read_buf[4096];
    char *read_buf = (char *)calloc(1024 * 1024 * 8, 1);
    while(fp.good()){
        fp.read(read_buf, sizeof(read_buf));
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
    free(read_buf);
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
    std::string source_out = out_dir + "/tmp_get_iter" + source_config.output_suffix;
    std::string get_iter_out = out_dir + "/tmp_pintool";
    std::vector<const char*> source_argv;
    std::vector<const char*> source_envp;
    
    // argv
    source_argv.push_back(pinbin_path.c_str());
    source_argv.push_back("-t");
    std::string path_tmp = pintool_path + "/obj-intel64/get_iter_num.so";
    source_argv.push_back(path_tmp.c_str());
    source_argv.push_back("-addr");
    source_argv.push_back(addr_str.c_str());
    source_argv.push_back("-o");
    source_argv.push_back(get_iter_out.c_str());
    source_argv.push_back("-p");
    if (check_ptr) source_argv.push_back("1");
    else source_argv.push_back("0");
    source_argv.push_back("--");
    source_argv.push_back(source_config.bin_path.c_str());
    for (const auto &a : source_config.args)
    {   
        if (a == "$$"){
            source_argv.push_back(source_out.c_str());
        }else if (a == "@@"){
            source_argv.push_back(source_config.seed_file.c_str());
        }else{
            source_argv.push_back(a.c_str());
        }
    }
    source_argv.push_back(0);

    // envp
    for (const auto &e : source_config.env)
    {
        source_envp.push_back(e.c_str());
    }
    source_envp.push_back(0);

    // fork and run
    int pid = fork();
    if (pid == -1){
        perror("fork failed!\n");
        return false;
    }else if(pid == 0){
        // discard output
        int null_fd = open("/dev/null", O_WRONLY);
        if (null_fd < 0) perror("failed to open /dev/null!");
        dup2(null_fd, STDOUT_FILENO);
        dup2(null_fd, STDERR_FILENO);
        close(null_fd);
        if (source_config.input_type == "Stdin"){
            int input_file_fd = open(source_config.seed_file.c_str(), O_RDONLY);
            dup2(input_file_fd, STDIN_FILENO);
            close(input_file_fd);
        }
        execve(source_argv[0], const_cast<char* const*>(source_argv.data()), const_cast<char* const*>(source_envp.data()));
        perror("execve failed!");
        exit(EXIT_FAILURE);
    }

    int status;
    waitpid(pid, &status, 0);
    if (WEXITSTATUS(status) != 0){
        printf("get_iter() failed at %s!\n", addr_str.c_str());
        return 0;
    }

    // std::ostringstream oss;
    // for (const auto &e : source_config.env)
    // {
    //     oss << e << " ";
    // }
    // oss << pinbin_path << " ";
    // oss << "-t" << " ";
    // oss << pintool_path + "/obj-intel64/get_iter_num.so" << " ";
    // oss << "-addr" << " ";
    // oss << addr_str << " ";
    // oss << "-o" << " ";
    // oss << get_iter_out << " ";
    // oss << "-p" << " ";
    // if (check_ptr) oss << "1" << " ";
    // else oss << "0" << " ";
    // oss << "--" << " ";
    // oss << source_config.bin_path << " ";
    // for (const auto &a : source_config.args)
    // {   
    //     if (a == "$$"){
    //         oss << source_out << " ";
    //     }else{
    //         oss << a << " ";
    //     }
    // }
    // oss << ">/dev/null 2>&1" << " ";

    // std::string cmd = oss.str();
    // //printf("get_iter cmd: %s\n", cmd.c_str());
    // if (system(cmd.c_str()) != 0) return 0;

    std::ifstream file(get_iter_out);
    std::string result = "";
    std::getline(file, result);
    size_t del_idx = 0, iter_num = 0, p_count = 0;

    result = result.substr(result.find(',') + 1, result.length());
    del_idx = result.find(',');
    try
    {
        iter_num = std::stoul(result.substr(0, del_idx));
        p_count = std::stoul(result.substr(del_idx + 1, result.length()));
        //printf("%p,%lu,%lu\n", (void *)std::stoul(addr_str), iter_num, p_count);
    }
    catch(const std::exception& e)
    {
        std::cerr << e.what() << '\n';
        iter_num = 0;
        p_count = 0;
    }
    
    if (p_count != 0) is_pointer = true;
    else is_pointer = false;

    if (!std::filesystem::remove(source_out)) std::cerr << "get_iter: delete file failed\n";
    if (!std::filesystem::remove(get_iter_out)) std::cerr << "get_iter: delete file failed\n";
    return iter_num;
}

size_t Worker::get_elapsed_seconds(){
    auto now = std::chrono::high_resolution_clock::now();
    auto time_period = std::chrono::duration_cast<std::chrono::seconds>(now - start_time);
    size_t elapsed_seconds = time_period.count();
    return elapsed_seconds;
}

bool Worker::pp_valid_check(const Patchpoint &pp){
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
    //printf("pp_valid_check: %p, %ld, %d\n", (void *)pp.addr, num_iter, is_pointer);
    /// hit number is not 0 and the value is not a pointer
    return (addr2iter.map[pp.addr] != 0) && (addr2iter.chk_ptr_map[pp.addr] == false);
}

void Worker::generate_testcases(){
    if (stop_soon) return;
    selected_pps.interest_pps.clear();
    selected_pps.unfuzzed_pps.clear();
    selected_pps.random_pps.clear();

    size_t res = new_selection_config.interest_num + new_selection_config.random_num + new_selection_config.unfuzzed_num;
    size_t real_select;
    thread_local std::random_device rd;
    thread_local std::mt19937 gen(rd()); // Mersenne Twister engine
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
        // std::lock_guard<std::mutex> lock(source_pps.mutex);
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


void Worker::generate_testcases_multi(){
    if (stop_soon) return;
    selected_pps_multi.unfuzzed_pps.pps.clear();
    selected_pps_multi.interest_pps.pps.clear();

    thread_local std::random_device rd;
    thread_local std::mt19937 gen(rd()); // Mersenne Twister engine
    std::ostringstream oss;

    {
        std::lock_guard<std::mutex> lock(global_read_ptr.mtx);
        std::uniform_int_distribution<size_t> dist(1, max_pps_one_mut);
        size_t my_multi_pps_num = global_read_ptr.curr_multi_pps_num;
        if (global_read_ptr.random_flag) my_multi_pps_num = dist(gen);
        if (global_read_ptr.ptr + my_multi_pps_num - 1 >= source_pps.pps.size()){
            my_multi_pps_num = source_pps.pps.size() - global_read_ptr.ptr;
        }
        for (size_t i = global_read_ptr.ptr; i < global_read_ptr.ptr + my_multi_pps_num; i++)
        {
            selected_pps_multi.unfuzzed_pps.pps.push_back(source_pps.pps[i]);
        }
        selected_pps_multi.unfuzzed_pps.original_num = my_multi_pps_num;
        //global_read_ptr.ptr += my_multi_pps_num;
        global_read_ptr.ptr ++;
        if (global_read_ptr.ptr > source_pps.pps.size() - 1){
            global_read_ptr.ptr = 0;
            if (global_read_ptr.curr_multi_pps_num == max_pps_one_mut && !global_read_ptr.random_flag) global_read_ptr.random_flag = true;
            if (!global_read_ptr.random_flag){
                global_read_ptr.curr_multi_pps_num++;
            }
        }
        unfuzzed_count++;
        
    }
    oss << "[*] Id: " << id << " Selected one \'" << selected_pps_multi.unfuzzed_pps.str() << "\' new pps combine, ";
    
    {   
        std::lock_guard<std::mutex> lock(interest_pps_multi.mutex);
        /// select one insteresting combine for every 10 unfuzzed combine
        if (interest_pps_multi.set.size() > 0 && unfuzzed_count > 10){
            std::uniform_int_distribution<size_t> dist_interest(0, interest_pps_multi.set.size() - 1);
            selected_pps_multi.interest_pps = *std::next(interest_pps_multi.set.begin(), dist_interest(gen));
            oss << "selected one \'" << selected_pps_multi.interest_pps.str() << "\' interesting pps combine";
            unfuzzed_count = 0;
        }
    }
    
    output_log(oss.str());
    //printf("%s\n", oss.str().c_str());
}

void Worker::generate_testcases_branch(){
    if (stop_soon) return;
    selected_pps.unfuzzed_pps.clear();
    selected_pps.random_pps.clear();

    size_t real_select;
    thread_local std::random_device rd;
    thread_local std::mt19937 gen(rd()); // Mersenne Twister engine
    std::ostringstream oss;

    if (!source_unfuzzed_pps_branch.pps.empty()){
        std::lock_guard<std::mutex> lock(source_unfuzzed_pps_branch.mutex);
        real_select = std::min(source_unfuzzed_pps_branch.pps.size(), new_selection_config.unfuzzed_num);
        for (size_t i = 0; i < real_select; i++){
            selected_pps.unfuzzed_pps.push_back(source_unfuzzed_pps_branch.pps[i]);
        }
        source_unfuzzed_pps_branch.pps.erase(source_unfuzzed_pps_branch.pps.begin(), source_unfuzzed_pps_branch.pps.begin() + real_select);
        oss << "[*] Id: " << id << " Selected " << selected_pps.unfuzzed_pps.size() << "/" << new_selection_config.unfuzzed_num << " unfuzzed branch pps, ";
    }else{
        oss << "[*] Id: " << id << " Selected " << "0/0" << " branch unfuzzed pps, ";
    }
    
    if (source_unfuzzed_pps_branch.pps.empty())
    {   
        // std::lock_guard<std::mutex> lock(source_pps_branch.mutex);
        real_select = std::min(source_pps_branch.pps.size(), new_selection_config.random_num);
        Patchpoints tmp_source_pps_branch = source_pps_branch.pps;
        std::shuffle(tmp_source_pps_branch.begin(), tmp_source_pps_branch.end(), gen);
        
        for (size_t i = 0; i < real_select; i++){
            selected_pps.random_pps.push_back(tmp_source_pps_branch[i]);
        }
    }

    oss << " " <<  selected_pps.random_pps.size() << "/" << new_selection_config.random_num << " random branch pps";

    output_log(oss.str());
    //printf("%s\n", oss.str().c_str());
}

TestCase Worker::fuzz_one(PintoolArgs& pintool_args, const Patchpoint &pp){
    auto now = std::chrono::system_clock::now();
    auto duration = now.time_since_epoch();
    auto millis = std::chrono::duration_cast<std::chrono::milliseconds>(duration).count();
    std::string timestamp = std::to_string(millis);
    std::string out_file = work_dir + "/source_out_" + std::to_string(id) + "_" + timestamp + source_config.output_suffix;
    std::string in_file = "";
    std::string new_env_file = "";
    std::vector<const char*> source_argv;
    std::vector<const char*> source_envp;
    TestCase testcase;
    memset(testcase.filename, 0, sizeof(testcase.filename));

    // argv and envp
    source_argv.push_back(pinbin_path.c_str());
    source_argv.push_back("-t");
    std::string pintool_mut_path = "";
    if (level == 1) pintool_mut_path = pintool_path + "/obj-intel64/mutate_ins_one.so";
    else if (level == 2) pintool_mut_path = pintool_path + "/obj-intel64/mutate_ins_multi.so";
    else if (level == 3) {
        if (branch_flip_type == 1)
            pintool_mut_path = pintool_path + "/obj-intel64/branch_flip.so";
        else if (branch_flip_type == 2)
            pintool_mut_path = pintool_path + "/obj-intel64/branch_flip_multi.so";
        else
            abort();
    }
    else abort();

    source_argv.push_back(pintool_mut_path.c_str());
    for (const auto& arg : pintool_args){
        source_argv.push_back(arg.first.c_str());
        source_argv.push_back(arg.second.c_str());
    }
    source_argv.push_back("--");
    source_argv.push_back(source_config.bin_path.c_str());
    for (const auto &a : source_config.args)
    {
        if (a == "$$"){
            source_argv.push_back(out_file.c_str());
        }else if (a == "@@"){
            in_file = work_dir + "/source_in_" + std::to_string(id) + "_" + timestamp + source_config.input_suffix;
            std::filesystem::copy(source_config.seed_file, in_file);
            source_argv.push_back(in_file.c_str());
        }else{
            source_argv.push_back(a.c_str());
        }
    }
    source_argv.push_back(0);
    // fill envp
    std::vector<std::string> tmp_source_env = source_config.env;
    for (const auto &e : source_config.env)
    {                
        std::string env_value = e.substr(e.find('=') + 1);
        std::string env_name = e.substr(0, e.find('='));
        if (std::filesystem::is_regular_file(env_value) && env_value.find(".so") == std::string::npos){
            std::filesystem::path tmp_path = env_value;
            new_env_file = work_dir + "/" + tmp_path.filename().string();
            std::string new_env = env_name + "=" + new_env_file;
            tmp_source_env.push_back(new_env);
            std::filesystem::copy(env_value, new_env_file, std::filesystem::copy_options::overwrite_existing);
            source_envp.push_back(tmp_source_env.back().c_str());
        }else{
            source_envp.push_back(e.c_str());
        }           
    } 
    source_envp.push_back(0);
    
    // printf("%d: cmd: ", id);
    // std::vector<const char*>::iterator it;
    // for(it = source_argv.begin(); it != source_argv.end(); it++){
    //     printf("%s ", *it);
    // }
    // printf("\n");

    int pid = fork();
    // source_pids[id] = pid;

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
        if (source_config.input_type == "Stdin"){
            int input_file_fd = open(in_file.c_str(), O_RDONLY);
            dup2(input_file_fd, STDIN_FILENO);
            close(input_file_fd);
        }
        // set limit to the file size of output to 8MB
        struct rlimit limit;
        limit.rlim_cur = 1024 * 1024 * 8;
        limit.rlim_max = 1024 * 1024 * 8;
        if (setrlimit(RLIMIT_FSIZE, &limit) != 0) perror("setrlimit():RLIMIT_FSIZE failed!\n");
        // set vitual memory limit to 1GB
        limit.rlim_cur = 1024 * 1024 * 1024;
        limit.rlim_max = 1024 * 1024 * 1024;
        if (setrlimit(RLIMIT_AS, &limit) != 0) perror("setrlimit():RLIMIT_AS failed!\n");
        // disable core dump
        limit.rlim_cur = 0;
        limit.rlim_max = 0;
        if (setrlimit(RLIMIT_CORE, &limit) != 0) perror("setrlimit():RLIMIT_CORE failed!\n");

        // restrict output dir?
        // assert(chdir(out_dirs[id].c_str()) == 0);
        if (chdir(work_dir.c_str()) != 0) perror("chdir() failed!\n");
        // set timeout
        alarm(generator_timeout);
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
    // source_pids[id] = -1;

    bool fail = true;
    if (std::filesystem::exists(out_file)){
        if (std::filesystem::is_regular_file(out_file)){
            if (std::filesystem::file_size(out_file) != 0)
                fail = false;
        }
        if (fail)
            std::filesystem::remove_all(out_file);
    }
    
    if (!fail){
        std::string file_hash = sha256(out_file);
        strncpy(testcase.filename, out_file.c_str(), sizeof(testcase.filename));
        testcase.filename[sizeof(testcase.filename) - 1] = 0;
        strncpy(testcase.filehash, file_hash.c_str(), 64);
        testcase.filehash[64] = '0';
        testcase.patch_point.addr = pp.addr;
        testcase.patch_point.reg_size = pp.reg_size;
        if (level == 1) {
            hash2pp[file_hash] = pp;
        }
        else if (level == 2){
            if (selected_pps_multi.interest_pps.pps.size() != 0 && pp.addr == selected_pps_multi.interest_pps.pps[0].addr){
                hash2pps_multi[file_hash] = selected_pps_multi.interest_pps;
                testcase.multi_num = selected_pps_multi.interest_pps.original_num;
            }
            else if(pp.addr == selected_pps_multi.unfuzzed_pps.pps[0].addr){
                hash2pps_multi[file_hash] = selected_pps_multi.unfuzzed_pps;
                testcase.multi_num = selected_pps_multi.unfuzzed_pps.original_num;
            }
            else
                abort();
            
        }else if (level == 3){

        }
        else{abort();}
        
    }
    testcase.worker_id = id;
    cur_mut_count++;
    total_mutations_count++;

    if (fuzzer_timeout != 0){
        if (__glibc_unlikely(get_elapsed_seconds() > fuzzer_timeout))
            stop_soon = true;
    }
    if (in_file != ""){
        if (!std::filesystem::remove(in_file)) std::cerr << "fuzz_one: delete input file failed\n";
    }
    if (new_env_file != ""){
        if (!std::filesystem::remove(new_env_file)) std::cerr << "fuzz_one: delete copied env file failed\n";
    }

    return testcase;
}

void Worker::mutations_one(const Patchpoint &pp, int mut_type){
    if (stop_soon) return;
    PintoolArgs pintool_args;
    uint64_t num_iter = addr2iter.map[pp.addr];
    pintool_args["-addr"] = std::to_string(pp.addr);
    pintool_args["-mut"] = std::to_string(mut_type);
    pintool_args["-iter"] = std::to_string(num_iter);
    std::vector<size_t> iters;
    /// fast mode: only consider first and last execution
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
    size_t reg_max_bytes2mut = (pp.reg_size < 5) ? pp.reg_size : 5;

    switch (mut_type)
    {
        case BIT_FLIP:

            for (size_t j = 0; j < iters.size(); j++)
            {   
                if (stop_soon) return;
                pintool_args["-iter2mut"] = std::to_string(iters[j]);
                for (size_t i = 0; i < reg_max_bytes2mut * 8; i++)
                {   
                    if (stop_soon) return;
                    pintool_args["-off"] = std::to_string(i);
                    pintool_args["-baddr"] = "0";
                    TestCase ts = fuzz_one(pintool_args, pp);
                    ts.mut_type = mut_type;
                    mq_send(mqd, (const char *)&ts, sizeof(TestCase), 1);

                    /// combine branch flip
                    if (stop_soon) return;
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
                if (stop_soon) return;
                pintool_args["-iter2mut"] = std::to_string(iters[j]);
                for (size_t i = 0; i < reg_max_bytes2mut; i++)
                {
                    if (stop_soon) return;
                    pintool_args["-off"] = std::to_string(i);
                    pintool_args["-baddr"] = "0";
                    TestCase ts = fuzz_one(pintool_args, pp);
                    ts.mut_type = mut_type;
                    mq_send(mqd, (const char *)&ts, sizeof(TestCase), 1);

                    /// combine branch flip
                    if (stop_soon) return;
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
                if (stop_soon) return;
                pintool_args["-baddr"] = "0";
                TestCase ts = fuzz_one(pintool_args, pp);
                ts.mut_type = mut_type;
                mq_send(mqd, (const char *)&ts, sizeof(TestCase), 1);

                if (stop_soon) return;
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
                if (stop_soon) return;
                pintool_args["-baddr"] = "0";
                TestCase ts = fuzz_one(pintool_args, pp);
                ts.mut_type = mut_type;
                mq_send(mqd, (const char *)&ts, sizeof(TestCase), 1);

                if (stop_soon) return;
                if (pp.next_mov_b4_jmp != 0){
                    pintool_args["-baddr"] = std::to_string(pp.next_mov_b4_jmp);
                    TestCase ts = fuzz_one(pintool_args, pp);
                    ts.mut_type = mut_type;
                    mq_send(mqd, (const char *)&ts, sizeof(TestCase), 1);
                }
            }
            
            // specified index and random byte
            // for (size_t i = 1; i < std::min((uint8_t)4, reg_max_bytes2mut); i++)
            // {   
            //     pintool_args["-off"] = std::to_string(i);
            //     for (size_t j = 0; j < max_random_steps; j++)
            //     {
            //         if (stop_soon) return;
            //         pintool_args["-baddr"] = "0";
            //         TestCase ts = fuzz_one(pintool_args, pp);
            //         ts.mut_type = mut_type;
            //         mq_send(mqd, (const char *)&ts, sizeof(TestCase), 1);

            //         if (stop_soon) return;
            //         if (pp.next_mov_b4_jmp != 0){
            //             pintool_args["-baddr"] = std::to_string(pp.next_mov_b4_jmp);
            //             TestCase ts = fuzz_one(pintool_args, pp);
            //             ts.mut_type = mut_type;
            //             mq_send(mqd, (const char *)&ts, sizeof(TestCase), 1);
            //         }
            //     }
            // }
            break;
        case U8ADD:
            for (size_t j = 0; j < iters.size(); j++)
            {   
                if (stop_soon) return;
                pintool_args["-iter2mut"] = std::to_string(iters[j]);
                /// apply only the lowest byte
                // for (size_t i = 0; i < std::min((uint8_t)2, reg_max_bytes2mut); i++)
                // {
                // pintool_args["-off"] = std::to_string(i);
                pintool_args["-off"] = std::to_string(0);
                for (size_t j = 1; j < 256; j++)
                {
                    if (stop_soon) return;
                    pintool_args["-baddr"] = "0";
                    pintool_args["-u8"] = std::to_string(j);
                    TestCase ts = fuzz_one(pintool_args, pp);
                    ts.mut_type = mut_type;
                    mq_send(mqd, (const char *)&ts, sizeof(TestCase), 1);

                    if (stop_soon) return;
                    if (pp.next_mov_b4_jmp != 0){
                        pintool_args["-baddr"] = std::to_string(pp.next_mov_b4_jmp);
                        TestCase ts = fuzz_one(pintool_args, pp);
                        ts.mut_type = mut_type;
                        mq_send(mqd, (const char *)&ts, sizeof(TestCase), 1);
                    }

                }
                // }
            }
            break;

        case HAVOC:
            for (size_t i = 0; i < max_random_steps; i++)
            {   
                if (stop_soon) return;
                pintool_args["-baddr"] = "0";
                TestCase ts = fuzz_one(pintool_args, pp);
                ts.mut_type = mut_type;
                mq_send(mqd, (const char *)&ts, sizeof(TestCase), 1);

                if (stop_soon) return;
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

void Worker::mutations_multi(const Patchpoints &pps, int mut_type){
    if (stop_soon) return;
    PintoolArgs pintool_args;
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
                if (stop_soon) return;
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
                if (stop_soon) return;
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
                if (stop_soon) return;
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
                if (stop_soon) return;
                TestCase ts = fuzz_one(pintool_args, pps[0]);
                ts.mut_type = mut_type;
                mq_send(mqd, (const char *)&ts, sizeof(TestCase), 1);
            }

            break;
        case U8ADD_MULTI:
            // for (size_t i = 0; i < std::min((uint8_t)2, max_reg_size); i++)
            for (size_t i = 0; i < std::min((uint8_t)1, max_reg_size); i++)
            {
                muts_off_str = "";
                for (size_t j = 0; j < pps.size(); j ++)
                    muts_off_str += (std::to_string(i % (pps[j].reg_size)) + ",");
                muts_off_str.pop_back();
                pintool_args["-off"] = muts_off_str;

                for (size_t j = 1; j < 256; j++)
                {
                    if (stop_soon) return;
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
                if (stop_soon) return;
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

void Worker::mutations_branch(const Patchpoint &pp, int mut_type){
    if (stop_soon) return;
    PintoolArgs pintool_args;
    pintool_args["-addr"] = std::to_string(pp.addr);

    if (mut_type == BRANCH_FLIP){
        if (stop_soon) return;
        branch_flip_type = 1;
        pintool_args["-n"] = "0";
        TestCase ts = fuzz_one(pintool_args, pp);
        ts.mut_type = BRANCH_FLIP;
        mq_send(mqd, (const char *)&ts, sizeof(TestCase), 1);
        if (ts.filename[0] == '\0'){
            if (stop_soon) return;
            // combine with next 10 branch flip
            for (size_t i = 1; i <= 10; i++)
            {   
                if (stop_soon) return;
                pintool_args["-n"] = std::to_string(i);
                ts = fuzz_one(pintool_args, pp);
                ts.mut_type = BRANCH_FLIP_NEXT;
                mq_send(mqd, (const char *)&ts, sizeof(TestCase), 1);
            }
        }

    }else if (mut_type == BRANCH_FLIP_MULTI){// combination
        if (stop_soon) return;
        branch_flip_type = 2;
        thread_local std::random_device rd;
        thread_local std::mt19937 gen(rd()); // Mersenne Twister engine
        static std::uniform_int_distribution<> dist_ins2instr(1, 10);
        // randomly generate the number of branch instructions to flip
        pintool_args["-n"] = std::to_string(dist_ins2instr(gen));
        
        // instrument with half probability
        // flip branch with half probability on a single hit for one instrument instruction
        pintool_args["-i"] = "1";
        pintool_args["-f"] = "1";
        TestCase ts = fuzz_one(pintool_args, pp);
        ts.mut_type = BRANCH_FLIP_MULTI;
        mq_send(mqd, (const char *)&ts, sizeof(TestCase), 1);
        if (stop_soon) return;

        // only instrument with half probability
        pintool_args["-i"] = "1";
        pintool_args["-f"] = "0";
        ts = fuzz_one(pintool_args, pp);
        ts.mut_type = BRANCH_FLIP_MULTI;
        mq_send(mqd, (const char *)&ts, sizeof(TestCase), 1);
        if (stop_soon) return;

        // only flip branch with half probability
        pintool_args["-i"] = "0";
        pintool_args["-f"] = "1";
        ts = fuzz_one(pintool_args, pp);
        ts.mut_type = BRANCH_FLIP_MULTI;
        mq_send(mqd, (const char *)&ts, sizeof(TestCase), 1);
        if (stop_soon) return;

        // always instrument found ins and flip branch
        pintool_args["-i"] = "0";
        pintool_args["-f"] = "0";
        ts = fuzz_one(pintool_args, pp);
        ts.mut_type = BRANCH_FLIP_MULTI;
        mq_send(mqd, (const char *)&ts, sizeof(TestCase), 1);
    }

}

void Worker::fuzz_candidates_one(){
    if (stop_soon) return;
    // unfuzzed patchpoints
    for (size_t i = 0; i < selected_pps.unfuzzed_pps.size(); i++){
        if (stop_soon) return;
        if ( !pp_valid_check(selected_pps.unfuzzed_pps[i]) ) continue;
        mutations_one(selected_pps.unfuzzed_pps[i], BYTE_FLIP);
        mutations_one(selected_pps.unfuzzed_pps[i], BIT_FLIP);
        mutations_one(selected_pps.unfuzzed_pps[i], U8ADD);
    }
    // interesting patchpoints
    for (size_t i = 0; i < selected_pps.interest_pps.size(); i++){
        if (stop_soon) return;
        mutations_one(selected_pps.interest_pps[i], RANDOM_BYTE0);
        mutations_one(selected_pps.interest_pps[i], RANDOM_BYTE);
        mutations_one(selected_pps.interest_pps[i], HAVOC);
    }
    // random patchpoints
    for (size_t i = 0; i < selected_pps.random_pps.size(); i++){
        if (stop_soon) return;
        if ( !pp_valid_check(selected_pps.random_pps[i]) ) continue;
        mutations_one(selected_pps.random_pps[i], RANDOM_BYTE0);
        mutations_one(selected_pps.random_pps[i], RANDOM_BYTE);
        mutations_one(selected_pps.random_pps[i], HAVOC);
    }
    
}

void Worker::fuzz_candidates_multi(){
    if (stop_soon) return;
    // unfuzzed patchpoints
    Patchpoints new_pps;
    for (const auto &pp : selected_pps_multi.unfuzzed_pps.pps)
    {
        if (stop_soon) return;
        if (pp_valid_check(pp))
            new_pps.push_back(pp);
    }
    selected_pps_multi.unfuzzed_pps.pps = new_pps;
    if (new_pps.size() > 1){
        if (stop_soon) return;
        mutations_multi(selected_pps_multi.unfuzzed_pps.pps, BYTE_FLIP_MULTI);
        mutations_multi(selected_pps_multi.unfuzzed_pps.pps, BIT_FLIP_MULTI);
        mutations_multi(selected_pps_multi.unfuzzed_pps.pps, U8ADD_MULTI);
    }
    
    // interesting patchpoints
    if (!selected_pps_multi.interest_pps.pps.empty()){
        if (stop_soon) return;
        mutations_multi(selected_pps_multi.interest_pps.pps, RANDOM_BYTE0_MULTI);
        mutations_multi(selected_pps_multi.interest_pps.pps, RANDOM_BYTE_MULTI);
        mutations_multi(selected_pps_multi.interest_pps.pps, HAVOC_MULTI);
    }
    
}

void Worker::fuzz_candidates_branch(){
    if (stop_soon) return;
    // unfuzzed patchpoints
    for (size_t i = 0; i < selected_pps.unfuzzed_pps.size(); i++){
        if (stop_soon) return;
        mutations_branch(selected_pps.unfuzzed_pps[i], BRANCH_FLIP);
    }

    // random patchpoints combination
    if (!selected_pps.random_pps.empty()){
        for (size_t i = 0; i < selected_pps.random_pps.size(); i++){
            if (stop_soon) return;
            mutations_branch(selected_pps.random_pps[i], BRANCH_FLIP_MULTI);
        }
    }
    // clear records
    size_t *count_ptr = (size_t *)posix_shm.shm_base_ptr;
    count_ptr[id + 1] = 0;
    cur_mut_count = 0;
}

void Worker::save_interest_pps(){
    if (stop_soon) return;
    if (cur_mut_count == 0) return;
    size_t *count_ptr = (size_t *)posix_shm.shm_base_ptr;
    size_t max_wait_s = 3;
    // wait for afl++ used all testcases this worker produced
    while (count_ptr[id + 1] != cur_mut_count && max_wait_s > 0)
    {   
        if (stop_soon) return;
        //printf("inconsistence in %d, count in shm:%ld, count in worker:%ld\n", id, count_ptr[id + 1], cur_mut_count);
        sleep(1);
        max_wait_s--;
    }
    count_ptr[id + 1] = 0;
    cur_mut_count = 0;
    
    std::string afl_output_dir = afl_config.dir_out;
    std::vector<std::string> sub_dirs;
    if (is_master){
        sub_dirs.push_back("/master/queue");
        sub_dirs.push_back("/master/crashes");
        sub_dirs.push_back("/master/hangs");
    }else{
        sub_dirs.push_back("/slave/queue");
        sub_dirs.push_back("/slave/crashes");
        sub_dirs.push_back("/slave/hangs");
    }
    std::string ftmm_file = "addr";
    //std::string new_cov_file = "+cov";
    for (const auto & sub_dir : sub_dirs){
        std::filesystem::path sync_dir = afl_output_dir + sub_dir;
        for (const auto& file : std::filesystem::directory_iterator(sync_dir)){
            if (stop_soon) return;
            if (std::filesystem::is_regular_file(file.path()) && file.path().string().find(ftmm_file) == std::string::npos){
            //if (std::filesystem::is_regular_file(file.path()) && file.path().string().find(new_cov_file) != std::string::npos){
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
    }
    
    if (level == 1){
        {
            std::lock_guard<std::mutex> lock(interest_pps.mutex);
            for (const auto& pair : hash2pp){
                if (stop_soon) return;
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
    else if (level == 2){
        {
            std::lock_guard<std::mutex> lock(interest_pps_multi.mutex);
            
            for (const auto& pair : hash2pps_multi){
                if (stop_soon) return;
                if (afl_files_hashes.find(pair.first) != afl_files_hashes.end()){
                    //printf("find interesting pps: %s, %s\n", pair.first.c_str(), addrs_str.c_str());
                    if (pair.second.str() == selected_pps_multi.interest_pps.str()) continue;
                    std::ostringstream oss;
                    oss << "[*] Find interesting pps combine: " << selected_pps_multi.unfuzzed_pps.str();
                    output_log(oss.str());
                    //printf("%s\n", oss.str().c_str());
                    interest_pps_multi.set.insert(selected_pps_multi.unfuzzed_pps);
                    break;
                }
            }
        }
        hash2pps_multi.clear();
    }else{
        abort();
    }

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
    if (level != 3){
        if (id % 2 == 0) level = 1;
            else level = 2;
    }
    //level = 1;

    // main loop of worker
    while(1){
        if (level == 1){
            generate_testcases();
            fuzz_candidates_one();
            save_interest_pps();
        }else if (level == 2){
            generate_testcases_multi();
            fuzz_candidates_multi();
            save_interest_pps();
        }else if (level == 3){
            generate_testcases_branch();
            fuzz_candidates_branch();
        }
        if (stop_soon) break;
    }
    
    mq_close(mqd);
    
    {
        std::lock_guard<std::mutex> lock(global_mutations_count.mtx);
        global_mutations_count.count += total_mutations_count;
    }
    // printf("Worker %d exited!\n", id);
    return;
}