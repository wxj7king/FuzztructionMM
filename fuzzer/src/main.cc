#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <mqueue.h>
#include <string>
#include <filesystem>
#include <chrono>
#include <sstream>
#include <fstream>
#include <random>
#include <iostream>
#include <sys/ipc.h>
#include <sys/shm.h>
#include <sys/wait.h>
#include <sys/mman.h>
#include <sys/resource.h>

#include "include/utils.h"
#include "include/worker.h"
#include "include/nlohmann/json.hpp"

// global variables
static pid_t afl_pid;
static pid_t worker_pid;
static std::vector<pthread_t> threads;
static std::vector<ThreadArg> targs;
static PosixShmPara posix_shm;
static const std::string ftmm_dir = "/tmp/ftmm_workdir";
static const std::string log_dir = "/tmp/ftmm_workdir/ftm_log";
static std::set<std::string> delete_white_list;

/// configurable parameters
static int schedule_mode = 2;
static size_t max_random_steps = 32;
static size_t max_num_one_mut = 1024;
static size_t num_thread = 1;
static size_t generator_timeout = 3;
static size_t max_pps_one_mut = 30;
/// run forever if it is zero
static size_t fuzzer_timeout = 0;
static bool with_afl = false;
static std::string config_path = "";
static BinConfig consumer_config;
static AflConfig afl_config;
/// envs for dependencies
static std::string aflpp_path = "";
static std::string afl_custom_mutator_path = "";

void main_sig_handler(int sig){
    kill(afl_pid, SIGKILL);
    waitpid(afl_pid, 0, 0);

    kill(worker_pid, SIGINT);
    waitpid(worker_pid, 0, 0);

    exit(0);
}

void worker_sig_handler(int sig){
    // kill potential child processes forked by worker threads
    // for (const auto& pid : Worker::source_pids){
    //     if (pid != -1){
    //         //printf("child process %d exist, kill it\n", pid);
    //         kill(pid, SIGKILL);
    //         waitpid(pid, 0, 0);
    //     }
    // }
    // // detach from worker threads
    // for (const auto& tid : threads){
    //     //printf("detach from thread %d\n", tid);
    //     pthread_detach(tid);
    // }

    // _exit(0);

    Worker::stop_soon = true;
}

static void at_exit(){
    // purge work dir
    for (const auto& entry : std::filesystem::directory_iterator(ftmm_dir))
    {   
        if (delete_white_list.count(entry.path().filename().string()) == 0){
            if (std::filesystem::is_regular_file(entry)){
                std::filesystem::remove(entry);
            }else if(std::filesystem::is_directory(entry)){
                std::filesystem::remove_all(entry);
            }
        }
    }

    // destroy shared memory and message queue
    mq_unlink(MQNAME);
    munmap(posix_shm.shm_base_ptr, posix_shm.size_in_bytes);
    shm_unlink(POSIX_SHM_NAME);
    //printf("\033[2J\033[H");
    printf("Fuzztruction--: Bye!\n");

}

static bool find_patchpoints(std::string out_dir, Patchpointslock& patch_points){
    std::string source_out = out_dir + "/tmp_source" + Worker::source_config.output_suffix;
    std::string find_ins_out = out_dir + "/tmp_pintool";
    std::vector<const char*> source_argv;
    std::vector<const char*> source_envp;

    // argv
    source_argv.push_back(Worker::pinbin_path.c_str());
    source_argv.push_back("-t");
    std::string path_tmp = Worker::pintool_path + "/obj-intel64/find_inst_sites.so";
    source_argv.push_back(path_tmp.c_str());
    source_argv.push_back("-o");
    source_argv.push_back(find_ins_out.c_str());
    source_argv.push_back("--");
    source_argv.push_back(Worker::source_config.bin_path.c_str());
    for (const auto &a : Worker::source_config.args)
    {   
        if (a == "$$"){
            source_argv.push_back(source_out.c_str());
        }else if (a == "@@"){
            if (Worker::source_config.input_type == "None"){
                perror("has \"@@\" and \"None\" input type\n");
                return false;
            }else if (Worker::source_config.input_type == "File"){
                source_argv.push_back(Worker::source_config.seed_file.c_str());
            }else{
                abort();
            }
        }else{
            source_argv.push_back(a.c_str());
        }
    }
    source_argv.push_back(0);

    // envp
    for (const auto &e : Worker::source_config.env)
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
        if (Worker::source_config.input_type == "Stdin"){
            int input_file_fd = open(Worker::source_config.seed_file.c_str(), O_RDONLY);
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
        perror("find_patchpoints() failed!\n");
        printf("Generator exited with status 0x%x.\n", WEXITSTATUS(status));
        return false;
    }

    // std::ostringstream oss;
    // for (const auto &e : Worker::source_config.env)
    // {
    //     oss << e << " ";
    // }
    // oss << Worker::pinbin_path << " ";
    // oss << "-t" << " ";
    // oss << Worker::pintool_path + "/obj-intel64/find_inst_sites.so" << " ";
    // oss << "-o" << " ";
    // oss << find_ins_out << " ";
    // oss << "--" << " ";
    // oss << Worker::source_config.bin_path << " ";
    // for (const auto &a : Worker::source_config.args)
    // {   
    //     if (a == "$$"){
    //         oss << source_out << " ";
    //     }else{
    //         oss << a << " ";
    //     }
    // }
    // oss << ">/dev/null 2>&1" << " ";

    // std::string cmd = oss.str();
    // //printf("cmd: %s\n", cmd.c_str());
    // if (system(cmd.c_str()) != 0) return false;

    /// FIXIT:hijack!
    //std::ifstream file("./output.asm");
    std::ifstream file(find_ins_out);
    
    std::vector<std::string> lines;
    if (file.is_open()){
        std::string line;
        while (std::getline(file, line)) 
            lines.push_back(line);
        file.close();
    }else{
        return false;
    }

    for (size_t i = 0; i < lines.size(); i++)
    {
        Patchpoint pp;
        std::string line = lines[i];
        size_t del_idx = line.find('@');
        std::string disas = line.substr(0, del_idx);
        line = line.substr(del_idx + 1, line.length());

        del_idx = line.find(',');
        //printf("dd: %s, %d\n", line.c_str(), del_idx);
        try
        {
            pp.addr = std::stoul(line.substr(0, del_idx), nullptr, 16); 
            pp.reg_size = (uint8_t)std::stoul(line.substr(del_idx + 1, line.length()));
        }
        catch(const std::exception& e)
        {
            continue;
        }
        /// skip jmp ins
        if (pp.reg_size == 32) continue;
        /// filter possible invalid ins
        if (pp.reg_size == 0) continue;

        uint64_t found_mov_b4_jmp_addr = 0;
        size_t max_search_depth = 500;
        size_t cap = std::min(lines.size(), i + max_search_depth);
        for (size_t j = i + 1; j < cap; j++)
        {
            if ((lines[j].find("jz") != std::string::npos) || (lines[j].find("jnz") != std::string::npos) ){
                if (j - 1 != i) {
                    std::string tmp_str = lines[j - 1];
                    //std::cout << tmp_str << std::endl;
                    /// a sequence of jmp, just skip
                    assert(tmp_str.find("mov") != std::string::npos);
                    tmp_str = tmp_str.substr(tmp_str.find('@') + 1, tmp_str.length());
                    tmp_str = tmp_str.substr(0, tmp_str.find(','));
                    try
                    {
                        found_mov_b4_jmp_addr = std::stoul(tmp_str, nullptr, 16); 
                    }
                    catch(const std::exception& e)
                    {
                        found_mov_b4_jmp_addr = 0;
                    }
                        
                    break;
                }else{
                    /// skip mov ins that has a direct effect on its following cond jmp
                    break;
                }
            }
        }
        // 0 or addr
        pp.next_mov_b4_jmp = found_mov_b4_jmp_addr;
        // printf("%s, %p, %u, %p\n", disas.c_str(), (void *)pp.addr, pp.reg_size, (void *)pp.next_mov_b4_jmp);
        patch_points.pps.push_back(pp);
    }
    

    if (!std::filesystem::remove(source_out)) std::cerr << "find pps: delete file source_out failed\n";
    if (!std::filesystem::remove(find_ins_out)) std::cerr << "find pps: delete file find_ins_out failed\n";
    printf("[*] find %ld instructions.\n", patch_points.pps.size());
    
    return true;
}

void *thread_worker(void* arg){
    ThreadArg *targ = (ThreadArg *)arg;
    Worker worker(targ->tid);
    worker.start();
    return nullptr;
}

static void child_process(){
    std::string out_dir = ftmm_dir;
    if (!find_patchpoints(out_dir, Worker::source_pps)) {
        perror("find_patchpoints() failed!\n");
        return;
    }
    //return;
    Worker::source_unfuzzed_pps.pps = Worker::source_pps.pps;
    Worker::start_time = std::chrono::high_resolution_clock::now();

    for (size_t i = 0; i < num_thread; i++){
        targs[i].tid = i;
        int rc = pthread_create(&threads[i], NULL, thread_worker, (void *)&targs[i]);
        if (rc) {
            perror("pthread_create()");
            _exit(EXIT_FAILURE);
        }
    }

    // wait for worker threads
    for (size_t i = 0; i < num_thread; i++){
        int rc = pthread_join(threads[i], NULL);
        if (rc) {
            perror("pthread_join()");
            _exit(EXIT_FAILURE);
        }
        //printf("thread %ld exited!\n", threads[i]);
    }
    printf("\nTotal number of mutations: %lu in %lu seconds\n", Worker::global_mutations_count.count, fuzzer_timeout);
}

static bool init(){

    std::filesystem::path curr_path = std::filesystem::current_path();
    //printf("\nCurrent path: %s\n", curr_path.string().c_str());

    threads.resize(num_thread);
    targs.resize(num_thread);

    Worker::max_random_steps = max_random_steps;
    Worker::max_num_one_mut = max_num_one_mut;
    Worker::num_thread = num_thread;
    Worker::generator_timeout = generator_timeout;
    Worker::max_pps_one_mut = max_pps_one_mut;

    // Worker::source_pids.assign(num_thread, -1);
    Worker::ftmm_dir = ftmm_dir;
    Worker::new_selection_config.interest_num = 10;
    Worker::new_selection_config.unfuzzed_num = 20;
    Worker::new_selection_config.random_num = 10;
    Worker::schedule_mode = schedule_mode;
    Worker::global_read_ptr.ptr = 0;
    Worker::global_read_ptr.random_flag = false;
    /// multi pps starts from 2
    Worker::global_read_ptr.curr_multi_pps_num = 2;
    Worker::stop_soon = false;
    Worker::fuzzer_timeout = fuzzer_timeout;
    Worker::global_mutations_count.count = 0;

    auto now = std::chrono::system_clock::now();
    auto duration = now.time_since_epoch();
    auto millis = std::chrono::duration_cast<std::chrono::milliseconds>(duration).count();
    std::string timestamp = std::to_string(millis);
    Worker::log_path = log_dir + "/log_" + timestamp;

    if (!std::filesystem::exists(log_dir)){
        if (!std::filesystem::create_directories(log_dir)) {
            printf("failed to create directory: %s\n", log_dir.c_str());
            return false;
        }
    }
    // do not delete log dir
    delete_white_list.insert("ftm_log");

    // initialize message queue
    mq_unlink(MQNAME);
    Worker::my_mqattr.mq_flags = 0;
    //Worker::my_mqattr.mq_maxmsg = 30;
    Worker::my_mqattr.mq_maxmsg = 10;
    Worker::my_mqattr.mq_msgsize = sizeof(TestCase);
    Worker::my_mqattr.mq_curmsgs = 0;
    mqd_t tmp_mqd = mq_open(MQNAME, O_CREAT | O_EXCL,  0600, &Worker::my_mqattr);
    if (tmp_mqd == -1){
        perror ("mq_open");
        printf("please set the max length of posix message queue with: \'echo 30 > /proc/sys/fs/mqueue/msg_max\'\n");
        return false;
    }
    mq_close(tmp_mqd);

    // initialize shared memory between afl++
    shm_unlink(POSIX_SHM_NAME);
    if ((posix_shm.shmfd = shm_open(POSIX_SHM_NAME, O_CREAT | O_EXCL | O_RDWR, 0666)) != -1){
        posix_shm.size_in_bytes = sizeof(size_t) * (num_thread + 1);
        if (ftruncate(posix_shm.shmfd, posix_shm.size_in_bytes) != -1){
            if ((posix_shm.shm_base_ptr = (unsigned char *)mmap(NULL, posix_shm.size_in_bytes, PROT_READ | PROT_WRITE, MAP_SHARED, posix_shm.shmfd, 0)) == MAP_FAILED){
                perror("mmap() failed\n");
                return false;
            }
        }else{
            perror("ftruncate() failed\n");
            return false;
        }
    }else{
        perror("shm_open() failed\n");
        return false;
    }
    memset(posix_shm.shm_base_ptr, 0, posix_shm.size_in_bytes);

    // tell afl++ the size of shared memory
    *((size_t *)posix_shm.shm_base_ptr) = posix_shm.size_in_bytes;
    Worker::posix_shm = posix_shm;

    return true;
}

static void reap_resources(){
    for (const auto& entry : std::filesystem::directory_iterator(ftmm_dir))
    {   
        if (delete_white_list.count(entry.path().filename().string()) == 0){
            if (std::filesystem::is_regular_file(entry)){
                std::filesystem::remove(entry);
            }else if(std::filesystem::is_directory(entry)){
                std::filesystem::remove_all(entry);
            }
        }
    }
    mq_unlink(MQNAME);
    munmap(posix_shm.shm_base_ptr, posix_shm.size_in_bytes);
    shm_unlink(POSIX_SHM_NAME);
}

static bool load_config(const std::string &path){
    std::ifstream f(path);
    if (!f.is_open()){
        std::cerr << "open config file failed.\n";
        return false;
    }

    std::ifstream dependencies_file("./dep_config.json");
    if (!dependencies_file.is_open()){
        std::cerr << "open config file failed.\n";
        return false;
    }

    try
    {   
        nlohmann::json data = nlohmann::json::parse(f);
        // generator
        for (const auto &e : data["generator"]["env"])
            Worker::source_config.env.push_back(e);
        Worker::source_config.bin_path = data["generator"]["bin_path"];
        for (const auto &e : data["generator"]["args"])
            Worker::source_config.args.push_back(e);
        Worker::source_config.input_type = data["generator"]["input_type"];
        Worker::source_config.output_type = data["generator"]["output_type"];
        Worker::source_config.seed_file = data["generator"]["seed_file"];
        Worker::source_config.input_suffix = data["generator"]["input_suffix"];
        Worker::source_config.output_suffix = data["generator"]["output_suffix"];

        // consumer
        for (const auto &e : data["consumer"]["env"])
            consumer_config.env.push_back(e);
        consumer_config.bin_path = data["consumer"]["bin_path"];
        for (const auto &e : data["consumer"]["args"])
            consumer_config.args.push_back(e);
        consumer_config.input_type = data["consumer"]["input_type"];
        consumer_config.output_type = data["consumer"]["output_type"];

        // afl++
        afl_config.dir_in = data["afl++"]["dir_in"];
        afl_config.dir_out = data["afl++"]["dir_out"];
        Worker::afl_config = afl_config;

        // dependencies paths
        nlohmann::json data2 = nlohmann::json::parse(dependencies_file);
        aflpp_path = data2["deps"]["aflpp"];
        afl_custom_mutator_path = data2["deps"]["aflpp_custom"];
        Worker::pinbin_path = data2["deps"]["pinbin"];
        Worker::pintool_path = data2["deps"]["pintool"];
    }
    catch(const nlohmann::json::exception& e)
    {
        std::cerr << e.what() << '\n' << "exception id: " << e.id << std::endl;
        return false;
    }
    
    return true;
}

static void usage(){
    const char* table = 
        "fuzzer [options]"
        "\nNote: \'-f\' option is mandatory!"
        "\n  -f path           config file of parameters of source and sink binary"
        "\n  -r num            maxmium steps for random mutation (default: 32)"
        "\n  -n num_thread     number of threads (default: 1)"
        "\n  -T seconds        timeout for fuzzer (default: forever)"
        "\n  -t seconds        timeout for each run of mutated source binary (default: 3s)"
        "\n  -m num            maximum number of test cases one mutation can produce (default: 1024)"
        "\n  -l 1/2            fast mode: 1, fine-grained mode: 2 (default: 2)"
        "\n  -a                use mutations from AFL++ (default: false)"
        "\n  -h help           show help\n"
        ;
    fprintf(stdout, "Fuzztrunction-- v0.1\n%s\n", table);
    exit(1);
}

static void print_params(){
    const char* params = 
        "Fuzztrunction-- v0.1\n"
        "Run options: "
        "\n  -f %s"
        "\n  -r %ld"
        "\n  -n %ld"
        "\n  -T %ld"
        "\n  -t %ld"
        "\n  -m %ld"
        "\n  -l %d"
        "\n  -a %d\n"
        ;
    
    printf(params, config_path.c_str(), max_random_steps, num_thread, fuzzer_timeout, generator_timeout, max_num_one_mut, schedule_mode, with_afl);
}


int main(int argc, char **argv){
    int show_help = 0, opt;
    int loaded = 0;
    opterr = 0;

    while ((opt = getopt(argc, argv, "h:f:r:n:T:t:m:l:a")) > 0)
    {
        switch (opt)
        {
            case 'h':
                show_help = 1;
                break;

            case 'f':
                config_path = optarg;
                break;
                
            /// TODO: set cap to those parameters
            case 'r':
                max_random_steps = atoll(optarg);
                if (max_random_steps == 0){
                    fprintf(stderr, "Invalid value of maxmium steps for random mutation: %s\n", optarg);
                    show_help = 1;
                }
                break;

            case 'n':
                num_thread = atoll(optarg);
                if (num_thread == 0){
                    fprintf(stderr, "Invalid value of the number of threads: %s\n", optarg);
                    show_help = 1;
                }
                break;

            case 'T':
                fuzzer_timeout = atoll(optarg);
                if (fuzzer_timeout == 0){
                    fprintf(stderr, "Invalid value of the fuzzer timeout: %s\n", optarg);
                    show_help = 1;
                }
                break;

            case 't':
                generator_timeout = atoll(optarg);
                if (generator_timeout == 0){
                    fprintf(stderr, "Invalid value of the timeout for the execution of source binary: %s\n", optarg);
                    show_help = 1;
                }
                break;

            case 'm':
                max_num_one_mut = atoll(optarg);
                if (max_num_one_mut == 0){
                    fprintf(stderr, "Invalid value of the maximum number of test case one mutation can produce: %s\n", optarg);
                    show_help = 1;
                }
                break;

            case 'l':
                schedule_mode = atoi(optarg);
                if (schedule_mode != 1 && schedule_mode != 2){
                    fprintf(stderr, "Invalid value of mutation schedule mode: %s\n", optarg);
                    show_help = 1;
                }
                break;

            case 'a':
                with_afl = true;
                break;

            case '?':
                if (opt == 'h' || opt == 'r' || opt == 'n' || opt == 'm' || opt == 't' || opt == 'T'|| opt == 'f'|| opt == 'l'){
                    fprintf(stderr, "Option -%c need an argument\n", optopt);
                }else if(isprint(optopt)){
                    fprintf(stderr, "Unknow option -%c\n", optopt);
                }else{
                    fprintf(stderr, "Unknow option character 0x%x\n", optopt);
                }
                show_help = 1;
                break;

            default:
                show_help = 1;
        }
    }

    if (!load_config(config_path)) {
        fprintf(stderr, "Load config file failed: %s\n", optarg);
        loaded = 0;
    }else{
        loaded = 1;
    }
    
    if (show_help == 1 || loaded == 0){
        usage();
    }

    print_params();
    printf("\nGenerator config:\n");
    printf("binary path: %s\n", Worker::source_config.bin_path.c_str());
    printf("env: ");
    for (auto &e : Worker::source_config.env)
        printf("%s\n", e.c_str());
    printf("args: ");
    for (auto &a : Worker::source_config.args)
        printf("%s ", a.c_str());

    printf("\n\nConsumer config:\n");
    printf("binary path: %s\n", consumer_config.bin_path.c_str());
    printf("env: \n");
    for (auto &e : consumer_config.env)
        printf("%s\n", e.c_str());
    printf("args: ");
    for (auto &a : consumer_config.args)
        printf("%s ", a.c_str());
    printf("\n\n");

    //exit(0);
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

    signal(SIGINT, main_sig_handler);
    signal(SIGKILL, main_sig_handler);
    signal(SIGTERM, main_sig_handler);
    atexit(at_exit);

    std::vector<const char*> afl_envp;
    std::vector<const char*> afl_argv;

    // fill argv
    std::string afl_fuzz_path = aflpp_path + "/afl-fuzz";
    afl_argv.push_back(afl_fuzz_path.c_str());
    afl_argv.push_back("-i");
    afl_argv.push_back(afl_config.dir_in.c_str());
    afl_argv.push_back("-o");
    afl_argv.push_back(afl_config.dir_out.c_str());
    afl_argv.push_back("--");
    afl_argv.push_back(consumer_config.bin_path.c_str());
    for (const auto &a : consumer_config.args)
    {
        afl_argv.push_back(a.c_str());
    }
    afl_argv.push_back(0);
    
    // fill envp
    if (!with_afl){
        afl_envp.push_back("AFL_CUSTOM_MUTATOR_ONLY=1");
    }
    afl_envp.push_back("AFL_SKIP_CPUFREQ=1");
    
    // "AFL_CUSTOM_MUTATOR_LIBRARY=/home/proj/proj/src/afl_customut/inject_ts_multi2.so"
    std::string custom_mutator_env = "AFL_CUSTOM_MUTATOR_LIBRARY=" + afl_custom_mutator_path + "/inject_ts.so";
    afl_envp.push_back(custom_mutator_env.c_str());
    /// TODO: really need this?
    for (const auto &e : consumer_config.env)
    {
        afl_envp.push_back(e.c_str());
    }
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
    if (WIFEXITED(status)){
        if (WEXITSTATUS(status) != 0)
            printf("Worker process with PID %ld exited with status 0x%x.\n", (long)worker_pid, WEXITSTATUS(status));
    }
    else if (WIFSIGNALED(status)) printf("Worker process with PID %ld has been terminated by signal %d .\n", (long)worker_pid, WTERMSIG(status));

    kill(afl_pid, SIGKILL);
    waitpid(afl_pid, &status, 0);
    reap_resources();
    return 0;

}
