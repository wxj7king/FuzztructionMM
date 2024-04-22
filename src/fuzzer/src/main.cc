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

#include "include/utils.h"
#include "include/worker.h"
#include "include/nlohmann/json.hpp"

// global variables
static pid_t afl_pid;
static pid_t worker_pid;
static std::vector<pthread_t> threads;
static std::vector<ThreadArg> targs;
static ShmPara shm;
static PosixShmPara posix_shm;
static const std::string ftmm_dir = "/tmp/ftmm_workdir";
static const std::string log_dir = "/tmp/ftmm_workdir/ftm_log";
static std::set<std::string> delete_white_list;

/// configurable parameters
static int mut_level = 2;
static size_t max_random_steps = 32;
static size_t max_num_one_mut = 1024;
static size_t num_thread = 1;
static size_t source_timeout = 3;
/// run forever if it is zero
static size_t fuzzer_timeout = 0;
static bool with_afl = false;
static std::string config_path = "";
static BinConfig target_config;
static AflConfig afl_config;

void main_sig_handler(int sig){
    kill(afl_pid, SIGKILL);
    waitpid(afl_pid, 0, 0);

    kill(worker_pid, SIGINT);
    waitpid(worker_pid, 0, 0);

    exit(0);
}

void worker_sig_handler(int sig){
    // kill potential child processes forked by worker threads
    for (const auto& pid : Worker::source_pids){
        if (pid != -1){
            //printf("child process %d exist, kill it\n", pid);
            kill(pid, SIGKILL);
            waitpid(pid, 0, 0);
        }
    }
    // detach from worker threads
    for (const auto& tid : threads){
        //printf("detach from thread %d\n", tid);
        pthread_detach(tid);
    }

    _exit(0);
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

    // destroy shared memory and shared queue
    shmdt(shm.shm_base_ptr);
    shmctl(shm.shm_id, IPC_RMID, NULL);
    mq_unlink(MQNAME);
    munmap(posix_shm.shm_base_ptr, posix_shm.size_in_bytes);
    shm_unlink(POSIX_SHM_NAME);
    printf("\nFuzztruction--: Have a nice day!\n");

}

static bool find_patchpoints(std::string out_dir, Patchpointslock& patch_points){
    std::string source_out = out_dir + "/tmp_source";
    std::string find_ins_out = out_dir + "/tmp_pintool";
    //std::string cmd = "LD_LIBRARY_PATH=/home/proj/proj/uninstrumented/openssl/ /home/proj/proj/tools/pin-3.28-98749-g6643ecee5-gcc-linux/pin -t /home/proj/proj/src/pintool/find_inst_sites2/obj-intel64/find_inst_sites.so -- /home/proj/proj/uninstrumented/openssl/apps/openssl genrsa -aes128 -passout pass:xxxxx -out @ 512 2>/dev/null";
    std::ostringstream oss;
    for (const auto &e : Worker::source_config.env)
    {
        oss << e << " ";
    }
    oss << "/home/proj/proj/tools/pin-3.28-98749-g6643ecee5-gcc-linux/pin" << " ";
    oss << "-t" << " ";
    oss << "/home/proj/proj/src/pintool/find_inst_sites3/obj-intel64/find_inst_sites.so" << " ";
    oss << "-o" << " ";
    oss << find_ins_out << " ";
    oss << "--" << " ";
    oss << Worker::source_config.bin_path << " ";
    for (const auto &a : Worker::source_config.args)
    {   
        if (a == "@@"){
            oss << source_out << " ";
        }else{
            oss << a << " ";
        }
    }
    oss << ">/dev/null 2>&1" << " ";

    std::string cmd = oss.str();
    //printf("cmd: %s\n", cmd.c_str());
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

    if (!std::filesystem::remove(source_out)) std::cerr << "find pps: delete file source_out failed\n";
    if (!std::filesystem::remove(find_ins_out)) std::cerr << "find pps: delete file find_ins_out failed\n";
    
    return true;
}

void *thread_worker(void* arg){
    ThreadArg *targ = (ThreadArg *)arg;
    Worker worker(targ->tid, mut_level);
    worker.start();
    return nullptr;
}

static void child_process(){
    std::string out_dir = ftmm_dir;
    if (!find_patchpoints(out_dir, Worker::source_pps)) {
        perror("find_patchpoints() failed!\n");
        return;
    }
    // return;
    Worker::source_unfuzzed_pps.pps = Worker::source_pps.pps;
    
    // std::random_device rd;
    // std::mt19937 gen(rd());
    // std::shuffle(unfuzzed_pps.begin(), unfuzzed_pps.end(), gen);

    for (size_t i = 0; i < num_thread; i++){
        targs[i].tid = i;
        int rc = pthread_create(&threads[i], NULL, thread_worker, (void *)&targs[i]);
        if (rc) {
            perror("pthread_create()");
            _exit(EXIT_FAILURE);
        }
    }

    // wait for all workers even though they will not return
    for (size_t i = 0; i < num_thread; i++){
        int rc = pthread_join(threads[i], NULL);
        if (rc) {
            perror("pthread_join()");
            _exit(EXIT_FAILURE);
        }
        //printf("thread %ld exited!\n", threads[i]);
    }
}

static bool init(){
    threads.resize(num_thread);
    targs.resize(num_thread);

    Worker::max_random_steps = max_random_steps;
    Worker::max_num_one_mut = max_num_one_mut;
    Worker::num_thread = num_thread;
    Worker::source_timeout = source_timeout;

    Worker::source_pids.assign(num_thread, -1);
    Worker::ftmm_dir = ftmm_dir;
    Worker::new_selection_config.interest_num = 10;
    Worker::new_selection_config.unfuzzed_num = 20;
    Worker::new_selection_config.random_num = 10;

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
    Worker::my_mqattr.mq_maxmsg = 10;
    Worker::my_mqattr.mq_msgsize = sizeof(TestCase);
    Worker::my_mqattr.mq_curmsgs = 0;
    mqd_t tmp_mqd = mq_open(MQNAME, O_CREAT | O_EXCL,  0600, &Worker::my_mqattr);
    if (tmp_mqd == -1){
        perror ("mq_open");
        return false;
    }
    mq_close(tmp_mqd);

    // initialize shared memory
    shm.size_in_bytes = num_thread * sizeof(Masks);
    shm.key = ftok(SHM_NAME, 'A');
    shm.shm_id = shmget(shm.key, shm.size_in_bytes, IPC_CREAT | IPC_EXCL | 0666);
    if (shm.shm_id == -1){
        if (errno == EEXIST) {
            std::cout << "shared memory exists\n";
            std::cout << "recreate it\n";
            int tmp_id = shmget(shm.key, 0, 0);
            if (tmp_id == -1) {
                std::cerr << "shm_get failed again\n";
                return false;
            }
            if (shmctl(tmp_id, IPC_RMID, NULL) == -1){
                std::cerr << "delete failed";
                return false;
            }
            shm.shm_id = shmget(shm.key, shm.size_in_bytes, IPC_CREAT | IPC_EXCL | 0666);
            if (shm.shm_id == -1){
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
    shm.shm_base_ptr = (unsigned char *)shmat(shm.shm_id, NULL, 0);
    if (shm.shm_base_ptr == (void *)-1){
        std::cerr << "shmat() failed!\n";
        return false;
    }
    printf("shared memory created successfully! Size: %ld Bytes\n", shm.size_in_bytes);
    Worker::shm = shm;

    // initialize shared memory between afl++
    shm_unlink(POSIX_SHM_NAME);
    if ((posix_shm.shmfd = shm_open(POSIX_SHM_NAME, O_CREAT | O_EXCL | O_RDWR, 0666)) != -1){
        posix_shm.size_in_bytes = sizeof(size_t) * num_thread;
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
    // tell afl++ the size of shared memory
    *((size_t *)posix_shm.shm_base_ptr) = sizeof(size_t) * num_thread;
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

    shmdt(shm.shm_base_ptr);
    shmctl(shm.shm_id, IPC_RMID, NULL);
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

    try
    {   
        nlohmann::json data = nlohmann::json::parse(f);
        // generator
        for (const auto &e : data["generator"]["env"])
            Worker::source_config.env.push_back(e);
        Worker::source_config.bin_path = data["generator"]["bin_path"];
        for (const auto &e : data["generator"]["args"])
            Worker::source_config.args.push_back(e);
        // target
        for (const auto &e : data["target"]["env"])
            target_config.env.push_back(e);
        target_config.bin_path = data["target"]["bin_path"];
        for (const auto &e : data["target"]["args"])
            target_config.args.push_back(e);
        // afl++
        afl_config.dir_in = data["afl++"]["dir_in"];
        afl_config.dir_out = data["afl++"]["dir_out"];
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
        "\n  -f config_file    config file of parameters of source and sink binary"
        "\n  -r num            maxmium steps for random mutation (default: 32)"
        "\n  -n num_thread     number of threads (default: 1)"
        "\n  -T seconds        fuzzer terminates after this time period (default: forever)"
        "\n  -t seconds        timeout for each run of mutated source binary (default: 3s)"
        "\n  -m num            maximum number of test cases one mutation can produce (default: 1024)"
        "\n  -l mut_level      mutation level, 1 or 2, more fine-grained more higher (default: 2)"
        "\n  -a                use mutations of AFL++ (default: false)"
        "\n  -h help           show help\n"
        ;
    fprintf(stderr, "Fuzztrunction-- v0.1\n%s\n", table);
    exit(1);
}

static void print_params(){
    const char* params = 
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
    
    printf(params, config_path.c_str(), max_random_steps, num_thread, fuzzer_timeout, source_timeout, max_num_one_mut, mut_level, with_afl);
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
                    fprintf(stderr, "Invalid value of the fuzzer: %s\n", optarg);
                    show_help = 1;
                }
                break;

            case 't':
                source_timeout = atoll(optarg);
                if (source_timeout == 0){
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
                mut_level = atoi(optarg);
                if (mut_level != 1 && mut_level != 2){
                    fprintf(stderr, "Invalid value of mutation level: %s\n", optarg);
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
    printf("env: \n");
    for (auto &e : Worker::source_config.env)
        printf("%s\n", e.c_str());
    printf("args: ");
    for (auto &a : Worker::source_config.args)
        printf("%s ", a.c_str());

    printf("\n\nTarget config:\n");
    printf("binary path: %s\n", target_config.bin_path.c_str());
    printf("env: \n");
    for (auto &e : target_config.env)
        printf("%s\n", e.c_str());
    printf("args: ");
    for (auto &a : target_config.args)
        printf("%s ", a.c_str());
    printf("\n");

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
    afl_argv.push_back("/home/proj/proj/AFLplusplus/afl-fuzz");
    afl_argv.push_back("-i");
    afl_argv.push_back(afl_config.dir_in.c_str());
    afl_argv.push_back("-o");
    afl_argv.push_back(afl_config.dir_out.c_str());
    afl_argv.push_back("--");
    afl_argv.push_back(target_config.bin_path.c_str());
    for (const auto &a : target_config.args)
    {
        afl_argv.push_back(a.c_str());
    }
    afl_argv.push_back(0);
    
    // fill envp
    if (!with_afl){
        afl_envp.push_back("AFL_CUSTOM_MUTATOR_ONLY=1");
    }
    afl_envp.push_back("AFL_CUSTOM_MUTATOR_LIBRARY=/home/proj/proj/src/afl_customut/inject_ts_multi2.so");
    /// TODO: really need this?
    for (const auto &e : target_config.env)
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
    if (WIFEXITED(status)) printf("Worker process with PID %ld exited with status 0x%x.\n", (long)worker_pid, WEXITSTATUS(status));
    else if (WIFSIGNALED(status)) printf("Worker process with PID %ld has been terminated by signal %d .\n", (long)worker_pid, WTERMSIG(status));

    // waitpid(afl_pid, &status, 0);
    // if (WIFEXITED(status)) printf("worker process with PID %ld exited with status 0x%x.\n", (long)afl_pid, WEXITSTATUS(status));
    // else printf("afl not exited?!\n");
    kill(afl_pid, SIGKILL);
    waitpid(afl_pid, &status, 0);
    reap_resources();
    return 0;

}
