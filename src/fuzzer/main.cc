#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <mqueue.h>
#include <string.h>
#include <assert.h>
#include <sys/wait.h>
#include <sys/resource.h>

#include <string>
#include <memory>
#include <filesystem>
#include <chrono>
#include <sstream>
#include <fstream>
#include <random>
#include <iostream>
#include <algorithm>

#include <condition_variable>
#include <openssl/evp.h>
#include <openssl/sha.h>
#include <sys/ipc.h>
#include <sys/shm.h>

//#include "utils.h"
#include "include/utils.h"
#include "include/worker.h"

// global variables
static pid_t afl_pid;
static pid_t worker_pid;
static pthread_t threads[NUM_THREAD];
static ThreadArg targs[NUM_THREAD];
static Shm_para shm_para;
static std::string ftmm_dir = "/tmp/ftmm_workdir";
static std::set<std::string> delete_white_list;
static int mut_level;


static bool find_patchpoints(std::string out_dir, Patchpointslock& patch_points){
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


void *thread_worker(void* arg){
    ThreadArg *targ = (ThreadArg *)arg;
    Worker worker(targ->tid, mut_level);
    worker.start();
    return nullptr;
}

void main_signal_handler(int sig){
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
    shmctl(shm_para.shm_id, IPC_RMID, NULL);
    mq_unlink(MQNAME);
    printf("\nFuzztruction--: Have a nice day!\n");

}

static void child_process(){
    std::string out_dir = ftmm_dir;
    if (!find_patchpoints(out_dir, Worker::source_pps)) {
        perror("find_patchpoints() failed!\n");
        return;
    }
    // return;
    Worker::source_unfuzzed_pps.pps = Worker::source_pps.pps;
    Worker::ftmm_dir = ftmm_dir;
    // std::random_device rd;
    // std::mt19937 gen(rd());
    // std::shuffle(unfuzzed_pps.begin(), unfuzzed_pps.end(), gen);

    for (int i = 0; i < NUM_THREAD; i++){
        targs[i].tid = i;
        int rc = pthread_create(&threads[i], NULL, thread_worker, (void *)&targs[i]);
        if (rc) {
            perror("pthread_create()");
            _exit(EXIT_FAILURE);
        }
    }

    // wait for all workers even though they will not return
    for (int i = 0; i < NUM_THREAD; i++){
        int rc = pthread_join(threads[i], NULL);
        if (rc) {
            perror("pthread_join()");
            _exit(EXIT_FAILURE);
        }
        //printf("thread %ld exited!\n", threads[i]);
    }
}

static bool init(){
    Worker::my_mqattr.mq_flags = 0;
    Worker::my_mqattr.mq_maxmsg = 10;
    Worker::my_mqattr.mq_msgsize = sizeof(TestCase);
    Worker::my_mqattr.mq_curmsgs = 0;

    Worker::new_selection_config.interest_num = 10;
    Worker::new_selection_config.unfuzzed_num = 20;
    Worker::new_selection_config.random_num = 10;

    auto now = std::chrono::system_clock::now();
    auto duration = now.time_since_epoch();
    auto millis = std::chrono::duration_cast<std::chrono::milliseconds>(duration).count();
    std::string timestamp = std::to_string(millis);
    std::string log_dir = ftmm_dir + "/ftm_log";
    Worker::log_path = log_dir + "/log_" + timestamp;
    if (!std::filesystem::exists(log_dir)){
        if (!std::filesystem::create_directories(log_dir)) {
            printf("failed to create directory: %s\n", log_dir.c_str());
            return false;
        }
    }
    delete_white_list.insert("ftm_log");

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
    Worker::shm_para = shm_para;

    mut_level = 2;

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

    shmctl(shm_para.shm_id, IPC_RMID, NULL);
    mq_unlink(MQNAME);

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

    signal(SIGINT, main_signal_handler);
    signal(SIGKILL, main_signal_handler);
    signal(SIGTERM, main_signal_handler);
    atexit(at_exit);

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
