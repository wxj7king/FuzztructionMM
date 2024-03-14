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
#include <string>
#include <memory>
#include <filesystem>
#include <chrono>
#include <sstream>
#include <fstream>
#include <random>
#include <iostream>

#define MQNAME "/TEST_MQ"
#define MAX_FILE_SIZE 16 * 1024
#define MAX_INJECTVAL 4096
#define NUM_PROC 8
#define TIMEOUT 5
#define NUM_TESTCASE 3
typedef struct patch_point{
    uint64_t addr;
    uint64_t injectValue;
} Patchpoint;
typedef struct test_case{
    char filename[255];
    Patchpoint patch_point;
}TestCase;
typedef std::vector<Patchpoint> Patchpoints;
struct mq_attr my_mqattr;
std::string out_dir = "";
pid_t pids[NUM_PROC];
pid_t afl_pid;
int num_process = NUM_PROC;
static volatile int timeout_flag;

void timeout_handler(int sig){
    timeout_flag = 1;
}

Patchpoints find_patchpoints(std::string out_dir){
    Patchpoints patch_points;
    std::string cmd = "LD_LIBRARY_PATH=/home/proj/proj/uninstrumented/openssl/ /home/proj/proj/tools/pin-3.28-98749-g6643ecee5-gcc-linux/pin -t /home/proj/proj/src/pintool/find_inst_sites2/obj-intel64/find_inst_sites.so -- /home/proj/proj/uninstrumented/openssl/apps/openssl genrsa -aes128 -passout pass:xxxxx -out @ 512 2>/dev/null";
    out_dir = out_dir + "/tmp_rsak";
    cmd = cmd.replace(cmd.find('@'), 1, out_dir);
    char buffer[128] = {};
    std::string result = "";

    std::shared_ptr<FILE> pipe(popen(cmd.c_str(), "r"), pclose);
    if (!pipe) throw std::runtime_error("popen() failed!");
    while (!feof(pipe.get())) {
        if (fgets(buffer, 128, pipe.get()) != NULL){
            Patchpoint pp;
            result = buffer;
            pp.addr = std::stoul(result.substr(0, result.find(',')), nullptr, 16);
            //printf("%lx, %s\n", pp.addr, buffer);
            patch_points.push_back(pp);
        }
    }
    
    //flip_branch(patch_points);
    return patch_points;

}

TestCase generate_testcase(int id, Patchpoints &patch_points){
    auto now = std::chrono::system_clock::now();
    auto duration = now.time_since_epoch();
    auto millis = std::chrono::duration_cast<std::chrono::milliseconds>(duration).count();
    std::string timestamp = std::to_string(millis);
    std::string out_file = out_dir + "/rsak_" + timestamp;
    std::vector<const char*> source_argv;
    std::vector<const char*> source_envp;
    size_t pp_idx;
    uint64_t injectValue, addr;

    std::random_device rd;
    std::mt19937 gen(rd()); // Mersenne Twister engine
    // Create a uniform distribution for the range
    std::uniform_int_distribution<int> dist_idx(0, patch_points.size());
    std::uniform_int_distribution<int> dist_val(0, MAX_INJECTVAL);

    std::string addrs_str = "", injectValues_str = "";
    for (size_t i = 0; i < NUM_TESTCASE; i ++){
        pp_idx = dist_idx(gen);
        addr = patch_points[pp_idx].addr;
        addrs_str += (std::to_string(addr) + ",");
        injectValue = dist_val(gen);
        injectValues_str += (std::to_string(injectValue) + ",");
        patch_points[pp_idx].injectValue = injectValue;
        
    }
    addrs_str.pop_back();
    injectValues_str.pop_back();
    // pp_idx = dist_idx(gen);
    // addr = patch_points[pp_idx].addr;
    // injectValue = dist_val(gen);
    // // addr = 0x2030b4;
    // // injectValue = 4096;
    // patch_points[pp_idx].injectValue = injectValue;
    // const char* addr_str = std::to_string(addr).c_str();
    // const char* injectValue_str = std::to_string(injectValue).c_str();

    // argv and envp
    source_argv.push_back("/home/proj/proj/tools/pin-3.28-98749-g6643ecee5-gcc-linux/pin");
    source_argv.push_back("-t");
    source_argv.push_back("/home/proj/proj/src/pintool/mutate_ins2/obj-intel64/mutate_ins.so");
    source_argv.push_back("-addr");
    source_argv.push_back(addrs_str.c_str());
    source_argv.push_back("-val");
    source_argv.push_back(injectValues_str.c_str());
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

    // printf("addr: %s, injectvalue: %s\n", source_argv[4], source_argv[6]);
    // printf("cmd: \n");
    // std::vector<const char*>::iterator it;
    // for(it = source_argv.begin(); it != source_argv.end(); it++){
    //     std::cout << *it << " ";
    // }

    // TODO: set maximum file size limit
    // TODO: replace system() with execve()
    int pid = fork();
    if (pid == -1){
        perror("fork failed!");
        _exit(1);
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
        execve(source_argv[0], const_cast<char* const*>(source_argv.data()), const_cast<char* const*>(source_envp.data()));
        perror("execve failed!");
        _exit(1);
    }

    signal(SIGALRM, timeout_handler);
    alarm(TIMEOUT);
    waitpid(pid, NULL, 0);
    // if(ret != 0){
    //     std::cout << "system function error\n";
    //     return 0;
    // }
    int fail = 1;
    std::ifstream mutated_output(out_file);
    if (timeout_flag){
        printf("timeout occured!\n");
        fail = 1;
    }else if (!mutated_output){
        //std::cout << "mutated output file open failed\n";
        fail = 1;
    }else if(std::filesystem::file_size(out_file) == 0){
        //std::cout << "mutated output file is empty\n";
        fail = 1;
    }else{
        //std::cout << "mutated output file is exist!\n";
        fail = 0;
    }

    TestCase testcase;
    if (fail){
        memset(testcase.filename, 0, sizeof(testcase.filename));
    }else{
        memcpy(testcase.filename, out_file.c_str(), sizeof(testcase.filename));
        testcase.patch_point.addr = addr;
        testcase.patch_point.injectValue = injectValue;
    }
    return testcase;

}

void child_process(int id){
    out_dir = "/tmp/ftm_workerDir_" + std::to_string(id);
    if (!std::filesystem::exists(out_dir)){
        if (!std::filesystem::create_directory(out_dir)) {
            printf("failed to create directory in process %d\n", id);
            _exit(1);
        }
    }
    Patchpoints pps = find_patchpoints(out_dir);
    
    mqd_t mqd = mq_open (MQNAME, O_CREAT | O_RDWR,  0600, &my_mqattr);
    if (mqd == -1){
        perror("mq_open");
        _exit(1);
    }

    int i = 1000000;

    //sprintf(ts.filename, "From child process %d", id);
    while(i--){
        timeout_flag = 0;
        TestCase ts = generate_testcase(id, pps);
        mq_send(mqd, (const char *)&ts, sizeof(TestCase), 1);
    }
    mq_close(mqd);
    //mq_unlink(MQNAME);
    if (out_dir != ""){
        if(!std::filesystem::remove_all(out_dir)) printf("failed to delete dir '%s'\n", out_dir.c_str());
    }
    _exit(0);
}

void signal_handler(int sig){
    for (int i = 0; i < NUM_PROC; i++){
        // SIGTERM
        //kill(pids[i], SIGKILL);
        kill(pids[i], SIGTERM);
    }
    kill(afl_pid, SIGKILL);
    for (int i = 0; i < NUM_PROC; i++){
        out_dir = "/tmp/ftm_workerDir_" + std::to_string(i);
        if(!std::filesystem::remove_all(out_dir)) printf("failed to delete dir '%s'\n", out_dir.c_str());
    }
    
    mq_unlink(MQNAME);
    printf("\nHave a nice day!\n");
    exit(0);
}


int main(){

    my_mqattr.mq_flags = 0;
    my_mqattr.mq_maxmsg = 10;
    my_mqattr.mq_msgsize = sizeof(TestCase);
    my_mqattr.mq_curmsgs = 0;

    for (int i = 0; i < num_process; i++) {
        if ((pids[i] = fork()) < 0) {
            perror("fork");
            abort();
        } else if (pids[i] == 0) {
            child_process(i);
            _exit(0);
        }
    }
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
    if(afl_pid == 0){
        execve(afl_argv[0], const_cast<char* const*>(afl_argv.data()), const_cast<char* const*>(afl_envp.data()));
        perror("execve failed!\n");
    }
    
    while (num_process > 0) {
        pid_t pid = wait(&status);
        printf("Child with PID %ld exited with status 0x%x.\n", (long)pid, status);
        --num_process;  // TODO(pts): Remove pid from the pids array.
    }

    waitpid(afl_pid, &status, 0);
    printf("afl-fuzz with PID %ld exited with status 0x%x.\n", (long)afl_pid, status);
    return 0;

}
