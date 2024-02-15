#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdint.h>
#include <mqueue.h>
#include <string.h>
#include <assert.h>
#include <sys/wait.h>
#include <vector>
#include <string>
#include <memory>
#include <filesystem>
#include <chrono>
#include <sstream>
#include <fstream>
#include <random>
#include <time.h>

#define MQNAME "/TEST_MQ"

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
pid_t pids[4];
#define MAX_FILE_SIZE 4096
#define MAX_INJECTVAL 4096

Patchpoints find_patchpoints(std::string out_dir){
    Patchpoints patch_points;
    std::string cmd = "LD_LIBRARY_PATH=/home/proj/proj/uninstrumented/openssl/ /home/proj/proj/tools/pin-3.28-98749-g6643ecee5-gcc-linux/pin -t /home/proj/proj/src/pintool/find_inst_sites/obj-intel64/find_inst_sites.so -- /home/proj/proj/uninstrumented/openssl/apps/openssl genrsa -aes128 -passout pass:xxxxx -out @ 512 2>/dev/null";
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
    std::ostringstream tmp_ss;
    
    tmp_ss << "LD_LIBRARY_PATH=/home/proj/proj/uninstrumented/openssl/ timeout 5 /home/proj/proj/tools/pin-3.28-98749-g6643ecee5-gcc-linux/pin -t /home/proj/proj/src/pintool/mutate_ins/obj-intel64/mutate_ins.so -addr @ -val @ -- /home/proj/proj/uninstrumented/openssl/apps/openssl genrsa -aes128 -passout pass:xxxxx -out ";
    tmp_ss << out_file;
    tmp_ss << " 512 > /dev/null 2>&1";
    std::string cmd1 = tmp_ss.str();
    //std::string cmd2 = "rm -f /tmp/rsak2";
    size_t pp_idx;
    uint64_t mask = 0x000000000000ffff;
    uint64_t injectValue, addr;

    std::random_device rd;
    std::mt19937 gen(rd()); // Mersenne Twister engine
    // Create a uniform distribution for the range
    std::uniform_int_distribution<int> dist_idx(0, patch_points.size());
    std::uniform_int_distribution<int> dist_val(0, MAX_INJECTVAL);

    pp_idx = dist_idx(gen);
    addr = patch_points[pp_idx].addr;
    injectValue = dist_val(gen);
    // addr = 0x30b4;
    // injectValue = 4096;
    patch_points[pp_idx].injectValue = injectValue;
    size_t pos1, pos2;
    pos1 = cmd1.find('@');
    cmd1 = cmd1.replace(pos1, 1, std::to_string(addr & mask));
    
    pos2 = cmd1.find('@');
    cmd1 = cmd1.replace(pos2, 1, std::to_string(injectValue));
    printf("cmd: %s\n", cmd1.c_str());

    // TODO: set maximum file size limit
    int ret = system(cmd1.c_str());
    // if(ret != 0){
    //     std::cout << "system function error\n";
    //     return 0;
    // }
    int f = 1;
    std::ifstream mutated_output(out_file);
    if (!mutated_output){
        //std::cout << "mutated output file open failed\n";
        f = 1;
        //return -1;
    }else if(std::filesystem::file_size(out_file) == 0){
        //std::cout << "mutated output file is empty\n";
        f = 1;
    }else{
        //std::cout << "mutated output file is exist!\n";
        f = 0;
    }

    TestCase testcase;
    if (f){
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
            exit(1);
        }
    }
    Patchpoints pps = find_patchpoints(out_dir);
    mqd_t mqd = mq_open (MQNAME, O_CREAT | O_RDWR,  0600, &my_mqattr);
    if (mqd == -1){
        perror ("mq_open");
        exit (1);
    }

    int i = 1000;    
    //sprintf(ts.filename, "From child process %d", id);
    while(i--){
        TestCase ts = generate_testcase(id, pps);
        mq_send(mqd, (const char *)&ts, sizeof(TestCase), 1);
    }
    mq_close(mqd);
    //mq_unlink(MQNAME);
    //if(!std::filesystem::remove(out_dir)) printf("failed to delete dir '%s'\n", out_dir.c_str());
    exit(0);
}

void signal_handler(int sig){

    for (int i = 0; i < 4; i++){
        kill(pids[i], SIGKILL);
    }
    for (int i = 0; i < 4; i++){
        out_dir = "/tmp/ftm_workerDir_" + std::to_string(i);
        if(!std::filesystem::remove_all(out_dir)) printf("failed to delete dir '%s'\n", out_dir.c_str());
    }
    
    mq_unlink(MQNAME);
    printf("Have a nice day!\n");
    exit(0);
}


int main(){
    //pid_t pids[4];
    int n = 4;
    my_mqattr.mq_flags = O_NONBLOCK;
    my_mqattr.mq_maxmsg = 10;
    my_mqattr.mq_msgsize = sizeof(TestCase);
    my_mqattr.mq_curmsgs = 0;

    for (int i = 0; i < n; i++) {
        if ((pids[i] = fork()) < 0) {
            perror("fork");
            abort();
        } else if (pids[i] == 0) {
            child_process(i);
            exit(0);
        }
    }
    signal(SIGINT, signal_handler);
    int count = 4000;
    mqd_t mqd = mq_open (MQNAME, O_CREAT | O_RDWR,  0600, &my_mqattr);
    if (mqd == -1){
        perror ("mq_open");
        exit (1);
    }
    struct mq_attr attr;
    assert(mq_getattr(mqd, &attr) != -1);
    //assert(mq_setattr(mqd, &my_mqattr, &attr) != -1);
    printf("mq_flags %ld\n",  attr.mq_flags);
    printf("mq_maxmsg %ld\n", attr.mq_maxmsg);
    printf("mq_msgsize %ld\n",attr.mq_msgsize);
    printf("mq_curmsgs %ld\n",attr.mq_curmsgs);

    char *buffer = (char *)calloc(attr.mq_msgsize, 1);
    assert(buffer != NULL);
    unsigned int pri;
    while(count--){
        while(1){
            int ret = mq_receive(mqd, buffer, attr.mq_msgsize, &pri);
            if (ret == -1) {
                if (errno == EAGAIN){
                    //printf("MQ currently empty.\n");
                    sleep(1);
                    continue;
                }else{
                    perror("mq_receive");
                    exit(EXIT_FAILURE);
                }
            }
            break;
            
        }
        
        //int ret = mq_timedreceive(mqd, buffer, attr.mq_msgsize, &pri, &timeout);
        
        printf("Received [priority %u]: '%s'\n", pri, ((TestCase *)buffer)->filename);
        TestCase *ts_ptr = (TestCase *)buffer;
        if (strcmp(ts_ptr->filename, "") != 0){
            std::string filename = ts_ptr->filename;
            std::stringstream buf;
            std::ifstream mutated_output(filename);
            buf << mutated_output.rdbuf();
            printf("Addr: %ld, Value: %ld\n", ts_ptr->patch_point.addr, ts_ptr->patch_point.injectValue);
            printf("Content: \n%s\n", (buf.str()).c_str());
            std::filesystem::remove(filename);
        }
    }
    free(buffer);
    //mq_close(mqd);
    
    int status;
    pid_t pid;
    while (n > 0) {
        pid = wait(&status);
        printf("Child with PID %ld exited with status 0x%x.\n", (long)pid, status);
        --n;  // TODO(pts): Remove pid from the pids array.
    }
    mq_unlink(MQNAME);
}