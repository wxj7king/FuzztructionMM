/*
    New Custom Mutator for AFL++
    Written by Khaled Yakdan <yakdan@code-intelligence.de>
                         Andrea Fioraldi <andreafioraldi@gmail.com>
                         Shengtuo Hu <h1994st@gmail.com>
                         Dominik Maier <mail@dmnk.co>
*/

// You need to use -I/path/to/AFLplusplus/include -I.
#include "afl-fuzz.h"
#include <sys/stat.h> 
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <math.h>
#include <time.h>
#include <iostream>
#include <vector>
#include <map>
#include <fstream>
#include <sstream>
#include <filesystem>
#include <chrono>

typedef struct patch_point{
    uint64_t addr;
    uint64_t injectValue;
} Patchpoint;
typedef std::vector<Patchpoint> Patchpoints;
typedef struct my_mutator {
    afl_state_t *afl;
    unsigned char *buf;
    uint64_t file_count;
    Patchpoints patch_points;
    //Patchpoint last_mut;
    uint64_t file_suffix;
    bool success;

} my_mutator_t;

#define MAX_FILE_SIZE 4096
#define MAX_INJECTVAL 4096
#define MAX_NUM_TS 3
namespace fs = std::filesystem;

extern "C" {

Patchpoints find_patchpoints(uint64_t suffix){

    Patchpoints patch_points;
    std::string cmd = "LD_LIBRARY_PATH=/home/proj/proj/uninstrumented/openssl/ /home/proj/proj/tools/pin-3.28-98749-g6643ecee5-gcc-linux/pin -t /home/proj/proj/src/pintool/find_inst_sites2/obj-intel64/find_inst_sites.so -- /home/proj/proj/uninstrumented/openssl/apps/openssl genrsa -aes128 -passout pass:xxxxx -out @ 512 2>/dev/null";
    cmd = cmd.replace(cmd.find('@'), 1, "/tmp/rsak_" + std::to_string(suffix));
    //printf("cmd :%s\n", cmd.c_str());
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

my_mutator_t *afl_custom_init(afl_state_t *afl, unsigned int seed) {

    //printf("init!\n");
    srand(seed);
    my_mutator_t *data = (my_mutator_t *)calloc(1, sizeof(my_mutator_t));
    if (!data) {
        perror("afl_custom_init alloc");
        return NULL;
    }

    if ((data->buf = (unsigned char *)malloc(MAX_FILE_SIZE)) == NULL) {
        perror("afl_custom_init malloc");
        return NULL;
    }
    
    data->file_count = 0;
    data->afl = afl;
    
    auto now = std::chrono::system_clock::now();
    auto duration = now.time_since_epoch();
    auto millis = std::chrono::duration_cast<std::chrono::milliseconds>(duration).count();
    data->file_suffix = millis;
    data->patch_points = find_patchpoints(data->file_suffix);
    
    return data;

}


size_t afl_custom_post_process(my_mutator_t *data, unsigned char *in_buf, size_t buf_size, unsigned char **out_buf) {
    data->file_count++;

    if (buf_size < 2){
        *out_buf = nullptr;
        buf_size = 0;
        return buf_size;
    }
    //printf("inbuf: %s\n--------------\n", in_buf);
    int num_idx = buf_size >= (MAX_NUM_TS * 2) ? MAX_NUM_TS : (buf_size / 2);
    std::string tmp_file = "/tmp/rsak2_" + std::to_string(data->file_suffix);
    std::string cmd1 = "LD_LIBRARY_PATH=/home/proj/proj/uninstrumented/openssl/ timeout 5 /home/proj/proj/tools/pin-3.28-98749-g6643ecee5-gcc-linux/pin -t /home/proj/proj/src/pintool/mutate_ins2/obj-intel64/mutate_ins.so -addr @ -val @ -- /home/proj/proj/uninstrumented/openssl/apps/openssl genrsa -aes128 -passout pass:xxxxx -out " + tmp_file + " 512 > /dev/null 2>&1";
    std::string cmd2 = "rm -f " + tmp_file;

    uint16_t pp_idx;
    uint64_t injectValue, addr;

    std::string addrs_str = "", injectValues_str = "";
    for (int i = 0; i < num_idx; i ++){
        pp_idx = *(uint16_t *)(in_buf + i*2);
        pp_idx %= data->patch_points.size();
        addr = data->patch_points[pp_idx].addr;
        addrs_str += (std::to_string(addr) + ",");
        injectValue = rand() % MAX_INJECTVAL;
        injectValues_str += (std::to_string(injectValue) + ",");
        data->patch_points[pp_idx].injectValue = injectValue;
        
    }
    addrs_str.pop_back();
    injectValues_str.pop_back();

    size_t pos;
    pos = cmd1.find('@');
    cmd1 = cmd1.replace(pos, 1, addrs_str);
    
    pos = cmd1.find('@');
    cmd1 = cmd1.replace(pos, 1, injectValues_str);
    //printf("cmd: %s\n", cmd1.c_str());

    system(cmd2.c_str());
    system(cmd1.c_str());
    // if(ret != 0){
    //     std::cout << "system function error\n";
    //     return 0;
    // }
    int f = 1;
    std::ifstream mutated_output(tmp_file);
    if (!mutated_output){
        //std::cout << "mutated output file open failed\n";
        f = 1;
        //return -1;
    }else if(fs::file_size(tmp_file) == 0){
        //std::cout << "mutated output file is empty\n";
        f = 1;
    }else{
        //std::cout << "mutated output file is exist!\n";
        *out_buf = data->buf;
        std::stringstream buf;
        buf << mutated_output.rdbuf();
        memcpy(*out_buf, (buf.str()).c_str(), MAX_FILE_SIZE);
        (*out_buf)[MAX_FILE_SIZE - 1] = '\0';
        f = 0;
    }
    
    if (f == 0){
        data->success = true;
        //*out_buf = data->buf;
        buf_size = strlen((char *)(*out_buf));
        //printf("-----------------------\n%s\n%ld\n-----------------------\n\n", data->buf, buf_size);
    }else{
        data->success = false;
        //*out_buf = in_buf;
        *out_buf = nullptr;
        buf_size = 0;
    }
    //printf("-----------------------\n%s\n%ld\n-----------------------\n\n", *out_buf, buf_size);
    return buf_size;

}

void afl_custom_deinit(my_mutator_t *data) {

    free(data->buf);
    free(data);

}

}


