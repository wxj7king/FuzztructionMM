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
#include <iostream>
#include <vector>
#include <map>
#include <fstream>
#include <sstream>
#include <filesystem>

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
    Patchpoint last_mut;
    bool success;

} my_mutator_t;
#define MAX_FILE_SIZE 4096
#define MAX_INJECTVAL 4096
namespace fs = std::filesystem;

extern "C" {

Patchpoints find_patchpoints(){
    Patchpoints patch_points;
    const char cmd[] = "LD_LIBRARY_PATH=/home/proj/proj/uninstrumented/openssl/ /home/proj/proj/tools/pin-3.28-98749-g6643ecee5-gcc-linux/pin -t /home/proj/proj/src/pintool/find_inst_sites/obj-intel64/find_inst_sites.so -- /home/proj/proj/uninstrumented/openssl/apps/openssl genrsa -aes128 -passout pass:xxxxx -out /tmp/rsak1 512";
    char buffer[128] = {};
    std::string result = "";

    std::shared_ptr<FILE> pipe(popen(cmd, "r"), pclose);
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
    data->patch_points = find_patchpoints();

    return data;

}


size_t afl_custom_post_process(my_mutator_t *data, unsigned char *in_buf, size_t buf_size, unsigned char **out_buf) {
    data->file_count++;
    std::string tmp_file = "/tmp/rsak2";
    std::string cmd1 = "LD_LIBRARY_PATH=/home/proj/proj/uninstrumented/openssl/ timeout 5 /home/proj/proj/tools/pin-3.28-98749-g6643ecee5-gcc-linux/pin -t /home/proj/proj/src/pintool/mutate_ins/obj-intel64/mutate_ins.so -addr @ -val @ -- /home/proj/proj/uninstrumented/openssl/apps/openssl genrsa -aes128 -passout pass:xxxxx -out /tmp/rsak2 512 > /dev/null 2>&1";
    std::string cmd2 = "rm -f /tmp/rsak2";
    size_t pp_idx;
    uint64_t mask = 0x000000000000ffff;
    uint64_t injectValue;
    pp_idx = rand() % data->patch_points.size();
    injectValue = rand() % MAX_INJECTVAL;
    data->patch_points[pp_idx].injectValue = injectValue;
    size_t pos1, pos2;
    pos1 = cmd1.find('@');
    if (data->file_count % 20 == 0) cmd1 = cmd1.replace(pos1, 1, std::to_string(0x30b4));
    else cmd1 = cmd1.replace(pos1, 1, std::to_string(data->patch_points[pp_idx].addr & mask));
    
    pos2 = cmd1.find('@');
    if (data->file_count % 20 == 0) cmd1 = cmd1.replace(pos2, 1, std::to_string(4096));
    else cmd1 = cmd1.replace(pos2, 1, std::to_string(injectValue));
    //printf("cmd: %s\n", cmd1.c_str());

    int ret = system(cmd2.c_str());
    ret = system(cmd1.c_str());
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
        data->last_mut.addr = data->patch_points[pp_idx].addr & mask;
        data->last_mut.injectValue = injectValue;
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

const char *afl_custom_describe(my_mutator_t *data, size_t max_description_len){
    if (data->success){
        std::string des = "mymut_" + std::to_string(data->last_mut.addr) + "_" + std::to_string(data->last_mut.injectValue);
        return des.c_str();
    }else{
        return nullptr;
    }

}

void afl_custom_deinit(my_mutator_t *data) {

    free(data->buf);
    free(data);

}

}


