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
#include <mqueue.h>
//#include <assert.h>
#include <iostream>
#include <fstream>
#include <sstream>
#include <filesystem>

typedef struct patch_point{
    uint64_t addr;
    uint8_t reg_size;
    uint64_t next_mov_b4_jmp;
} Patchpoint;

typedef struct test_case{
    char filename[255];
    char filehash[65];
    Patchpoint patch_point;
    int mut_type;
    int worker_id;
    size_t multi_num;
}TestCase;

typedef struct posix_shm_para{
    int shmfd;
    unsigned char *shm_base_ptr;
    size_t size_in_bytes;
}PosixShmPara;

typedef struct my_mutator {
    afl_state_t *afl;
    unsigned char *buf;
    unsigned char *msg_buf;
    size_t ts_counter;
    bool success;
    struct mq_attr my_mqattr;
    PosixShmPara posix_shm;
    mqd_t mqd;
    unsigned int mq_pri;
    char ts_description[256];
} my_mutator_t;

#define MQNAME "/FTMM_MQ"
#define POSIX_SHM_NAME "FTMM_AFL_SHM"

static const char *mut_types[] = {"byte_flip", "bit_flip", "rand_byte", "rand_byte0", "u8add", "havoc",
                                  "byte_flip_multi", "bit_flip_multi", "rand_byte_multi", "rand_byte0_multi", "u8add_multi", "havoc_multi",
                                  "branch_flip", "branch_flip_next", "branch_flip_multi"
                                  };
extern "C" {

my_mutator_t *afl_custom_init(afl_state_t *afl, unsigned int seed) {
    my_mutator_t *data = (my_mutator_t *)calloc(1, sizeof(my_mutator_t));
    if (!data) {
        perror("afl_custom_init calloc");
        return NULL;
    }

    if ((data->buf = (unsigned char *)malloc(MAX_FILE)) == NULL) {
        perror("afl_custom_init malloc");
        return NULL;
    }

    data->my_mqattr.mq_flags = 0;
    // data->my_mqattr.mq_maxmsg = 30;
    data->my_mqattr.mq_maxmsg = 10;
    data->my_mqattr.mq_msgsize = sizeof(TestCase);
    data->my_mqattr.mq_curmsgs = 0;
    mqd_t mqd = mq_open (MQNAME, O_RDWR,  0600, &data->my_mqattr);
    if (mqd == -1){
        perror("mq_open");
        return NULL;
    }
    // struct mq_attr old_attr;
    // data->my_mqattr.mq_flags = O_NONBLOCK;
    // assert(mq_getattr(mqd, &old_attr) != -1);
    // assert(mq_setattr(mqd, &data->my_mqattr, &old_attr) != -1);

    // initialize shared memory between fuzzer
    if ((data->posix_shm.shmfd = shm_open(POSIX_SHM_NAME, O_RDWR, 0666)) != -1){
        if ((data->posix_shm.shm_base_ptr = (unsigned char *)mmap(NULL, sizeof(size_t), PROT_READ | PROT_WRITE, MAP_SHARED, data->posix_shm.shmfd, 0)) == MAP_FAILED){
            perror("mmap() failed\n");
            return NULL;
        }
        data->posix_shm.size_in_bytes = *((size_t *)data->posix_shm.shm_base_ptr);
        if ((data->posix_shm.shm_base_ptr = (unsigned char *)mremap(data->posix_shm.shm_base_ptr, sizeof(size_t), data->posix_shm.size_in_bytes, MREMAP_MAYMOVE)) == MAP_FAILED){
            perror("mremap() failed\n");
            return NULL;
        }
        // clear
        //*((size_t *)data->posix_shm.shm_base_ptr) = 0;

    }else{
        perror("shm_open() failed\n");
        return NULL;
    }

    data->mqd = mqd;
    data->ts_counter = 0;
    data->afl = afl;
    if ((data->msg_buf = (unsigned char *)malloc(sizeof(TestCase))) == NULL) {
        perror("afl_custom_init malloc");
        return NULL;
    }
    data->mq_pri = 1;
    data->success = false;
    return data;

}

size_t afl_custom_fuzz(my_mutator_t *data, uint8_t *buf, size_t buf_size,
                       u8 **out_buf, uint8_t *add_buf,
                       size_t add_buf_size,  // add_buf can be NULL
                       size_t max_size) {
    
    // printf("in afl_custom_fuzz %ld, %ld\n", data->ts_counter, max_size);
    // default untouched buf
    u32 out_size = buf_size;
    *out_buf = buf;

    ssize_t ret = mq_receive(data->mqd, (char *)data->msg_buf, data->my_mqattr.mq_msgsize, &data->mq_pri);
    if (ret == -1) {
        if (errno == EAGAIN){
            //printf("MQ currently empty.\n");
        }else{
            perror("mq_receive");
        }
        data->success = false;
        return out_size;
    }
    
    TestCase *ts_ptr = (TestCase *)data->msg_buf;
    size_t *count_ptr = (size_t *)data->posix_shm.shm_base_ptr;
    count_ptr[ts_ptr->worker_id + 1]++;

    if (strcmp(ts_ptr->filename, "") != 0){
        data->ts_counter++;
        data->success = true;
        memset(data->buf, 0, MAX_FILE);
        *out_buf = data->buf;
        // read content
        std::string filename = ts_ptr->filename;
        std::stringstream buf;
        std::ifstream mutated_output(filename);
        if (mutated_output.is_open()){
            mutated_output.read(reinterpret_cast<char *>(*out_buf), max_size);
            out_size = mutated_output.gcount();
        }
        // printf("Addr: %lu, Value: %u\n", ts_ptr->patch_point.addr, ts_ptr->patch_point.reg_size);
        // printf("Content: \n%s\n", *out_buf);
        std::filesystem::remove(filename);
    }else{
        data->success = false;
    }

    return out_size;
}

uint32_t afl_custom_fuzz_count(my_mutator_t *data, const u8 *buf, size_t buf_size){
    data->afl->stage_name = (uint8_t *)"Fuzztruction--";
    data->afl->stage_short = (uint8_t *)"Fuzztruction--";
    if (data->afl->afl_env.afl_custom_mutator_only)
        return (uint32_t)(64 * 1024);
    else
        return (uint32_t)(1024);
}

// size_t afl_custom_post_process(my_mutator_t *data, unsigned char *in_buf, size_t buf_size, unsigned char **out_buf) {
//     size_t out_size = buf_size;
//     *out_buf = in_buf;
//     if (!data->success){
//         if (unlikely(strcmp(reinterpret_cast<const char*>(data->afl->stage_name), "Fuzztruction--") != 0)){
//             data->success = true;
//         }else{
//             *out_buf = NULL;
//             out_size = 0;
//         }
//     }
//     return out_size;
// }

const char *afl_custom_describe(my_mutator_t *data, size_t max_description_len){
    //printf("in describe!\n");
    char *ret = data->ts_description;
    memset(ret, 0, 256);
    if (data->success){
        TestCase *ts_ptr = (TestCase *)data->msg_buf;
        char addr[32];
        snprintf(addr, 32, "0x%lx", ts_ptr->patch_point.addr);
        strcat(ret, "addr:");
        strcat(ret, addr);
        strcat(ret, ",mut:");
        strcat(ret, mut_types[ts_ptr->mut_type]);
        if (ts_ptr->mut_type >= 6 && ts_ptr->mut_type < 12){
            strcat(ret, ",num_pps:");
            strcat(ret, std::to_string(ts_ptr->multi_num).c_str());
        }
        //printf("addr: %lx, mut: %d\n", ts_ptr->patch_point.addr, ts_ptr->mut_type);
    }else{           
        strcat(ret, "origin");
    }  
    return ret;
}

void afl_custom_deinit(my_mutator_t *data) {
    free(data->buf);
    free(data);
    free(data->msg_buf);
    mq_close(data->mqd);
    munmap(data->posix_shm.shm_base_ptr, data->posix_shm.size_in_bytes);

}

}


