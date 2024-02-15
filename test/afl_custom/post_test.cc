/*
  New Custom Mutator for AFL++
  Written by Khaled Yakdan <yakdan@code-intelligence.de>
             Andrea Fioraldi <andreafioraldi@gmail.com>
             Shengtuo Hu <h1994st@gmail.com>
             Dominik Maier <mail@dmnk.co>
*/

// You need to use -I/path/to/AFLplusplus/include -I.
#include "afl-fuzz.h"
#include <iostream>
#include <vector>
#include <map>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

std::map<int, std::string> cipher = {
  {0, "aes-128-cbc"},
  {1, "aes-128-ecb"},
  {2, "aes-192-cbc"},
  {3, "aes-192-ecb"},
  {4, "aes-256-cbc"},
  {5, "aes-256-ecb"},
  
  {6, "camellia-128-cbc"},
  {7, "camellia-128-ecb"},
  {8, "camellia-192-cbc"},
  {9, "camellia-192-ecb"},
  {10, "camellia-256-cbc"},
  {11, "camellia-256-ecb"}

};

typedef struct my_mutator {

  afl_state_t *afl;
  unsigned char *buf;
  unsigned int file_count;

} my_mutator_t;


extern "C" my_mutator_t *afl_custom_init(afl_state_t *afl, unsigned int seed) {

  srand(seed);
  my_mutator_t *data = (my_mutator_t *)calloc(1, sizeof(my_mutator_t));
  if (!data) {

    perror("afl_custom_init alloc");
    return NULL;

  }

  if ((data->buf = (unsigned char *)malloc(1024)) == NULL) {

    free(data->buf);
    perror("afl_custom_init malloc");
    return NULL;

  }

  data->file_count = 0;
  data->afl = afl;

  return data;

}

extern "C" size_t afl_custom_post_process(my_mutator_t *data, unsigned char *in_buf,
                               size_t buf_size, unsigned char **out_buf) {

  //printf("random input: \n");
  //printf("-----------------------\n%s\n%ld\n-----------------------\n\n", in_buf, buf_size);

  //typedef unsigned BranchIndex;
  //std::vector<BranchIndex> branches_to_flip;

  if(buf_size < 4){
    *out_buf = in_buf;
    return buf_size;
  }

  unsigned int cipher_index;
  memcpy(&cipher_index, in_buf, 4);
  cipher_index += rand() % 1024;
  std::string tar_cipher = cipher[cipher_index % 12];
  printf("index: %u %s\n", cipher_index, tar_cipher.c_str());
  std::string flag = "genrsa -@ -passout pass:xxxxx -out 0";
  flag = flag.replace(8, 1, tar_cipher);

  unsigned char *pos = NULL;
  char n[3] = {0};
  snprintf(n, 3, "%d", ++data->file_count);
  memset(data->buf, 0, 1024);
  memcpy(data->buf, flag.c_str(), 1024);
  pos = (unsigned char *)strstr((char *)data->buf, "-out");
  memcpy((pos + 5), n, 3);
  memcpy((pos + 5 + strlen(n)), " 512\0", 5);

  *out_buf = data->buf;
  buf_size = strlen((char *)data->buf);
  printf("-----------------------\n%s\n%ld\n-----------------------\n\n", data->buf, buf_size);

  return buf_size;

}


extern "C" void afl_custom_deinit(my_mutator_t *data) {

  free(data->buf);
  free(data);

}

