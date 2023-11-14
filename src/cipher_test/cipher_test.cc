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
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <iostream>
#include <vector>
#include <array>
#include <fstream>
#include <sstream>
#include <filesystem>

std::vector<std::string> ciphers;
std::string cipher_conf_path = "/home/proj/proj/src/cipher_test/enc_valid.conf";
std::string openssl_path = "/home/proj/proj/openssl/apps/openssl";

typedef struct my_mutator {
  afl_state_t *afl;
  unsigned char *buf;
  unsigned int iterp;
} my_mutator_t;
#define MAX_FILE_SIZE 1024
namespace fs = std::filesystem;

extern "C" my_mutator_t *afl_custom_init(afl_state_t *afl, unsigned int seed) {

  srand(seed);
  my_mutator_t *data = (my_mutator_t *)calloc(1, sizeof(my_mutator_t));
  if (!data) {
    perror("afl_custom_init alloc");
    return NULL;
  }

  if ((data->buf = (unsigned char *)malloc(MAX_FILE_SIZE)) == NULL) {
    free(data->buf);
    perror("afl_custom_init malloc");
    return NULL;
  }

  // get cipher flags
  std::ifstream cipher_conf(cipher_conf_path);
  std::string readline;
  if (cipher_conf.is_open()){

    while(getline(cipher_conf, readline)){
      ciphers.push_back(readline);
    }
  }
  cipher_conf.close();

  //for (std::string cipher : ciphers){
  //    std::cout << cipher << '\n';
  //}

  data->afl = afl;
  data->iterp = 0;
  return data;

}


extern "C" size_t afl_custom_post_process(my_mutator_t *data, unsigned char *in_buf,
                               size_t buf_size, unsigned char **out_buf) {


  
  // rand index
  if(buf_size < 4){
    *out_buf = in_buf;
    return buf_size;
  }

  unsigned int cipher_index;
  memcpy(&cipher_index, in_buf, 4);
  cipher_index += (rand() % 1024);
  std::string tar_cipher = ciphers[cipher_index % ciphers.size()];
  
  /* 
  unsigned int cipher_index;
  data->iterp = (data->iterp + 1) % ciphers.size();
  cipher_index = data->iterp;
  std::string tar_cipher = ciphers[cipher_index];
  //printf("index: %u %s\n", cipher_index, tar_cipher.c_str());
  */

  int pid = getpid();
  std::string tmp_file = "/tmp/tmp_output_" + std::to_string(pid);
  //std::string flags = "genrsa -@ -passout pass:xxxxx -out " + tmp_file + " 512";
  std::string flags = "genrsa @ -passout pass:xxxxx -out " + tmp_file + " 512";
  flags = flags.replace(7, 1, tar_cipher);

  // generate rsa key
  int ret = 0, f = 0; // whether fail
  std::string cmd = "timeout 1 " + openssl_path + " " + flags + " 2>&1";
  //std::string cmd = "timeout 1 " + openssl_path + " " + flags;
  //std::cout << "cmd: " << cmd << '\n';

  // https://raymii.org/s/articles/Execute_a_command_and_get_both_output_and_exit_code.html
  std::array<char , 1048576> buffer {};
  std::string result;
  FILE *pipe = popen(cmd.c_str(), "r");
  if (pipe == nullptr){
    throw std::runtime_error("popen() failed!");
  }
  try {
    std::size_t bytesread;
    while ((bytesread = std::fread(buffer.data(), sizeof(buffer.at(0)), sizeof(buffer), pipe)) != 0) {
      result += std::string(buffer.data(), bytesread);
    }
  } catch (...){
    pclose(pipe);
    throw;
  }

  ret = WEXITSTATUS(pclose(pipe));
  //std::cout << result;
  //ret = system(cmd.c_str());
  
  memset(data->buf, 0, MAX_FILE_SIZE);
  if (ret != 0){
    std::cout << "openssl genrsa failed: " << tar_cipher << "\n";
    f = 1;
  }else{
    //std::cout << "generate rsa key!\n";
    std::ifstream rsa_key(tmp_file);
    if (!rsa_key){
      std::cout << "rsa key open failed\n";
      f = 1;
    }else if(fs::file_size(tmp_file) == 0){
      std::cout << "rsa key is empty\n";
      f = 1;
    }else{
      std::stringstream buf;
      buf << rsa_key.rdbuf();
      memcpy(data->buf, (buf.str()).c_str(), MAX_FILE_SIZE);
      data->buf[MAX_FILE_SIZE - 1] = '\0';
    }
  }

  if (f == 0){
    *out_buf = data->buf;
    buf_size = strlen((char *)data->buf);
  }else{
    *out_buf = in_buf;
  }

  return buf_size;
}

extern "C" void afl_custom_deinit(my_mutator_t *data) {
  free(data->buf);
  free(data);
}

