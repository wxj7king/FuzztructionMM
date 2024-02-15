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

typedef unsigned BranchIndex;
typedef std::vector<BranchIndex> Branches;
typedef struct patch_point{
    unsigned int addr;
    unsigned char flip_byte;
} Patchpoint;
typedef std::vector<Patchpoint> Patchpoints;
typedef struct my_mutator {
  afl_state_t *afl;
  unsigned char *buf;
  unsigned int file_count;
  Patchpoints patch_points;

} my_mutator_t;
#define MAX_FILE_SIZE 1024
namespace fs = std::filesystem;

Patchpoints find_branches(){
  Branches branches;
  //std::string binary_dir = "/home/proj/proj/openssl/apps/openssl_flip";
  //int r;
  //r = system("objdump -d /home/proj/proj/openssl/apps/openssl_flip | sed \'/<genrsa_main>:/,/^$/!d\' > /home/proj/proj/objdump_out");
  //if(r != 0){
  //    std::cout << "system function error\n";
  //    return 0;
  //}
  std::ifstream objdump("/home/proj/proj/objdump_out");
  std::string read_line;
  Patchpoints patch_points;

  if(objdump.is_open()){
    size_t pos1, pos2;
    std::string inst;
    std::string addr_str;
    std::string flip_byte_str;
    unsigned int addr;
    unsigned char flip_byte;
    
    while(getline(objdump, read_line)){
      if(read_line.find('j') != std::string::npos){
        pos1 = read_line.find('\t');
        pos2 = read_line.find('\t', pos1 + 1);
        inst = read_line.substr(pos1 + 1, pos2 - pos1 - 1);
        pos1 = read_line.find(':');
        pos2 = read_line.rfind(' ', pos1);
        addr_str = read_line.substr(pos2 + 1, pos1 - pos2 - 1);
        //std::cout << inst << '\n';
        //std::cout << addr_str << '\n';

        if(read_line.find("jmp") != std::string::npos){
            continue;
        }

        if(inst.find("0f") != std::string::npos){
            flip_byte_str = inst.substr(inst.find(' ') + 1, 2);
            addr = std::stoul(addr_str, nullptr, 16) + 1;
        }else{
            flip_byte_str = inst.substr(0, 2);
            addr = std::stoul(addr_str, nullptr, 16);
        }
        flip_byte = std::stoul(flip_byte_str, nullptr, 16);
        
        if(read_line.find("je") != std::string::npos){
            flip_byte += 1;
            //1st 2nd +
        }
        else if(read_line.find("jne") != std::string::npos){
            flip_byte -= 1;
            //1st 2nd -
        }
        else if(read_line.find("ja") != std::string::npos){
            flip_byte -= 1;
            //1st 2nd -
        }
        else if(read_line.find("jae") != std::string::npos){
            flip_byte -= 1;
            //1st 2nd -
        }
        else if(read_line.find("jb") != std::string::npos){
            flip_byte += 1;
            //1st 2nd +
        }
        else if(read_line.find("jbe") != std::string::npos){
            flip_byte += 1;
            //1st 2nd +
        }
        else if(read_line.find("jg") != std::string::npos){
            flip_byte -= 1;
            //1st 2nd -
        }
        else if(read_line.find("jge") != std::string::npos){
            flip_byte -= 1;
            //1st 2nd -
        }
        else if(read_line.find("jl") != std::string::npos){
            flip_byte += 1;
            //1st 2nd +
        }
        else if(read_line.find("jle") != std::string::npos){
            flip_byte += 1;
            //1st 2nd +
        }
        else{
            continue;
        }
        
        Patchpoint patch_point;
        patch_point.addr = addr;
        patch_point.flip_byte = flip_byte;
        patch_points.push_back(patch_point);
        //std::cout << addr_str << addr <<'\n';
        //std::cout << flip_byte_str << flip_byte << '\n';

      }
        //std::cout << read_line << '\n';
    }
    objdump.close();
  }
  else std::cout << "file open error\n";
  //flip_branch(patch_points);
  return patch_points;

}

int flip_branch(Patchpoints patch_points, Branches branches_to_flip){
    std::string binary_dir = "/home/proj/proj/openssl/apps/openssl_to_flip";
    std::string patched_binary_dir = "/tmp/openssl_flipped";
    std::string cmd = "cp " + binary_dir + " " + patched_binary_dir;
    int ret = system(cmd.c_str());
    if (ret != 0){
      std::cout << "cp cmd error!" << '\n';
      return -1;
    }
    //std::cout << cmd << '\n';

    std::fstream bin_rewrite;
    bin_rewrite.open(patched_binary_dir, std::fstream::binary | std::fstream::in | std::fstream::out);
    if (!bin_rewrite){
      std::cout << "binary file open failed\n";
      return -1;
    }
    //std::stringstream stream;
    //stream << std::hex << patch_points[0].flip_byte;
    for (BranchIndex branch_index : branches_to_flip){
      BranchIndex tmp = (branch_index + rand()) % patch_points.size();
      bin_rewrite.seekp(patch_points[tmp].addr);
      bin_rewrite.write((const char *)&(patch_points[tmp].flip_byte), 1);
    }
    //bin_rewrite.close();
    
    return 0;

}

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

  data->file_count = 0;
  data->afl = afl;
  data->patch_points = find_branches();

  //std::string mutated_bin_output_dir = "./mutated_bin_output";
  //if (!fs::create_directory(mutated_bin_output_dir)){
  //  std::cerr << "create directory error!\n";
  //}

  return data;

}


extern "C" size_t afl_custom_post_process(my_mutator_t *data, unsigned char *in_buf,
                               size_t buf_size, unsigned char **out_buf) {


  if(buf_size < 4){
    *out_buf = in_buf;
    return buf_size;
  }

  unsigned int cipher_index;
  memcpy(&cipher_index, in_buf, 4);
  cipher_index += (rand() % 1024);
  std::string tar_cipher = cipher[cipher_index % 12];
  //printf("index: %u %s\n", cipher_index, tar_cipher.c_str());
  int pid = getpid();
  std::string tmp_file = "/tmp/tmp_output_" + std::to_string(pid);
  std::string flags = "genrsa -@ -passout pass:xxxxx -out " + tmp_file + " 512";
  flags = flags.replace(8, 1, tar_cipher);

  // flip branches
  int ret;
  Branches branches_to_flip;
  branches_to_flip.resize((unsigned int)ceil((float)buf_size / sizeof(BranchIndex)));
  //branches_to_flip.resize(((buf_size % sizeof(BranchIndex)) == 0)? (buf_size / sizeof(BranchIndex)) : (buf_size / sizeof(BranchIndex)) + 1);
  memcpy(branches_to_flip.data(), in_buf, buf_size);
  ret = flip_branch(data->patch_points, branches_to_flip);

  // use the mutated binary to generate the output which is than fed to consumer
  int f; // whether fail
  memset(data->buf, 0, 1024);
  if (ret != 0){
    std::cout << "flip_branch error!\n";
    f = 1;
  }
  else{
    std::string cmd = "timeout 1 /tmp/openssl_flipped " + flags;
    //std::cout << "cmd: " << cmd << '\n';
    ret = system(cmd.c_str());
    if (ret != 0){
      //std::cout << "mutated binary crash!\n";
      f = 1;
    }else{
      std::cout << "mutated output generated!\n";
      std::ifstream mutated_output(tmp_file);
      if (!mutated_output){
        std::cout << "mutated output file open failed\n";
        f = 1;
        //return -1;
      }else if(fs::file_size(tmp_file) == 0){
        std::cout << "mutated output file is empty\n";
        f = 1;
      }else{
        std::stringstream buf;
        buf << mutated_output.rdbuf();
        memcpy(data->buf, (buf.str()).c_str(), MAX_FILE_SIZE);
        data->buf[MAX_FILE_SIZE - 1] = '\0';
        f = 0;
      }
    }
  }
  
  if (f == 0){
    *out_buf = data->buf;
    buf_size = strlen((char *)data->buf);
    printf("-----------------------\n%s\n%ld\n-----------------------\n\n", data->buf, buf_size);
  }else{
    *out_buf = in_buf;
  }
  //printf("-----------------------\n%s\n%ld\n-----------------------\n\n", *out_buf, buf_size);
  return buf_size;

}

extern "C" void afl_custom_deinit(my_mutator_t *data) {

  free(data->buf);
  free(data);

}

