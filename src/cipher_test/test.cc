#include <stdio.h>
#include <stdlib.h>
#include <iostream>
#include <vector>
#include <map>
#include <fstream>
#include <sstream>

std::vector<std::string> ciphers;
std::string cipher_conf_path = "./enc_valid.conf";

int main(){
    std::ifstream cipher_conf(cipher_conf_path);
    std::string readline;
    if (cipher_conf.is_open()){

        while(getline(cipher_conf, readline)){
            ciphers.push_back(readline);
        }
    }

    for (std::string cipher : ciphers){
        std::cout << cipher << '\n';
    }
    cipher_conf.close();
    //std::cout << "file open error\n";
    return 0;
}