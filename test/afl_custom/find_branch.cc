#include <stdio.h>
#include <stdlib.h>
#include <iostream>
#include <vector>
#include <map>
#include <fstream>
#include <sstream>

typedef std::vector<unsigned int> Branches;
typedef struct patch_point{
    unsigned int addr;
    unsigned char flip_byte;
} Patchpoint;
typedef std::vector<Patchpoint> Patchpoints;

int flip_branch(Patchpoints patch_points){
    std::string binary_dir = "/home/proj/proj/openssl/apps/openssl_flip";
    std::fstream bin_rewrite;
    bin_rewrite.open(binary_dir, std::fstream::binary | std::fstream::in | std::fstream::out);
    bin_rewrite.seekp(patch_points[0].addr);
    //std::stringstream stream;
    //stream << std::hex << patch_points[0].flip_byte;
    bin_rewrite.write((const char *)&(patch_points[0].flip_byte), 1);
    bin_rewrite.close();
    return 0;

}

int main(){
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
                std::cout << addr_str << addr <<'\n';
                std::cout << flip_byte_str << flip_byte << '\n';

            }
            //std::cout << read_line << '\n';
        }
        objdump.close();
    }
    else std::cout << "file open error\n";
    
    flip_branch(patch_points);

    return 0;
}