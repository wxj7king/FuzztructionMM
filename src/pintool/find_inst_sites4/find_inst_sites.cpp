#include "pin.H"
#include <iostream>
#include <stdlib.h>
#include <stdio.h>
#include <time.h>
#include <algorithm>
#include <set>
#include <fstream>

using std::cerr;
using std::cout;
using std::dec;
using std::endl;
using std::flush;
using std::hex;

static std::vector<ADDRINT> insts;
static std::set<std::string> lib_blacklist;
static std::map<ADDRINT, size_t> ins_regsize;
static std::map<ADDRINT, std::string> ins_insstr;
KNOB< std::string > KnobOutputFile(KNOB_MODE_WRITEONCE, "pintool", "o", "found_ins.out", "specify output file name");
std::ofstream OutFile;

BOOL IsValidReg(REG reg){
    return (REG_is_xmm(reg) || REG_is_gr8(reg) || REG_is_gr16(reg) || REG_is_gr32(reg) || REG_is_gr64(reg) || REG_is_gr(reg));
}

BOOL IsValidMovIns(INS ins){
    // xed_iclass_enum_t ins_opcode = (xed_iclass_enum_t)INS_Opcode(ins);
    std::string opcode_str = INS_Mnemonic(ins);
    return opcode_str.find("MOV") != std::string::npos;
}

BOOL IsValidBranchIns(INS ins){
    xed_iclass_enum_t ins_opcode = (xed_iclass_enum_t)INS_Opcode(ins);
    if (ins_opcode == XED_ICLASS_JZ || ins_opcode == XED_ICLASS_JNZ) 
        return true;
    return false;
}

VOID InstrumentIns(INS ins, ADDRINT baseAddr)
{   
    
    ADDRINT offset = INS_Address(ins) - baseAddr;
    if (std::find(insts.begin(), insts.end(), offset) != insts.end()) return; //FIXME ? Why there could be multiple instrument?
    REG reg2mut = REG_INVALID();
    bool found = false;

    if (IsValidMovIns(ins)){
        if (INS_IsMemoryRead(ins)){
            if (!INS_OperandIsReg(ins, 0)) return;
            reg2mut = INS_OperandReg(ins, 0);
            found = true;
        }

        if (INS_IsMemoryWrite(ins)){
            if (!INS_OperandIsReg(ins, 1)) return;
            reg2mut = INS_OperandReg(ins, 1);
            found = true;
        }
        if (!IsValidReg(reg2mut) || !found) return;
        ins_regsize[offset] = (size_t)REG_Size(reg2mut);
    }else if (IsValidBranchIns(ins)){
        ins_regsize[offset] = 32; // to indicate a branch ins
    }else{
        return;
    }

    insts.push_back(offset); 
    ins_insstr[offset] = INS_Disassemble(ins);
    //printf("%p,%s,%u\n", (void *)(offset), INS_Disassemble(ins).c_str(), REG_Size(reg2mut));
    //printf("%p,%p,%s,%u\n", (void *)baseAddr, (void *)(INS_Address(ins) - baseAddr), INS_Disassemble(ins).c_str(), REG_Size(reg2mut));
    //printf("%p,%u\n", (void *)(INS_Address(ins) - baseAddr), REG_Size(reg2mut));
}

const char* StripPath(const char* path)
{
    const char* file = strrchr(path, '/');
    if (file)
        return file + 1;
    else
        return path;
}

// XXX: cannot use routine because the changed register value will not be saved
VOID InstrumentTrace(TRACE trace, VOID *v){
    ADDRINT baseAddr = 0;
    std::string img_name;
    IMG img = IMG_FindByAddress(TRACE_Address(trace));
    if (!IMG_Valid(img)) return;
    img_name = StripPath(IMG_Name(img).c_str());
    if (lib_blacklist.find(img_name) != lib_blacklist.end()) return;
    baseAddr = IMG_LowAddress(img);
    for (BBL bbl = TRACE_BblHead(trace); BBL_Valid(bbl); bbl = BBL_Next(bbl)) {
        for(INS ins = BBL_InsHead(bbl); INS_Valid(ins); ins = INS_Next(ins)){
            InstrumentIns(ins, baseAddr);
        }
    }

    // RTN rtn = TRACE_Rtn(trace);
    // std::string img_name;
    // if (RTN_Valid(rtn)){
    //     IMG img = SEC_Img(RTN_Sec(rtn));
    //     img_name = StripPath(IMG_Name(img).c_str());
    //     if (lib_blacklist.find(img_name) != lib_blacklist.end()) return;
    //     baseAddr = IMG_LowAddress(img);
    // }
    // else return;
    // // printf("img: %s, baseaddr: 0x%lx\n", img_name.c_str(), baseAddr);

    // for (BBL bbl = TRACE_BblHead(trace); BBL_Valid(bbl); bbl = BBL_Next(bbl)) {
    //     for(INS ins = BBL_InsHead(bbl); INS_Valid(ins); ins = INS_Next(ins)){
    //         InstrumentIns(ins, baseAddr);
    //     }
    // }
}

// VOID FindImgs(IMG img, VOID *v){
//     printf("Img loading: %s, id: %d, base: 0x%lx\n", IMG_Name(img).c_str(), IMG_Id(img), IMG_LowAddress(img));
// }
VOID output_found_ins(){
    for (const auto& addr : insts){
        OutFile.setf(std::ios::showbase);
        //OutFile << (void *)addr << "," << ins_regsize[addr] << std::endl;
        OutFile << ins_insstr[addr] << "@" <<(void *)addr << "," << ins_regsize[addr] << std::endl;
    }
    OutFile.close();
    //std::cout << REG_Size(REG_FLAGS) << std::endl;
}

VOID Fini(INT32 code, void *v){
    output_found_ins();
    return;
}

INT32 Usage()
{
    std::cerr << std::endl << KNOB_BASE::StringKnobSummary() << std::endl;
    return -1;
}

VOID Init(){
    lib_blacklist.insert("ld-linux-x86-64.so.2");
    lib_blacklist.insert("[vdso]");
    lib_blacklist.insert("libc.so.6");
    OutFile.open(KnobOutputFile.Value().c_str());
    return;
}

int main(INT32 argc, CHAR* argv[])
{   
    PIN_InitSymbols();
    if (PIN_Init(argc, argv)) return Usage();
    Init();
    //PIN_SetSyntaxATT();
    //INS_AddInstrumentFunction(InstrumentIns, 0);
    //IMG_AddInstrumentFunction(FindImgs, 0);
    TRACE_AddInstrumentFunction(InstrumentTrace, 0);
    PIN_AddFiniFunction(Fini, 0);
    PIN_StartProgram();
    return 0;
}