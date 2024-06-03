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
static std::map<ADDRINT, size_t> ins_hits;
static std::map<ADDRINT, std::string> ins_insstr;
// static std::set<ADDRINT> taken_branches;
KNOB< std::string > KnobOutputFile(KNOB_MODE_WRITEONCE, "pintool", "o", "found_cond_branch_ins.out", "specify output file name");
std::ofstream OutFile;

BOOL IsValidBranchIns(INS ins){
    xed_iclass_enum_t ins_opcode = (xed_iclass_enum_t)INS_Opcode(ins);
    // if (ins_opcode == XED_ICLASS_JZ || ins_opcode == XED_ICLASS_JNZ) 
    //     return true;
    // if (INS_Category(ins) == XED_CATEGORY_COND_BR){
    //     if (!INS_IsXbegin(ins) && !INS_IsXend(ins))
    //         return true;
    // }
    switch (ins_opcode)
    {
        case XED_ICLASS_JB:
        case XED_ICLASS_JBE: 		
        case XED_ICLASS_JL: 	
        case XED_ICLASS_JLE: 	
        case XED_ICLASS_JNB:	
        case XED_ICLASS_JNBE: 	
        case XED_ICLASS_JNL: 	
        case XED_ICLASS_JNLE: 	
        case XED_ICLASS_JNO: 	
        case XED_ICLASS_JNP: 	
        case XED_ICLASS_JNS: 	
        case XED_ICLASS_JNZ: 	
        case XED_ICLASS_JO: 	
        case XED_ICLASS_JP: 		
        case XED_ICLASS_JS: 	
        case XED_ICLASS_JZ:
            return true;
        default:
            break;
    }
    return false;
}

// VOID Taken(ADDRINT offset){
//     if (taken_branches.count(offset) == 0)
//         taken_branches.insert(offset);
//     //ins_hits[offset]++;
// }

inline VOID CountHits(ADDRINT offset){
    ins_hits[offset]++;
}

VOID InstrumentIns(INS ins, ADDRINT baseAddr)
{   
    ADDRINT offset = INS_Address(ins) - baseAddr;
    
    if (IsValidBranchIns(ins)){
        if (std::find(insts.begin(), insts.end(), offset) != insts.end()) {
            // printf("Repeated: %p,%s\n", (void *)(offset), INS_Disassemble(ins).c_str());
            return; //FIXME ? Why there could be multiple instrument?
        }
        ins_hits[offset] = 0;
    }else{
        return;
    }

    insts.push_back(offset); 
    ins_insstr[offset] = INS_Disassemble(ins);
    
    INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)CountHits, IARG_ADDRINT, offset, IARG_END);
    //INS_InsertCall(ins, IPOINT_TAKEN_BRANCH, (AFUNPTR)Taken, IARG_ADDRINT, offset, IARG_END);
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

}

// VOID FindImgs(IMG img, VOID *v){
//     printf("Img loading: %s, id: %d, base: 0x%lx\n", IMG_Name(img).c_str(), IMG_Id(img), IMG_LowAddress(img));
// }
VOID output_found_ins(){
    OutFile.setf(std::ios::showbase);
    for (const auto& addr : insts){
        // if (taken_branches.count(addr) == 1)
        //     OutFile << ins_insstr[addr] << "@" <<(void *)addr << "," << ins_hits[addr] << ",1" << std::endl;
        // //OutFile << (void *)addr << "," << ins_hits[addr] << std::endl;
        // else 
        //     OutFile << ins_insstr[addr] << "@" <<(void *)addr << "," << ins_hits[addr] << ",0" << std::endl;
        OutFile << ins_insstr[addr] << "@" <<(void *)addr << "," << ins_hits[addr] << std::endl;
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
    //IMG_AddInstrumentFunction(FindImgs, 0);
    TRACE_AddInstrumentFunction(InstrumentTrace, 0);
    PIN_AddFiniFunction(Fini, 0);
    PIN_StartProgram();
    return 0;
}