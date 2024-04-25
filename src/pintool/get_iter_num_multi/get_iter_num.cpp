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

/// assume that typical pointer uses 6 bytes
#define IsPointer(x) ((((uintptr_t)(x)) & ~0xffffffffff) != 0)
static std::set<std::string> lib_blacklist;
static std::map<ADDRINT, UINT32> ins2icounts;
static std::map<ADDRINT, UINT32> ins2pcounts;
static std::map<ADDRINT, UINT8*> ins2buf;
static std::vector<ADDRINT> insts;
static std::map<ADDRINT, std::string> ins_insstr;

KNOB<std::string> KnobNewAddr(KNOB_MODE_WRITEONCE, "pintool", "addr", "0", "specify addrs of instructions");
KNOB<std::string> KnobCheckPtr(KNOB_MODE_WRITEONCE, "pintool", "p", "0", "specify whether to check if it's possibly a pointer");
KNOB<std::string> KnobOutput(KNOB_MODE_WRITEONCE, "pintool", "o", "get_iter_output", "specify the output file path");

static std::ofstream OutFile;

BOOL IsValidReg(REG reg){
    return (REG_is_xmm(reg) || REG_is_gr8(reg) || REG_is_gr16(reg) || REG_is_gr32(reg) || REG_is_gr64(reg) || REG_is_gr(reg));
}

BOOL IsValidMovIns(INS ins){
    // xed_iclass_enum_t ins_opcode = (xed_iclass_enum_t)INS_Opcode(ins);
    std::string opcode_str = INS_Mnemonic(ins);
    return opcode_str.find("MOV") != std::string::npos;
}

VOID ReadRegVal(ADDRINT off, REG reg, CONTEXT *ctx){
    PIN_GetContextRegval(ctx, reg, ins2buf[off]);
    //printf("%p\n", (void *)val);
    if (IsPointer(ins2buf[off])) ins2pcounts[off]++;
    //PIN_SetContextRegval(ctx, reg, read_buf);
    ins2icounts[off]++;
    printf("dummy print\t");
}

VOID InstrumentIns(INS ins, ADDRINT baseAddr)
{   
    ADDRINT offset = INS_Address(ins) - baseAddr;
    if (std::find(insts.begin(), insts.end(), offset) != insts.end()) return; //FIXME ? Why there could be multiple instrument?

    REG reg2read = REG_INVALID();
    REGSET regsetIn, regsetOut;
    bool found = false;

    if (IsValidMovIns(ins)){
        if (INS_IsMemoryRead(ins)){
            if (!INS_OperandIsReg(ins, 0)) return;
            reg2read = INS_OperandReg(ins, 0);
            found = true;
        }
        if (INS_IsMemoryWrite(ins)){
            if (!INS_OperandIsReg(ins, 1)) return;
            reg2read = INS_OperandReg(ins, 1);
            found = true;
        }
        if (!IsValidReg(reg2read) || !found) return;

        REGSET_Insert(regsetIn, reg2read);
        REGSET_Insert(regsetIn, REG_FullRegName(reg2read));
        REGSET_Insert(regsetOut, reg2read);
        REGSET_Insert(regsetOut, REG_FullRegName(reg2read));
        INS_InsertCall(ins, IPOINT_AFTER, (AFUNPTR)ReadRegVal,
                        IARG_ADDRINT, offset,
                        IARG_UINT32, reg2read,
                        IARG_PARTIAL_CONTEXT, &regsetIn, &regsetOut,
                        IARG_END);
    }else{
        return;
    }
    
    insts.push_back(offset); 
    ins_insstr[offset] = INS_Disassemble(ins);
    ins2buf[offset] = (UINT8 *)calloc(1, REG_Size(reg2read));
    ins2icounts[offset] = 0;
    ins2pcounts[offset] = 0;
    std::cout << ins_insstr[offset] << std::endl;
    
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

VOID Fini(INT32 code, void *v){
    if (OutFile.is_open()){
        OutFile.setf(std::ios::showbase);
        for (const auto& addr : insts){
            //OutFile << (void *)addr << "," << ins_regsize[addr] << std::endl;
            OutFile << ins_insstr[addr] << "@" <<(void *)addr << "," << ins2icounts[addr] << "," << ins2pcounts[addr] << std::endl;
        }
    }
    OutFile.close();
    //printf("\n%p,%ld,%ld\n", (void *)addr, icount, pcount);
    return;
}

INT32 Usage()
{
    // cerr << endl << KNOB_BASE::StringKnobSummary() << endl;
    return -1;
}

VOID Init(){
    lib_blacklist.insert("ld-linux-x86-64.so.2");
    lib_blacklist.insert("[vdso]");
    lib_blacklist.insert("libc.so.6");
    OutFile.open(KnobOutput.Value().c_str());
    //printf("%lu\n", addr);
    return;
}

int main(INT32 argc, CHAR* argv[])
{   
    PIN_InitSymbols();
    if (PIN_Init(argc, argv)) return Usage();
    Init();
    TRACE_AddInstrumentFunction(InstrumentTrace, 0);
    PIN_AddFiniFunction(Fini, 0);
    PIN_StartProgram();
    return 0;
}