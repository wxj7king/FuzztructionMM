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
static std::vector<ADDRINT> insts;
static std::set<std::string> lib_blacklist;
static UINT64 icount = 0;
static UINT64 pcount = 0;

KNOB<std::string> KnobNewAddr(KNOB_MODE_WRITEONCE, "pintool", "addr", "0", "specify addrs of instructions");
KNOB<std::string> KnobCheckPtr(KNOB_MODE_WRITEONCE, "pintool", "p", "0", "specify whether to check if it's possibly a pointer");
KNOB<std::string> KnobOutput(KNOB_MODE_WRITEONCE, "pintool", "o", "get_iter_output", "specify the output file path");
static UINT64 addr = 0;
static int flag = 0;
static UINT8 *read_buf = NULL;
static std::ofstream OutFile;

//VOID Ins_counter(){
inline VOID PIN_FAST_ANALYSIS_CALL Ins_counter(){
    /// do not know why only when printing smth, the icount could be correct
    icount++;
    printf("dummy print\t");
}

VOID ReadRegVal(REG reg, CONTEXT *ctx){
    PIN_GetContextRegval(ctx, reg, read_buf);
    uintptr_t val = *((uintptr_t *)read_buf);
    //printf("%p\n", (void *)val);
    if (IsPointer(val)) pcount++;
    //PIN_SetContextRegval(ctx, reg, read_buf);
    icount++;
    printf("dummy print\t");
}

VOID InstrumentIns(INS ins, ADDRINT baseAddr)
{   
    ADDRINT offset = INS_Address(ins) - baseAddr;
    if (offset == addr) flag = 1;
    else return;

    if (KnobCheckPtr.Value() == "1"){
        REG reg2read = REG_INVALID();
        REGSET regsetIn, regsetOut;
        UINT32 reg_size = 0;
        if (INS_IsMemoryRead(ins)){
            reg2read = INS_OperandReg(ins, 0);
        }
        if (INS_IsMemoryWrite(ins)){
            reg2read = INS_OperandReg(ins, 1);
        }
        reg_size = REG_Size(reg2read);
        ASSERT(reg_size == 8, "reg size invalid");
        read_buf = (UINT8 *)calloc(8, 1);
        REGSET_Insert(regsetIn, reg2read);
        REGSET_Insert(regsetIn, REG_FullRegName(reg2read));
        REGSET_Insert(regsetOut, reg2read);
        REGSET_Insert(regsetOut, REG_FullRegName(reg2read));
        INS_InsertCall(ins, IPOINT_AFTER, (AFUNPTR)ReadRegVal,
                        IARG_UINT32, reg2read,
                        IARG_PARTIAL_CONTEXT, &regsetIn, &regsetOut,
                        IARG_END);
    }else{
        INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR) Ins_counter, IARG_FAST_ANALYSIS_CALL , IARG_END);
        //INS_InsertCall(ins, IPOINT_AFTER, (AFUNPTR) Ins_counter, IARG_END);
    }
    
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
    if (flag == 1) return;
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
        OutFile << (void *)addr << "," << icount << "," << pcount;
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
    addr = Uint64FromString(KnobNewAddr.Value());
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