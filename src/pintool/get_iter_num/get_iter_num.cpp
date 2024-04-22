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
static size_t count = 0;

KNOB<std::string> KnobNewAddr(KNOB_MODE_WRITEONCE, "pintool", "addr", "0", "specify addrs of instructions");
KNOB<std::string> KnobOutput(KNOB_MODE_WRITEONCE, "pintool", "o", "get_iter_output", "specify the output file path");
static UINT64 addr = 0;
static int flag = 0;
static std::ofstream OutFile;

inline VOID PIN_FAST_ANALYSIS_CALL Ins_counter(ADDRINT offset){
    count++;
}

VOID InstrumentIns(INS ins, ADDRINT baseAddr)
{   
    ADDRINT offset = INS_Address(ins) - baseAddr;
    if (offset == addr) flag = 1;
    else return;

    INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR) Ins_counter, IARG_FAST_ANALYSIS_CALL ,IARG_ADDRINT, offset, IARG_END);
    
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
    RTN rtn = TRACE_Rtn(trace);
    std::string img_name;
    if (RTN_Valid(rtn)){
        IMG img = SEC_Img(RTN_Sec(rtn));
        img_name = StripPath(IMG_Name(img).c_str());
        if (lib_blacklist.find(img_name) != lib_blacklist.end()) return;
        baseAddr = IMG_LowAddress(img);
    }
    else return;
    // printf("img: %s, baseaddr: 0x%lx\n", img_name.c_str(), baseAddr);

    for (BBL bbl = TRACE_BblHead(trace); BBL_Valid(bbl); bbl = BBL_Next(bbl)) {
        for(INS ins = BBL_InsHead(bbl); INS_Valid(ins); ins = INS_Next(ins)){
            InstrumentIns(ins, baseAddr);
        }

    }
}

VOID Fini(INT32 code, void *v){
    if (OutFile.is_open()){
        OutFile.setf(std::ios::showbase);
        OutFile << (void *)addr << "," << count;
    }
    OutFile.close();
    //printf("%p,%ld\n", (void *)addr, count);
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