#include "pin.H"
#include <iostream>
#include <stdlib.h>
#include <stdio.h>
#include <time.h>
#include <set>
#include <algorithm>

using std::cerr;
using std::cout;
using std::dec;
using std::endl;
using std::flush;
using std::hex;

//static int injected = 0;
enum VALID_INS_TYPE{
    INS_TYPE_MEM_READ,
    INS_TYPE_MEM_WRITE,
    INS_TYPE_LOAD_ARGS
};
typedef struct patch_point{
    ADDRINT addr;
    UINT64 injectValue;
} Patchpoint;
typedef std::vector<Patchpoint> Patchpoints;
std::set<std::string> lib_blacklist;
Patchpoints patch_points;
static BOOL detach_flag = false;

KNOB<std::string> KnobNewAddr(KNOB_MODE_WRITEONCE, "pintool", "addr", "0", "specify addrs of instructions");
KNOB<std::string> KnobNewVal(KNOB_MODE_WRITEONCE, "pintool", "val", "512", "specify values to inject");

VOID MutateReg(ADDRINT Ip, REG reg, UINT64 injectValue, CONTEXT *ctx){
    //srand(time(0));
    //UINT32 injectValue = rand() % MAXMUTVALUE;
    //printf("instruction@0x%lx, inject value of register %s with %ld\n", Ip, REG_StringShort(reg).c_str(), injectValue);
    PIN_SetContextRegval(ctx, reg, (UINT8 *)&injectValue);
    return;
}

BOOL IsValidReg(REG reg){
    switch (reg)
    {
        case REG_RIP:
        case REG_EIP:
        case REG_IP:
        case REG_RSP:
        case REG_ESP:
        case REG_SP:
        case REG_RBP:
        case REG_EBP:
        case REG_BP:
            return false;

        default:
            return true;
    }
}

BOOL isValidIns(INS ins, VALID_INS_TYPE ins_type){
    xed_iclass_enum_t ins_opcode = (xed_iclass_enum_t)INS_Opcode(ins);
    switch (ins_type)
    {
        case INS_TYPE_MEM_READ:
            switch(ins_opcode){
                case XED_ICLASS_POP:
                case XED_ICLASS_PUSH:
                case XED_ICLASS_OR:
                case XED_ICLASS_AND:
                case XED_ICLASS_XOR:
                case XED_ICLASS_MUL:
                case XED_ICLASS_JMP:
                case XED_ICLASS_CALL_FAR:
                case XED_ICLASS_CALL_NEAR:
                case XED_ICLASS_XCHG:
                case XED_ICLASS_CMPXCHG_LOCK:
                    return false;
                default:
                    return true;
            }
        
        case INS_TYPE_MEM_WRITE:
            switch(ins_opcode){
                case XED_ICLASS_PUSH:
                case XED_ICLASS_OR:
                case XED_ICLASS_AND:
                case XED_ICLASS_XOR:
                case XED_ICLASS_MUL:
                case XED_ICLASS_CALL_FAR:
                case XED_ICLASS_CALL_NEAR:
                    return false;
                default:
                    return true;
            }
        
        case INS_TYPE_LOAD_ARGS:{
            REG reg = REG_INVALID();
            reg = INS_OperandReg(ins, 1);
            switch (reg)
            {
                case REG_RDI:
                case REG_EDI:
                case REG_DI:
                case REG_DIL:
                case REG_RSI:
                case REG_ESI:
                case REG_SI:
                case REG_SIL:
                case REG_RDX:
                case REG_EDX:
                case REG_DX:
                case REG_DL:
                case REG_RCX:
                case REG_ECX:
                case REG_CX:
                case REG_CL:
                case REG_R8:
                case REG_R8D:
                case REG_R8W:
                case REG_R9:
                case REG_R9D:
                case REG_R9W:
                    return true;
                default:
                    return false;
            }
        }

        default:
            return false;
    }
}

VOID InstrumentIns(INS ins, ADDRINT baseAddr)
//VOID InstrumentIns(INS ins, VOID *v)
{
    //if (injected == 1) return;
    xed_iclass_enum_t ins_opcode = (xed_iclass_enum_t)INS_Opcode(ins);
    if (ins_opcode != XED_ICLASS_MOV) return;
    //printf("instruction@%p: %s\n", (void *)INS_Address(ins), INS_Disassemble(ins).c_str());
    ADDRINT addr_offset = (INS_Address(ins) - baseAddr);
    auto it = std::find_if(patch_points.begin(), patch_points.end(), [=](const Patchpoint& pp){return pp.addr == addr_offset;});
    if (it == patch_points.end()) return;
    Patchpoint pp = *it;
    patch_points.erase(it);
    if (patch_points.empty()) detach_flag = true;
    //if ((INS_Address(ins) - baseAddr) != KnobNewAddr.Value()) return;

    // if (ins_opcode == XED_ICLASS_MOV && INS_OperandIsReg(ins, 0) && INS_OperandIsReg(ins, 1)){
    // if (INS_OperandIsReg(ins, 0) && INS_OperandIsReg(ins, 1) && insCount < MAX_INSNUM){
    //     if (isValidIns(ins, INS_TYPE_LOAD_ARGS)){
    //         REG reg2mut = REG_INVALID();
    //         reg2mut = INS_OperandReg(ins, 1);
    //         if (!IsValidReg(reg2mut)) return;
            
    //         instmap[INS_Address(ins)] = INS_Disassemble(ins); 
    //         read_count++;
    //         total_count++;
    //         //printf("arg load instruction@%p, %s\n", (void *)INS_Address(ins), INS_Disassemble(ins).c_str());
    //         //printf("arg load instruction: %s\n", INS_Disassemble(ins).c_str());

    //         // random select inst
    //         if (total_count != inst2mut){
    //             return;
    //         }else{
    //             injected = 1;
    //         }
            
    //         // use REGSET
    //         REGSET regsetIn, regsetOut;
    //         REGSET_Insert(regsetIn, reg2mut);
    //         REGSET_Insert(regsetIn, REG_FullRegName(reg2mut));
    //         REGSET_Insert(regsetOut, reg2mut);
    //         REGSET_Insert(regsetOut, REG_FullRegName(reg2mut));

    //         srand(time(0));
    //         uint64_t mask = rand() % MAXMUTVALUE;
    //         INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR) MutateReg,
    //                         IARG_INST_PTR,// application IP
    //                         IARG_UINT32, reg2mut,
    //                         IARG_UINT64, mask,
    //                         IARG_PARTIAL_CONTEXT, &regsetIn, &regsetOut,
    //                         IARG_END);
    //     }
    // }
    printf("instruction@%p, inject value of %ld, %d\n", (void *)pp.addr, pp.injectValue, detach_flag);
    // TODO: use IPOINT to remove similar code
    if (INS_IsMemoryRead(ins) && !INS_IsRet(ins)){
        if (!INS_OperandIsReg(ins, 0)) return;
        REG reg2mut = REG_INVALID();
        reg2mut = INS_OperandReg(ins, 0);
        if (!IsValidReg(reg2mut)) return;
        
        //printf("data read instruction@%p, %s, %s\n", (void *)INS_Address(ins), INS_Disassemble(ins).c_str(), REG_StringShort(reg2mut).c_str());
        //printf("data read instruction@%p, %s\n", (void *)INS_Address(ins), INS_Disassemble(ins).c_str()); 
        //printf("data read instruction: %s\n", INS_Disassemble(ins).c_str());

        // use REGSET
        REGSET regsetIn, regsetOut;
        REGSET_Insert(regsetIn, reg2mut);
        REGSET_Insert(regsetIn, REG_FullRegName(reg2mut));
        REGSET_Insert(regsetOut, reg2mut);
        REGSET_Insert(regsetOut, REG_FullRegName(reg2mut));

        // srand(time(0));
        // uint64_t mask = rand() % MAXMUTVALUE;
        INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR) MutateReg,
                        IARG_INST_PTR,// application IP
                        IARG_UINT32, reg2mut,
                        IARG_UINT64, pp.injectValue,
                        IARG_PARTIAL_CONTEXT, &regsetIn, &regsetOut,
                        IARG_END);

    }

    if (INS_IsMemoryWrite(ins)){
        if (!INS_OperandIsReg(ins, 1)) return;
        REG reg2mut = REG_INVALID();
        reg2mut = INS_OperandReg(ins, 1);
        if (!IsValidReg(reg2mut)) return;

        //printf("data write instruction@%p, %s, %s\n", (void *)INS_Address(ins), INS_Disassemble(ins).c_str(), REG_StringShort(reg2mut).c_str());
        //printf("data write instruction@%p, %s\n", (void *)INS_Address(ins), INS_Disassemble(ins).c_str());
        //printf("data write instruction: %s\n", INS_Disassemble(ins).c_str());

        // use regset
        REGSET regsetIn, regsetOut;
        REGSET_Insert(regsetIn, reg2mut);
        REGSET_Insert(regsetIn, REG_FullRegName(reg2mut));
        REGSET_Insert(regsetOut, reg2mut);
        REGSET_Insert(regsetOut, REG_FullRegName(reg2mut));

        // srand(time(0));
        // uint64_t mask = rand() % MAXMUTVALUE;
        INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR) MutateReg,
                        IARG_INST_PTR,// application IP
                        IARG_UINT32, reg2mut,
                        IARG_UINT64, pp.injectValue,
                        IARG_PARTIAL_CONTEXT, &regsetIn, &regsetOut,
                        IARG_END);

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

// XXX: cannot use routine because the changed register value will not saved
VOID InstrumentTrace(TRACE trace, VOID *v){
    if (detach_flag) return;
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
    //printf("In %s\n", img_name.c_str());

    for (BBL bbl = TRACE_BblHead(trace); BBL_Valid(bbl); bbl = BBL_Next(bbl)) {
        for(INS ins = BBL_InsHead(bbl); INS_Valid(ins); ins = INS_Next(ins)){
            InstrumentIns(ins, baseAddr);
        }

    }
}

void Detatched(VOID *v){std::cerr << endl << "Detached from pintool!" << endl;}

void Fini(INT32 code, void *v){
	// printf("read counts: %ld\n", read_count);
    // printf("write counts: %ld\n", write_count);
	// printf("read number of insts: %ld\n", instmap.size());
    return;
}

INT32 Usage()
{
    // cerr << "This Pintool counts the number of times a routine is executed" << endl;
    // cerr << "and the number of instructions executed in a routine" << endl;
    cerr << endl << KNOB_BASE::StringKnobSummary() << endl;
    return -1;
}

std::vector<std::string> get_tokens(std::string args, std::string del){
    size_t pos_s = 0;
    size_t pos_e;
    std::string token;
    std::vector<std::string> vec;
    while((pos_e = args.find(del, pos_s)) != std::string::npos){
        token = args.substr(pos_s, pos_e - pos_s);
        pos_s = pos_e + del.length();
        vec.push_back(token);
    }
    vec.push_back(args.substr(pos_s));
    return vec;
}

BOOL Init(){
    lib_blacklist.insert("ld-linux-x86-64.so.2");
    lib_blacklist.insert("[vdso]");
    lib_blacklist.insert("libc.so.6");

    std::vector<std::string> args1 = get_tokens(KnobNewAddr.Value(), ",");
    std::vector<std::string> args2 = get_tokens(KnobNewVal.Value(), ",");
    if (args1.size() != args2.size()) return false;
    std::vector<std::string>::iterator it1, it2;
    for (it1 = args1.begin(), it2 = args2.begin(); it1 != args1.end(), it2 != args2.end(); it1++, it2++){
        Patchpoint pp;
        pp.addr = Uint64FromString(*it1);
        pp.injectValue = Uint64FromString(*it2);
        patch_points.push_back(pp);
        std::cout << "pp: " << pp.addr << "," << pp.injectValue << std::endl;
    }
    
    return true;
}

int main(INT32 argc, CHAR* argv[])
{   
    if (PIN_Init(argc, argv)) return Usage();
    if (!Init()) return Usage();
    //PIN_SetSyntaxATT();
    //INS_AddInstrumentFunction(InstrumentIns, 0);
    TRACE_AddInstrumentFunction(InstrumentTrace, 0);
    PIN_AddFiniFunction(Fini, 0);
    PIN_AddDetachFunction(Detatched, 0);
    PIN_StartProgram();
    return 0;
}