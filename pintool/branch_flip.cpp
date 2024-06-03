#include "pin.H"
#include <iostream>
#include <stdlib.h>
#include <stdio.h>
#include <time.h>
#include <set>
#include <algorithm>
#include <random>

using std::cerr;
using std::cout;
using std::dec;
using std::endl;
using std::flush;
using std::hex;

typedef struct patch_point{
    ADDRINT addr;
    UINT64 iter_total;
} Patchpoint;
std::set<std::string> lib_blacklist;
static Patchpoint patch_point;
static BOOL detach_flag = false;
static UINT64 cur_iter = 0;
static std::set<ADDRINT> inst_set;
static BOOL next_flag = false;
static size_t next_br_idx = 0;
// 1 based idx
static size_t next_br_idx_count = 1;

// static UINT8 *flags_val = NULL;
static UINT16 flags_val = 0;
static UINT16 control_flag_msk = 0;

std::random_device rd;
std::mt19937 gen(rd()); // Mersenne Twister engine
std::uniform_int_distribution<UINT8> dist_idx;

KNOB<std::string> KnobNewAddr(KNOB_MODE_WRITEONCE, "pintool", "addr", "0", "specify addrs of instructions");
KNOB<std::string> KnobNewIterNum(KNOB_MODE_WRITEONCE, "pintool", "iter", "0", "specify how iteration this ins will be executed in a loop");
KNOB<std::string> KnobNewNextBr(KNOB_MODE_WRITEONCE, "pintool", "n", "0", "next branch to flip");

VOID BranchFlip_SingleFlag(ADDRINT Ip, CONTEXT *ctx){
    // printf("curr iter %ld\n", cur_iter);
    PIN_GetContextRegval(ctx, REG_FLAGS, reinterpret_cast<UINT8 *>(&flags_val));
    // printf("branch flip at %p\n", (void *)Ip);
    flags_val ^= control_flag_msk;
    PIN_SetContextRegval(ctx, REG_FLAGS, reinterpret_cast<UINT8 *>(&flags_val));
    cur_iter++;
    if (cur_iter >= patch_point.iter_total && next_br_idx == 0)
        PIN_Detach();
}

// CF = 1 or ZF = 1 OR CF = 0 and ZF = 0
VOID BranchFlip_MultiFlags_1(ADDRINT Ip, CONTEXT *ctx){
    // printf("curr iter %ld\n", cur_iter);
    PIN_GetContextRegval(ctx, REG_FLAGS, reinterpret_cast<UINT8 *>(&flags_val));
    // printf("branch flip at %p\n", (void *)Ip);
    if ((flags_val & 0x0001) || (flags_val & 0x0040)){
        flags_val &= static_cast<UINT16>(~0x0001);
        flags_val &= static_cast<UINT16>(~0x0040);
    }else{
        flags_val ^= 0x0001;
    }
    
    PIN_SetContextRegval(ctx, REG_FLAGS, reinterpret_cast<UINT8 *>(&flags_val));
    cur_iter++;
    if (cur_iter >= patch_point.iter_total && next_br_idx == 0)
        PIN_Detach();
}

// ZF = 1 or SF <> OF OR ZF = 0 and SF = OF
VOID BranchFlip_MultiFlags_2(ADDRINT Ip, CONTEXT *ctx){
    // printf("curr iter %ld\n", cur_iter);
    PIN_GetContextRegval(ctx, REG_FLAGS, reinterpret_cast<UINT8 *>(&flags_val));
    // printf("branch flip at %p\n", (void *)Ip);
    if ( (flags_val & 0x0040) || ((flags_val & 0x0080) && !(flags_val & 0x0800)) || (!(flags_val & 0x0080) && (flags_val & 0x0800)) ){
        flags_val &= static_cast<UINT16>(~0x0040);
        flags_val &= static_cast<UINT16>(~0x0080);
        flags_val &= static_cast<UINT16>(~0x0800);
    }else{
        flags_val ^= 0x0040;
    }
    PIN_SetContextRegval(ctx, REG_FLAGS, reinterpret_cast<UINT8 *>(&flags_val));
    cur_iter++;
    if (cur_iter >= patch_point.iter_total && next_br_idx == 0)
        PIN_Detach();
}

BOOL IsValidBranchIns(INS ins){
    xed_iclass_enum_t ins_opcode = (xed_iclass_enum_t)INS_Opcode(ins);
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


VOID InstrumentIns(INS ins, ADDRINT baseAddr)
{
    
    ADDRINT addr_offset = (INS_Address(ins) - baseAddr);
    if (patch_point.addr != addr_offset && !next_flag) return;
    if (inst_set.count(addr_offset) == 1) return;
    inst_set.insert(addr_offset);

    if (!IsValidBranchIns(ins)) return;
    if (next_flag){
        if (next_br_idx_count != next_br_idx){
            next_br_idx_count++;
            return;
        }else{
            printf("find next br at idx: %ld!\n", next_br_idx);
        }
    }

    REG reg2mut = REG_FLAGS;
    REGSET regsetIn, regsetOut;
    // UINT32 reg_size = REG_Size(reg2mut);
    // flags_val = (UINT8 *)calloc(1, reg_size);
    // printf("flags size:%d\n", reg_size);
    printf("branch flip@%p, %s\n", (void *)addr_offset, INS_Disassemble(ins).c_str());

    REGSET_Insert(regsetIn, reg2mut);
    REGSET_Insert(regsetIn, REG_FullRegName(reg2mut));
    REGSET_Insert(regsetOut, reg2mut);
    REGSET_Insert(regsetOut, REG_FullRegName(reg2mut));
    xed_iclass_enum_t ins_opcode = (xed_iclass_enum_t)INS_Opcode(ins);

    switch (ins_opcode)
    {   
        case XED_ICLASS_JO:
        case XED_ICLASS_JNO: 
            // OF
            control_flag_msk = 0x0800;
            INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)BranchFlip_SingleFlag,
                    IARG_INST_PTR,// application IP
                    IARG_PARTIAL_CONTEXT, &regsetIn, &regsetOut,
                    IARG_END);
            break;
        case XED_ICLASS_JS: 
        case XED_ICLASS_JNS: 
        case XED_ICLASS_JL: 
        case XED_ICLASS_JNL: 
            // SF
            control_flag_msk = 0x0080;
            INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)BranchFlip_SingleFlag,
                    IARG_INST_PTR,// application IP
                    IARG_PARTIAL_CONTEXT, &regsetIn, &regsetOut,
                    IARG_END);
            break;
        case XED_ICLASS_JZ:
        case XED_ICLASS_JNZ: 
            // ZF
            control_flag_msk = 0x0040;
            INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)BranchFlip_SingleFlag,
                    IARG_INST_PTR,// application IP
                    IARG_PARTIAL_CONTEXT, &regsetIn, &regsetOut,
                    IARG_END);
            break;
        case XED_ICLASS_JB:
        case XED_ICLASS_JNB:	
        	// CF
            control_flag_msk = 0x0001;
            INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)BranchFlip_SingleFlag,
                    IARG_INST_PTR,// application IP
                    IARG_PARTIAL_CONTEXT, &regsetIn, &regsetOut,
                    IARG_END);
            break;
        case XED_ICLASS_JP: 
        case XED_ICLASS_JNP: 	
            // PF
            control_flag_msk = 0x0004;
            INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)BranchFlip_SingleFlag,
                    IARG_INST_PTR,// application IP
                    IARG_PARTIAL_CONTEXT, &regsetIn, &regsetOut,
                    IARG_END);
            break;
        case XED_ICLASS_JBE: 
        case XED_ICLASS_JNBE: 
            INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)BranchFlip_MultiFlags_1,
                    IARG_INST_PTR,// application IP
                    IARG_PARTIAL_CONTEXT, &regsetIn, &regsetOut,
                    IARG_END);
            break;
        case XED_ICLASS_JLE: 
        case XED_ICLASS_JNLE: 
            INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)BranchFlip_MultiFlags_2,
                    IARG_INST_PTR,// application IP
                    IARG_PARTIAL_CONTEXT, &regsetIn, &regsetOut,
                    IARG_END);
            break;
        default:
            abort();
            //break;
    }

    if (patch_point.addr == addr_offset){
        if (next_br_idx == 0)
            detach_flag = true;
        else{
            next_flag = true;
        }
    }else{
        detach_flag = true;
        next_flag = false;
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
    std::string img_name;
    IMG img = IMG_FindByAddress(TRACE_Address(trace));
    if (!IMG_Valid(img)) return;
    img_name = StripPath(IMG_Name(img).c_str());
    if (lib_blacklist.find(img_name) != lib_blacklist.end()) return;
    baseAddr = IMG_LowAddress(img);
    //printf("next trace!\n");
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
    // free(flags_val);
    return;
}

INT32 Usage()
{
    // cerr << "This Pintool counts the number of times a routine is executed" << endl;
    // cerr << "and the number of instructions executed in a routine" << endl;
    cerr << endl << KNOB_BASE::StringKnobSummary() << endl;
    return -1;
}

BOOL Init(){
    if (KnobNewAddr.Value() == "" || KnobNewIterNum.Value() == "") return false;

    lib_blacklist.insert("ld-linux-x86-64.so.2");
    lib_blacklist.insert("[vdso]");
    lib_blacklist.insert("libc.so.6");

    patch_point.addr = Uint64FromString(KnobNewAddr.Value());
    patch_point.iter_total = std::stoul(KnobNewIterNum.Value());
    next_br_idx = std::stoul(KnobNewNextBr.Value());

    printf("pp: %p, %ld, %ld\n", (void *)patch_point.addr, patch_point.iter_total, next_br_idx);

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