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
    // UINT64 iter_total;
} Patchpoint;
typedef std::vector<Patchpoint> Patchpoints;

std::set<std::string> lib_blacklist;
static Patchpoints patch_points;
static Patchpoints patch_points_uninst;
static BOOL detach_flag = false;

// static UINT8 *flags_val = NULL;
static std::map<ADDRINT, UINT16> pp2flag_val;
static std::map<ADDRINT, UINT16> pp2flag_msk;
//static UINT16 flags_val = 0;
//static UINT16 control_flag_msk = 0;

KNOB<std::string> KnobNewAddr(KNOB_MODE_WRITEONCE, "pintool", "addr", "0", "specify addrs of instructions");
// KNOB<std::string> KnobNewIterNum(KNOB_MODE_WRITEONCE, "pintool", "iter", "0", "specify how iteration this ins will be executed in a loop");
// KNOB<std::string> KnobNewNextBr(KNOB_MODE_WRITEONCE, "pintool", "n", "0", "next branch to flip");

VOID BranchFlip_SingleFlag(ADDRINT Ip, CONTEXT *ctx){
    PIN_GetContextRegval(ctx, REG_FLAGS, reinterpret_cast<UINT8 *>(&(pp2flag_val[Ip])));
    // printf("branch flip at %p\n", (void *)Ip);
    pp2flag_val[Ip] ^= pp2flag_msk[Ip];
    PIN_SetContextRegval(ctx, REG_FLAGS, reinterpret_cast<UINT8 *>(&(pp2flag_val[Ip])));
}

// CF = 1 or ZF = 1 OR CF = 0 and ZF = 0
VOID BranchFlip_MultiFlags_1(ADDRINT Ip, CONTEXT *ctx){
    PIN_GetContextRegval(ctx, REG_FLAGS, reinterpret_cast<UINT8 *>(&(pp2flag_val[Ip])));
    // printf("branch flip at %p\n", (void *)Ip);
    if ((pp2flag_val[Ip] & 0x0001) || (pp2flag_val[Ip] & 0x0040)){
        pp2flag_val[Ip] &= static_cast<UINT16>(~0x0001);
        pp2flag_val[Ip] &= static_cast<UINT16>(~0x0040);
    }else{
        pp2flag_val[Ip] ^= 0x0001;
    }
    PIN_SetContextRegval(ctx, REG_FLAGS, reinterpret_cast<UINT8 *>(&(pp2flag_val[Ip])));
}

// ZF = 1 or SF <> OF OR ZF = 0 and SF = OF
VOID BranchFlip_MultiFlags_2(ADDRINT Ip, CONTEXT *ctx){
    PIN_GetContextRegval(ctx, REG_FLAGS, reinterpret_cast<UINT8 *>(&(pp2flag_val[Ip])));
    // printf("branch flip at %p\n", (void *)Ip);
    if ( (pp2flag_val[Ip] & 0x0040) || ((pp2flag_val[Ip] & 0x0080) && !(pp2flag_val[Ip] & 0x0800)) || (!(pp2flag_val[Ip] & 0x0080) && (pp2flag_val[Ip] & 0x0800)) ){
        pp2flag_val[Ip] &= static_cast<UINT16>(~0x0040);
        pp2flag_val[Ip] &= static_cast<UINT16>(~0x0080);
        pp2flag_val[Ip] &= static_cast<UINT16>(~0x0800);
    }else{
        pp2flag_val[Ip] ^= 0x0040;
    }
    PIN_SetContextRegval(ctx, REG_FLAGS, reinterpret_cast<UINT8 *>(&(pp2flag_val[Ip])));
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
    auto it = std::find_if(patch_points_uninst.begin(), patch_points_uninst.end(), [=](const Patchpoint& pp){return pp.addr == addr_offset;});
    if (it == patch_points_uninst.end()) return;
    patch_points_uninst.erase(it);
    if (patch_points_uninst.empty()) detach_flag = true;
    if (!IsValidBranchIns(ins)) return;

    REG reg2mut = REG_FLAGS;
    REGSET regsetIn, regsetOut;
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
            pp2flag_msk[addr_offset] = 0x0800;
            INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)BranchFlip_SingleFlag,
                    IARG_ADDRINT, addr_offset,
                    IARG_PARTIAL_CONTEXT, &regsetIn, &regsetOut,
                    IARG_END);
            break;
        case XED_ICLASS_JS: 
        case XED_ICLASS_JNS: 
        case XED_ICLASS_JL: 
        case XED_ICLASS_JNL: 
            // SF
            pp2flag_msk[addr_offset] = 0x0080;
            INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)BranchFlip_SingleFlag,
                    IARG_ADDRINT, addr_offset,
                    IARG_PARTIAL_CONTEXT, &regsetIn, &regsetOut,
                    IARG_END);
            break;
        case XED_ICLASS_JZ:
        case XED_ICLASS_JNZ: 
            // ZF
            pp2flag_msk[addr_offset] = 0x0040;
            INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)BranchFlip_SingleFlag,
                    IARG_ADDRINT, addr_offset,
                    IARG_PARTIAL_CONTEXT, &regsetIn, &regsetOut,
                    IARG_END);
            break;
        case XED_ICLASS_JB:
        case XED_ICLASS_JNB:	
        	// CF
            pp2flag_msk[addr_offset] = 0x0001;
            INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)BranchFlip_SingleFlag,
                    IARG_ADDRINT, addr_offset,
                    IARG_PARTIAL_CONTEXT, &regsetIn, &regsetOut,
                    IARG_END);
            break;
        case XED_ICLASS_JP: 
        case XED_ICLASS_JNP: 	
            // PF
            pp2flag_msk[addr_offset] = 0x0004;
            INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)BranchFlip_SingleFlag,
                    IARG_ADDRINT, addr_offset,
                    IARG_PARTIAL_CONTEXT, &regsetIn, &regsetOut,
                    IARG_END);
            break;
        case XED_ICLASS_JBE: 
        case XED_ICLASS_JNBE: 
            INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)BranchFlip_MultiFlags_1,
                    IARG_ADDRINT, addr_offset,
                    IARG_PARTIAL_CONTEXT, &regsetIn, &regsetOut,
                    IARG_END);
            break;
        case XED_ICLASS_JLE: 
        case XED_ICLASS_JNLE: 
            INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)BranchFlip_MultiFlags_2,
                    IARG_ADDRINT, addr_offset,
                    IARG_PARTIAL_CONTEXT, &regsetIn, &regsetOut,
                    IARG_END);
            break;
        default:
            abort();
            //break;
    }
    pp2flag_val[addr_offset] = 0;

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
    if (KnobNewAddr.Value() == "") return false;

    lib_blacklist.insert("ld-linux-x86-64.so.2");
    lib_blacklist.insert("[vdso]");
    lib_blacklist.insert("libc.so.6");

    std::vector<std::string> addrs = get_tokens(KnobNewAddr.Value(), ",");
    if (addrs.empty()) return false;

    for (size_t i = 0; i < addrs.size(); i ++){
        Patchpoint pp;
        pp.addr = Uint64FromString(addrs[i]);
        patch_points.push_back(pp);
        std::cout << "pp: " << pp.addr <<  std::endl;
    }
    patch_points_uninst = patch_points;
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
    PIN_StartProgram();
    return 0;
}