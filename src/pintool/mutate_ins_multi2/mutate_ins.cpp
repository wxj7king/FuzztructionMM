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

//static int injected = 0;
enum VALID_INS_TYPE{
    INS_TYPE_MEM_READ,
    INS_TYPE_MEM_WRITE,
};
enum MUTATION_TYPE{
    BYTE_FLIP = 0,
    BIT_FLIP,
    RANDOM_BYTE,
    INJECT_VAL,
    U8ADD,
    RANDOM_BYTE0
};
#define RANDOM_MAX_STEPS 1024
typedef struct patch_point{
    ADDRINT addr;
    UINT64 injectValue;
    UINT64 mut_type;
    UINT64 mut_idx;
} Patchpoint;
typedef std::vector<Patchpoint> Patchpoints;
std::set<std::string> lib_blacklist;
Patchpoints patch_points;
static BOOL detach_flag = false;
static UINT32 *flip_idxes = NULL;
static UINT32 *last_flip_idxes = NULL;
static UINT32 *u8_adder = NULL;
static UINT8 *last_original_byte = NULL;
static int current_pps = 0;
std::random_device rd;
std::mt19937 gen(rd()); // Mersenne Twister engine
std::uniform_int_distribution<UINT8> dist_byte;
std::uniform_int_distribution<UINT8> dist_idx;
static int interest_val[] = {0, 1, 2};

KNOB<std::string> KnobNewAddr(KNOB_MODE_WRITEONCE, "pintool", "addr", "0", "specify addrs of instructions");
KNOB<std::string> KnobNewVal(KNOB_MODE_WRITEONCE, "pintool", "val", "512", "specify values to inject, pad 0 if not used");
KNOB<std::string> KnobNewMut(KNOB_MODE_WRITEONCE, "pintool", "mut", "1", "specify mutation types");
KNOB<std::string> KnobNewMutIdx(KNOB_MODE_WRITEONCE, "pintool", "idx", "0", "specify index of byte/bit to mutate, pad 0 if not used");

// VOID MutateReg(ADDRINT Ip, REG reg, UINT32 reg_size, UINT64 injectValue, CONTEXT *ctx){
//     UINT8 *reg_val = (UINT8 *)malloc(reg_size);
//     PIN_GetContextRegval(ctx, reg, reg_val);
//     UINT8 *ptr = (UINT8 *)&injectValue;
//     //printf("instruction@0x%lx, inject value of register %s with %ld, original value=%ld\n", Ip, REG_StringShort(reg).c_str(), injectValue, *(ADDRINT*)reg_val);
//     for (UINT32 i = 0; i < reg_size; i++){
//         reg_val[i] = ptr[i];
//     }
//     printf("instruction@0x%lx, inject value of register %s with %ld\n", Ip, REG_StringShort(reg).c_str(), *(ADDRINT*)reg_val);
//     PIN_SetContextRegval(ctx, reg, reg_val);
//     free(reg_val);
//     return;
// }

VOID ByteFlip(ADDRINT Ip, REG reg, UINT32 reg_size, UINT32 cur_pps, CONTEXT *ctx){
    if (flip_idxes[cur_pps] >= reg_size) return;
    UINT8 *reg_val = (UINT8 *)malloc(reg_size);
    PIN_GetContextRegval(ctx, reg, reg_val);
    // revert mutation
    if (flip_idxes[cur_pps] != 0) reg_val[last_flip_idxes[cur_pps]] ^= 0xff;
    //printf("byte flip: instruction@0x%lx, register %s, original value=%ld, cur_pps: %d ", Ip, REG_StringShort(reg).c_str(), *(ADDRINT*)reg_val, cur_pps);
    // flip byte
    last_flip_idxes[cur_pps] = flip_idxes[cur_pps];
    reg_val[flip_idxes[cur_pps]] ^= 0xff;
    flip_idxes[cur_pps]++;
    //printf("mutated value of register is %ld\n", *(ADDRINT*)reg_val);
    PIN_SetContextRegval(ctx, reg, reg_val);
    free(reg_val);
    return;
}

VOID BitFlip(ADDRINT Ip, REG reg, UINT32 reg_size, UINT32 cur_pps, CONTEXT *ctx){
    if (flip_idxes[cur_pps] >= reg_size * 8) return;
    UINT8 *reg_val = (UINT8 *)malloc(reg_size);
    PIN_GetContextRegval(ctx, reg, reg_val);
    // revert mutation
    if (flip_idxes[cur_pps] != 0) reg_val[last_flip_idxes[cur_pps] / 8] ^= 1 << (last_flip_idxes[cur_pps] % 8);
    //printf("bit flip: instruction@0x%lx, register %s, original value=%ld cur_pps: %d", Ip, REG_StringShort(reg).c_str(), *(ADDRINT*)reg_val, cur_pps);
    // flip bit
    last_flip_idxes[cur_pps] = flip_idxes[cur_pps];
    reg_val[flip_idxes[cur_pps] / 8] ^= 1 << (flip_idxes[cur_pps] % 8);
    flip_idxes[cur_pps]++;
    //printf("mutated value of register is %ld\n", *(ADDRINT*)reg_val);
    PIN_SetContextRegval(ctx, reg, reg_val);
    free(reg_val);
    return;
}
VOID RandomByte(ADDRINT Ip, REG reg, UINT32 reg_size, UINT32 cur_pps, CONTEXT *ctx){
    // use flip_idxes[cur_pps] as the number of current steps
    if (reg_size == 0) return;
    if (flip_idxes[cur_pps] >= RANDOM_MAX_STEPS) return;
    UINT8 *reg_val = (UINT8 *)malloc(reg_size);
    PIN_GetContextRegval(ctx, reg, reg_val);
    // revert mutation
    if (flip_idxes[cur_pps] != 0) reg_val[last_flip_idxes[cur_pps]] = last_original_byte[cur_pps];
    //printf("random byte: instruction@0x%lx, register %s, original value=%ld, cur_pps: %d ", Ip, REG_StringShort(reg).c_str(), *(ADDRINT*)reg_val, cur_pps);
    // random byte at random index
    last_flip_idxes[cur_pps] = dist_idx(gen) % reg_size;
    last_original_byte[cur_pps] = dist_byte(gen);
    reg_val[last_flip_idxes[cur_pps]] = last_original_byte[cur_pps];
    flip_idxes[cur_pps]++;
    //printf("random idx: %d, random byte: %d, mutated value of register is %ld\n", last_flip_idxes[cur_pps], last_original_byte[cur_pps], *(ADDRINT*)reg_val);
    PIN_SetContextRegval(ctx, reg, reg_val);
    free(reg_val);
    return;
}

VOID RandomByte0(ADDRINT Ip, REG reg, UINT32 reg_size, UINT32 cur_pps, CONTEXT *ctx){
    // use flip_idxes[cur_pps] as the number of current steps
    if (reg_size == 0) return;
    if (flip_idxes[cur_pps] >= RANDOM_MAX_STEPS) return;
    UINT8 *reg_val = (UINT8 *)malloc(reg_size);
    PIN_GetContextRegval(ctx, reg, reg_val);
    // revert mutation
    //printf("random byte0: instruction@0x%lx, register %s, original value=%ld, cur_pps: %d ", Ip, REG_StringShort(reg).c_str(), *(ADDRINT*)reg_val, cur_pps);
    // random byte at 0th byte
    reg_val[0] = dist_byte(gen);
    flip_idxes[cur_pps]++;
    //printf("at idx 0, random byte: %d, mutated value of register is %ld\n", reg_val[0], *(ADDRINT*)reg_val);
    PIN_SetContextRegval(ctx, reg, reg_val);
    free(reg_val);
    return;
}

VOID U8Add(ADDRINT Ip, REG reg, UINT32 reg_size, UINT32 cur_pps, CONTEXT *ctx){
    if (flip_idxes[cur_pps] >= reg_size) return;
    UINT8 *reg_val = (UINT8 *)malloc(reg_size);
    PIN_GetContextRegval(ctx, reg, reg_val);
    // revert mutation
    if (u8_adder[cur_pps] != 0) reg_val[last_flip_idxes[cur_pps]] = last_original_byte[cur_pps];
    //printf("u8 adder: instruction@0x%lx, register %s, original value=%ld, cur_pps: %d ", Ip, REG_StringShort(reg).c_str(), *(ADDRINT*)reg_val, cur_pps);
    // save original byte
    last_flip_idxes[cur_pps] = flip_idxes[cur_pps];
    last_original_byte[cur_pps] = reg_val[flip_idxes[cur_pps]];
    // xor with uint8 value
    reg_val[flip_idxes[cur_pps]] ^= (u8_adder[cur_pps] % 256);
    u8_adder[cur_pps]++;
    if (u8_adder[cur_pps] % 256 == 0){
        // don't set u8_adder[cur_pps] to 0 because we need this to revert mutation above
        // next byte
        flip_idxes[cur_pps]++;
    }

    //printf("mutated value of register is %ld\n", *(ADDRINT*)reg_val);
    PIN_SetContextRegval(ctx, reg, reg_val);
    free(reg_val);
    return;
}

VOID InjectVal(ADDRINT Ip, REG reg, UINT32 reg_size, CONTEXT *ctx){
    if (reg_size == 0) return;
    UINT8 *reg_val = (UINT8 *)malloc(reg_size);
    reg_val[0] = interest_val[dist_byte(gen) % 3];
    //printf("inject value: instruction@0x%lx, inject value of register %s with %ld\n", Ip, REG_StringShort(reg).c_str(), injectValue);
    PIN_SetContextRegval(ctx, reg, reg_val);
    free(reg_val);
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
        
        default:
            return false;
    }
}

VOID InstrumentIns(INS ins, ADDRINT baseAddr)
//VOID InstrumentIns(INS ins, VOID *v)
{
    xed_iclass_enum_t ins_opcode = (xed_iclass_enum_t)INS_Opcode(ins);
    if (ins_opcode != XED_ICLASS_MOV) return;
    //printf("instruction@%p: %s\n", (void *)INS_Address(ins), INS_Disassemble(ins).c_str());
    ADDRINT addr_offset = (INS_Address(ins) - baseAddr);
    auto it = std::find_if(patch_points.begin(), patch_points.end(), [=](const Patchpoint& pp){return pp.addr == addr_offset;});
    if (it == patch_points.end()) return;
    Patchpoint pp = *it;
    patch_points.erase(it);
    if (patch_points.empty()) detach_flag = true;

    printf("instruction@%p, mutation type: %ld, inject value=%ld, idx=%ld, end flag=%d\n", (void *)pp.addr, pp.mut_type, pp.injectValue, pp.mut_idx, detach_flag);
    //AFUNPTR mut_func = NULL;
    IPOINT ipoint;
    REG reg2mut = REG_INVALID();
    REGSET regsetIn, regsetOut;
    UINT32 reg_size = 0;

    // TODO: use IPOINT to remove similar code
    if (INS_IsMemoryRead(ins) && !INS_IsRet(ins)){
        if (!INS_OperandIsReg(ins, 0)) return;
        reg2mut = INS_OperandReg(ins, 0);
        if (!IsValidReg(reg2mut)) return;
        //printf("data read instruction@%p, %s, %s\n", (void *)INS_Address(ins), INS_Disassemble(ins).c_str(), REG_StringShort(reg2mut).c_str());
        //printf("data read instruction@%p, %s\n", (void *)INS_Address(ins), INS_Disassemble(ins).c_str()); 
        //printf("data read instruction: %s\n", INS_Disassemble(ins).c_str());

        REGSET_Insert(regsetIn, reg2mut);
        REGSET_Insert(regsetIn, REG_FullRegName(reg2mut));
        REGSET_Insert(regsetOut, reg2mut);
        REGSET_Insert(regsetOut, REG_FullRegName(reg2mut));
        reg_size = REG_Size(reg2mut);
        ipoint = IPOINT_AFTER;

    }

    if (INS_IsMemoryWrite(ins)){
        if (!INS_OperandIsReg(ins, 1)) return;
        reg2mut = INS_OperandReg(ins, 1);
        if (!IsValidReg(reg2mut)) return;
        //printf("data write instruction@%p, %s, %s\n", (void *)INS_Address(ins), INS_Disassemble(ins).c_str(), REG_StringShort(reg2mut).c_str());
        //printf("data write instruction@%p, %s\n", (void *)INS_Address(ins), INS_Disassemble(ins).c_str());
        //printf("data write instruction: %s\n", INS_Disassemble(ins).c_str());

        REGSET_Insert(regsetIn, reg2mut);
        REGSET_Insert(regsetIn, REG_FullRegName(reg2mut));
        REGSET_Insert(regsetOut, reg2mut);
        REGSET_Insert(regsetOut, REG_FullRegName(reg2mut));
        reg_size = REG_Size(reg2mut);
        ipoint = IPOINT_BEFORE;
    }

    switch (pp.mut_type)
    {
        case BYTE_FLIP:
            INS_InsertCall(ins, ipoint, (AFUNPTR)ByteFlip,
                        IARG_INST_PTR,// application IP
                        IARG_UINT32, reg2mut,
                        IARG_UINT32, reg_size,
                        IARG_UINT32, current_pps,
                        IARG_PARTIAL_CONTEXT, &regsetIn, &regsetOut,
                        IARG_END);
            break;
        case BIT_FLIP:
            INS_InsertCall(ins, ipoint, (AFUNPTR)BitFlip,
                        IARG_INST_PTR,// application IP
                        IARG_UINT32, reg2mut,
                        IARG_UINT32, reg_size,
                        IARG_UINT32, current_pps,
                        IARG_PARTIAL_CONTEXT, &regsetIn, &regsetOut,
                        IARG_END);
            break;
        case RANDOM_BYTE:
            INS_InsertCall(ins, ipoint, (AFUNPTR)RandomByte,
                        IARG_INST_PTR,// application IP
                        IARG_UINT32, reg2mut,
                        IARG_UINT32, reg_size,
                        IARG_UINT32, current_pps,
                        IARG_PARTIAL_CONTEXT, &regsetIn, &regsetOut,
                        IARG_END);
            break;
        case INJECT_VAL:
            INS_InsertCall(ins, ipoint, (AFUNPTR)InjectVal,
                        IARG_INST_PTR,// application IP
                        IARG_UINT32, reg2mut,
                        IARG_UINT32, reg_size,
                        IARG_PARTIAL_CONTEXT, &regsetIn, &regsetOut,
                        IARG_END);
            break;
        case U8ADD:
            INS_InsertCall(ins, ipoint, (AFUNPTR)U8Add,
                        IARG_INST_PTR,// application IP
                        IARG_UINT32, reg2mut,
                        IARG_UINT32, reg_size,
                        IARG_UINT32, current_pps,
                        IARG_PARTIAL_CONTEXT, &regsetIn, &regsetOut,
                        IARG_END);
            break;
        case RANDOM_BYTE0:
            INS_InsertCall(ins, ipoint, (AFUNPTR)RandomByte0,
                        IARG_INST_PTR,// application IP
                        IARG_UINT32, reg2mut,
                        IARG_UINT32, reg_size,
                        IARG_UINT32, current_pps,
                        IARG_PARTIAL_CONTEXT, &regsetIn, &regsetOut,
                        IARG_END);
            break;
        default:
            printf("error: invalid mutation type\n");
            return;
    }
    current_pps++;

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
    free(flip_idxes);
    free(last_original_byte);
    free(last_flip_idxes);
    free(u8_adder);
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
    if (KnobNewAddr.Value() == "" || KnobNewVal.Value() == "" || KnobNewMut.Value() == "" || KnobNewMutIdx.Value() == "") return false;

    lib_blacklist.insert("ld-linux-x86-64.so.2");
    lib_blacklist.insert("[vdso]");
    lib_blacklist.insert("libc.so.6");

    std::vector<std::string> args1 = get_tokens(KnobNewAddr.Value(), ",");
    std::vector<std::string> args2 = get_tokens(KnobNewVal.Value(), ",");
    std::vector<std::string> args3 = get_tokens(KnobNewMut.Value(), ",");
    std::vector<std::string> args4 = get_tokens(KnobNewMutIdx.Value(), ",");

    if (args1.size() != args2.size() || args2.size() != args3.size() || args3.size() != args4.size()) return false;

    for (size_t i = 0; i < args1.size(); i ++){
        Patchpoint pp;
        pp.addr = Uint64FromString(args1[i]);
        pp.injectValue = Uint64FromString(args2[i]);
        pp.mut_type = Uint64FromString(args3[i]);
        pp.mut_idx = Uint64FromString(args4[i]);
        patch_points.push_back(pp);
        std::cout << "pp: " << pp.addr << "," << pp.injectValue << "," << pp.mut_type << "," << pp.mut_idx << std::endl;
    }

    flip_idxes = (UINT32 *)calloc(args1.size(), sizeof(UINT32));
    last_flip_idxes = (UINT32 *)calloc(args1.size(), sizeof(UINT32));
    u8_adder = (UINT32 *)calloc(args1.size(), sizeof(UINT32));
    last_original_byte = (UINT8 *)calloc(args1.size(), sizeof(UINT8));

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