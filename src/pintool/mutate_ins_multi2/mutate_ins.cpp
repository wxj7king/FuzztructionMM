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
enum MUTATION_TYPE{
    BYTE_FLIP = 0,
    BIT_FLIP,
    RANDOM_BYTE,
    RANDOM_BYTE0,
    U8ADD,
    INJECT_VAL,
    COMBINE
};
#define RANDOM_MAX_STEPS 1024
typedef struct patch_point{
    ADDRINT addr;
    UINT64 mut_type;
} Patchpoint;
typedef std::vector<Patchpoint> Patchpoints;
std::set<std::string> lib_blacklist;
Patchpoints patch_points;
static BOOL detach_flag = false;
static UINT32 *flip_idxes = NULL;
static UINT32 *u8_adder = NULL;
static int current_pps = 0;
std::random_device rd;
std::mt19937 gen(rd()); // Mersenne Twister engine
std::uniform_int_distribution<UINT8> dist_byte;
std::uniform_int_distribution<UINT8> dist_idx;
std::uniform_int_distribution<UINT8> dist_mut(0, 4);
static int interest_val[] = {0, 1, 2};

KNOB<std::string> KnobNewAddr(KNOB_MODE_WRITEONCE, "pintool", "addr", "0", "specify addrs of instructions");
KNOB<std::string> KnobNewMut(KNOB_MODE_WRITEONCE, "pintool", "mut", "1", "specify mutation types");

VOID ByteFlip(ADDRINT Ip, REG reg, UINT32 reg_size, UINT32 cur_pps, CONTEXT *ctx){
    if (flip_idxes[cur_pps] >= reg_size) flip_idxes[cur_pps] = 0;
    UINT8 *reg_val = (UINT8 *)malloc(reg_size);
    PIN_GetContextRegval(ctx, reg, reg_val);
    //printf("byte flip: instruction@0x%lx, register %s, original value=%ld, cur_pps: %d ", Ip, REG_StringShort(reg).c_str(), *(ADDRINT*)reg_val, cur_pps);
    // flip byte
    reg_val[flip_idxes[cur_pps]] ^= 0xff;
    flip_idxes[cur_pps]++;
    //printf("mutated value of register is %ld\n", *(ADDRINT*)reg_val);
    PIN_SetContextRegval(ctx, reg, reg_val);
    free(reg_val);
    return;
}

VOID BitFlip(ADDRINT Ip, REG reg, UINT32 reg_size, UINT32 cur_pps, CONTEXT *ctx){
    if (flip_idxes[cur_pps] >= reg_size * 8) flip_idxes[cur_pps] = 0;
    UINT8 *reg_val = (UINT8 *)malloc(reg_size);
    PIN_GetContextRegval(ctx, reg, reg_val);
    //printf("bit flip: instruction@0x%lx, register %s, original value=%ld cur_pps: %d", Ip, REG_StringShort(reg).c_str(), *(ADDRINT*)reg_val, cur_pps);
    // flip bit
    reg_val[flip_idxes[cur_pps] / 8] ^= 1 << (flip_idxes[cur_pps] % 8);
    flip_idxes[cur_pps]++;
    //printf("mutated value of register is %ld\n", *(ADDRINT*)reg_val);
    PIN_SetContextRegval(ctx, reg, reg_val);
    free(reg_val);
    return;
}
VOID RandomByte(ADDRINT Ip, REG reg, UINT32 reg_size, UINT32 cur_pps, CONTEXT *ctx){
    // use flip_idxes[cur_pps] as the number of current steps
    if (flip_idxes[cur_pps] >= RANDOM_MAX_STEPS) return;
    UINT8 *reg_val = (UINT8 *)malloc(reg_size);
    PIN_GetContextRegval(ctx, reg, reg_val);
    //printf("random byte: instruction@0x%lx, register %s, original value=%ld, cur_pps: %d ", Ip, REG_StringShort(reg).c_str(), *(ADDRINT*)reg_val, cur_pps);
    // random byte at random index
    // UINT8 random_idx = dist_idx(gen) % reg_size;
    // UINT8 random_val = dist_byte(gen);
    // reg_val[random_idx] = random_val;
    reg_val[dist_idx(gen) % reg_size] = dist_byte(gen);
    flip_idxes[cur_pps]++;
    //printf("random idx: %d, random byte: %d, mutated value of register is %ld\n", random_idx, random_val, *(ADDRINT*)reg_val);
    PIN_SetContextRegval(ctx, reg, reg_val);
    free(reg_val);
    return;
}

VOID RandomByte0(ADDRINT Ip, REG reg, UINT32 reg_size, UINT32 cur_pps, CONTEXT *ctx){
    // use flip_idxes[cur_pps] as the number of current steps
    if (flip_idxes[cur_pps] >= RANDOM_MAX_STEPS) return;
    UINT8 *reg_val = (UINT8 *)malloc(reg_size);
    PIN_GetContextRegval(ctx, reg, reg_val);
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
    if (flip_idxes[cur_pps] >= reg_size) flip_idxes[cur_pps] = 0;
    UINT8 *reg_val = (UINT8 *)malloc(reg_size);
    PIN_GetContextRegval(ctx, reg, reg_val);
    //printf("u8 adder: instruction@0x%lx, register %s, original value=%ld, cur_pps: %d ", Ip, REG_StringShort(reg).c_str(), *(ADDRINT*)reg_val, cur_pps);
    // xor with uint8 value
    reg_val[flip_idxes[cur_pps]] ^= (u8_adder[cur_pps]);
    u8_adder[cur_pps]++;
    if (u8_adder[cur_pps] % 256 == 0){
        // next byte
        u8_adder[cur_pps] = 0;
        flip_idxes[cur_pps]++;
    }
    //printf("mutated value of register is %ld\n", *(ADDRINT*)reg_val);
    PIN_SetContextRegval(ctx, reg, reg_val);
    free(reg_val);
    return;
}

VOID InjectVal(ADDRINT Ip, REG reg, UINT32 reg_size, CONTEXT *ctx){
    UINT8 *reg_val = (UINT8 *)calloc(1, reg_size);
    reg_val[0] = interest_val[dist_byte(gen) % 3];
    //printf("inject value: instruction@0x%lx, inject value of register %s with %ld\n", Ip, REG_StringShort(reg).c_str(), injectValue);
    PIN_SetContextRegval(ctx, reg, reg_val);
    free(reg_val);
    return;
}

VOID Combine(ADDRINT Ip, REG reg, UINT32 reg_size, UINT32 cur_pps, CONTEXT *ctx){
    // use flip_idxes[cur_pps] as the number of current steps
    if (flip_idxes[cur_pps] >= RANDOM_MAX_STEPS) return;
    UINT8 *reg_val = (UINT8 *)malloc(reg_size);
    PIN_GetContextRegval(ctx, reg, reg_val);
    //printf("combine: instruction@0x%lx, register %s, original value=%ld, cur_pps: %d ", Ip, REG_StringShort(reg).c_str(), *(ADDRINT*)reg_val, cur_pps);
    // randomly select a mutation
    UINT8 mut = dist_mut(gen);
    if (mut == 0){
        reg_val[dist_idx(gen) % reg_size] ^= 0xff;
    }else if (mut == 1){
        UINT8 rand_idx = dist_idx(gen) % (reg_size * 8);
        reg_val[rand_idx / 8] ^= 1 << (rand_idx % 8);
    }else if (mut == 2){
        reg_val[dist_idx(gen) % reg_size] = dist_byte(gen);
    }else if (mut == 3){
        reg_val[0] = dist_byte(gen);
    }else if (mut == 4){
        reg_val[0] = interest_val[dist_byte(gen) % 3];
        for (size_t i = 1; i < reg_size; i++) reg_val[i] = 0;
    }
    flip_idxes[cur_pps]++;
    //printf("mut: %d, mutated value of register is %ld\n", mut, *(ADDRINT*)reg_val);
    PIN_SetContextRegval(ctx, reg, reg_val);
    free(reg_val);
    return;
}

VOID InstrumentIns(INS ins, ADDRINT baseAddr)
{
    //xed_iclass_enum_t ins_opcode = (xed_iclass_enum_t)INS_Opcode(ins);
    //printf("instruction@%p: %s\n", (void *)INS_Address(ins), INS_Disassemble(ins).c_str());
    ADDRINT addr_offset = (INS_Address(ins) - baseAddr);
    auto it = std::find_if(patch_points.begin(), patch_points.end(), [=](const Patchpoint& pp){return pp.addr == addr_offset;});
    if (it == patch_points.end()) return;
    Patchpoint pp = *it;
    patch_points.erase(it);
    if (patch_points.empty()) detach_flag = true;

    printf("instruction@%p, mutation type: %ld, end flag=%d\n", (void *)pp.addr, pp.mut_type, detach_flag);
    //AFUNPTR mut_func = NULL;
    IPOINT ipoint;
    REG reg2mut = REG_INVALID();
    REGSET regsetIn, regsetOut;
    UINT32 reg_size = 0;

    if (INS_IsMemoryRead(ins)){
        if (!INS_OperandIsReg(ins, 0)) return;
        reg2mut = INS_OperandReg(ins, 0);
        //printf("data read instruction@%p, %s, %s\n", (void *)INS_Address(ins), INS_Disassemble(ins).c_str(), REG_StringShort(reg2mut).c_str());
        ipoint = IPOINT_AFTER;
    }

    if (INS_IsMemoryWrite(ins)){
        if (!INS_OperandIsReg(ins, 1)) return;
        reg2mut = INS_OperandReg(ins, 1);
        //printf("data write instruction@%p, %s, %s\n", (void *)INS_Address(ins), INS_Disassemble(ins).c_str(), REG_StringShort(reg2mut).c_str());
        ipoint = IPOINT_BEFORE;
    }

    REGSET_Insert(regsetIn, reg2mut);
    REGSET_Insert(regsetIn, REG_FullRegName(reg2mut));
    REGSET_Insert(regsetOut, reg2mut);
    REGSET_Insert(regsetOut, REG_FullRegName(reg2mut));
    reg_size = REG_Size(reg2mut);

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
        case COMBINE:
            INS_InsertCall(ins, ipoint, (AFUNPTR)Combine,
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
    if (KnobNewAddr.Value() == "" || KnobNewMut.Value() == "") return false;

    lib_blacklist.insert("ld-linux-x86-64.so.2");
    lib_blacklist.insert("[vdso]");
    lib_blacklist.insert("libc.so.6");

    std::vector<std::string> args1 = get_tokens(KnobNewAddr.Value(), ",");
    std::vector<std::string> args2 = get_tokens(KnobNewMut.Value(), ",");

    if (args1.size() != args2.size()) return false;

    for (size_t i = 0; i < args1.size(); i ++){
        Patchpoint pp;
        pp.addr = Uint64FromString(args1[i]);
        pp.mut_type = Uint64FromString(args2[i]);
        patch_points.push_back(pp);
        std::cout << "pp: " << pp.addr << "," << pp.mut_type << "," << std::endl;
    }

    flip_idxes = (UINT32 *)calloc(args1.size(), sizeof(UINT32));
    u8_adder = (UINT32 *)calloc(args1.size(), sizeof(UINT32));

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