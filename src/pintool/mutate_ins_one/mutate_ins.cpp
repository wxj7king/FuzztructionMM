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

enum MUTATION_TYPE{
    BYTE_FLIP = 0,
    BIT_FLIP,
    RANDOM_BYTE,
    RANDOM_BYTE0,
    U8ADD,
    HAVOC
};

typedef struct patch_point{
    ADDRINT addr;
    UINT64 mut_type;
    UINT64 iter_total;
    UINT64 iter2mut;
    UINT64 mut_offset;
} Patchpoint;
std::set<std::string> lib_blacklist;
static Patchpoint patch_point;
static BOOL detach_flag = false;
static BOOL fliped = false;
static UINT8 u8_adder = 0;
static int interest_val[] = {0, 1, 2, 0x80};
static UINT8 *reg_val = NULL;
static UINT8 *flags_val = NULL;
static UINT64 cur_iter = 0;
static ADDRINT branch_addr = 0;
static std::set<ADDRINT> inst_set;
static UINT8 havoc_count = 0;

std::random_device rd;
std::mt19937 gen(rd()); // Mersenne Twister engine
std::uniform_int_distribution<UINT8> dist_byte;
std::uniform_int_distribution<UINT8> dist_idx;
std::uniform_int_distribution<UINT8> dist_havoc(0, 5);
std::uniform_int_distribution<UINT32> u32_dist;

KNOB<std::string> KnobNewAddr(KNOB_MODE_WRITEONCE, "pintool", "addr", "0", "specify addrs of instructions");
KNOB<std::string> KnobNewMut(KNOB_MODE_WRITEONCE, "pintool", "mut", "0", "specify mutation types");
KNOB<std::string> KnobNewIterNum(KNOB_MODE_WRITEONCE, "pintool", "iter", "0", "specify how iteration this ins will be executed in a loop");
KNOB<std::string> KnobNewIter2Mut(KNOB_MODE_WRITEONCE, "pintool", "iter2mut", "0", "specify in which iteration its mutation will be applied");
KNOB<std::string> KnobNewOffset(KNOB_MODE_WRITEONCE, "pintool", "off", "0", "index of byte or bit in the register");
KNOB<std::string> KnobNewU8Adder(KNOB_MODE_WRITEONCE, "pintool", "u8", "0", "value of uint8_t added to a byte in a register");
KNOB<std::string> KnobNewBranchAddr(KNOB_MODE_WRITEONCE, "pintool", "baddr", "0", "specify addr of branch instruction");

VOID ByteFlip(ADDRINT Ip, REG reg, UINT32 reg_size, CONTEXT *ctx){
    PIN_GetContextRegval(ctx, reg, reg_val);
    printf("byte flip: instruction@0x%lx, register %s, original value=%lu ,", Ip, REG_StringShort(reg).c_str(), *(ADDRINT*)reg_val);
    // flip byte
    if (cur_iter == patch_point.iter2mut)
        reg_val[patch_point.mut_offset] ^= 0xff;
    printf("mutated value of register is %lu\n", *(ADDRINT*)reg_val);
    PIN_SetContextRegval(ctx, reg, reg_val);
    cur_iter++;
    if (cur_iter > patch_point.iter2mut && branch_addr == 0) PIN_Detach();
    return;
}

VOID BitFlip(ADDRINT Ip, REG reg, UINT32 reg_size, CONTEXT *ctx){
    PIN_GetContextRegval(ctx, reg, reg_val);
    printf("bit flip: instruction@0x%lx, register %s, original value=%ld ,", Ip, REG_StringShort(reg).c_str(), *(ADDRINT*)reg_val);
    // flip bit
    if (cur_iter == patch_point.iter2mut)
        reg_val[patch_point.mut_offset / 8] ^= 1 << (patch_point.mut_offset % 8);
    printf("mutated value of register is %ld\n", *(ADDRINT*)reg_val);
    PIN_SetContextRegval(ctx, reg, reg_val);
    cur_iter++;
    if (cur_iter > patch_point.iter2mut && branch_addr == 0) PIN_Detach();
    return;
}
VOID RandomByte(ADDRINT Ip, REG reg, UINT32 reg_size, CONTEXT *ctx){
    PIN_GetContextRegval(ctx, reg, reg_val);
    //printf("random byte: instruction@0x%lx, register %s, original value=%ld ,", Ip, REG_StringShort(reg).c_str(), *(ADDRINT*)reg_val);
    // random byte at random index
    // UINT8 random_idx = dist_idx(gen) % reg_size;
    // UINT8 random_val = dist_byte(gen);
    // reg_val[random_idx] = random_val;
    if (cur_iter == patch_point.iter2mut)
    {
        if (patch_point.mut_offset != 0) 
            reg_val[patch_point.mut_offset] = dist_byte(gen);
        else 
            reg_val[dist_idx(gen) % reg_size] = dist_byte(gen);
    }
    
    //printf("random idx: %d, random byte: %d, mutated value of register is %ld\n", random_idx, random_val, *(ADDRINT*)reg_val);
    PIN_SetContextRegval(ctx, reg, reg_val);
    cur_iter++;
    if (cur_iter > patch_point.iter2mut && branch_addr == 0) PIN_Detach();
    return;
}

VOID RandomByte0(ADDRINT Ip, REG reg, UINT32 reg_size, CONTEXT *ctx){
    PIN_GetContextRegval(ctx, reg, reg_val);
    //printf("random byte0: instruction@0x%lx, register %s, original value=%ld ,", Ip, REG_StringShort(reg).c_str(), *(ADDRINT*)reg_val);
    // random byte at 0th byte
    if (cur_iter == patch_point.iter2mut)
        reg_val[0] = dist_byte(gen);
    //printf("at idx 0, random byte: %d, mutated value of register is %ld\n", reg_val[0], *(ADDRINT*)reg_val);
    PIN_SetContextRegval(ctx, reg, reg_val);
    cur_iter++;
    if (cur_iter > patch_point.iter2mut && branch_addr == 0) PIN_Detach();
    return;
}

VOID U8Add(ADDRINT Ip, REG reg, UINT32 reg_size, CONTEXT *ctx){
    PIN_GetContextRegval(ctx, reg, reg_val);
    printf("u8 adder: instruction@0x%lx, register %s, original value=%ld ,", Ip, REG_StringShort(reg).c_str(), *(ADDRINT*)reg_val);
    // xor with uint8 value
    if (cur_iter == patch_point.iter2mut)
        reg_val[patch_point.mut_offset] ^= u8_adder;
    printf("mutated value of register is %ld\n", *(ADDRINT*)reg_val);
    PIN_SetContextRegval(ctx, reg, reg_val);
    cur_iter++;
    if (cur_iter > patch_point.iter2mut && branch_addr == 0) PIN_Detach();
    return;
}

VOID Havoc(ADDRINT Ip, REG reg, UINT32 reg_size, CONTEXT *ctx){
    if (havoc_count > 4) return;
    PIN_GetContextRegval(ctx, reg, reg_val);
    //printf("havoc: instruction@0x%lx, register %s, original value=%ld ,", Ip, REG_StringShort(reg).c_str(), *(ADDRINT*)reg_val);
    // randomly select a mutation
    UINT8 mut = dist_havoc(gen);
    if (mut == 0){
        reg_val[dist_idx(gen) % reg_size] ^= 0xff;
    }else if (mut == 1){
        UINT8 rand_idx = dist_idx(gen) % (reg_size * 8);
        reg_val[rand_idx / 8] ^= 1 << (rand_idx % 8);
    }else if (mut == 2){
        reg_val[dist_idx(gen) % reg_size] = dist_byte(gen);
    }else if (mut == 3){
        reg_val[0] = interest_val[dist_byte(gen) % 4];
        for (size_t i = 1; i < reg_size; i++) reg_val[i] = 0;
    }else if (mut == 4){
        reg_val[0] = dist_byte(gen);
    }
    // do not mutate if mut == 5
    if (mut != 5) havoc_count++;

    //printf("mut: %d, mutated value of register is %ld\n", mut, *(ADDRINT*)reg_val);
    PIN_SetContextRegval(ctx, reg, reg_val);
    if (havoc_count > 4 && branch_addr == 0) PIN_Detach();
    return;
}

VOID BranchFlip(ADDRINT Ip, REG reg, UINT32 reg_size, CONTEXT *ctx){
    //printf("curr iter %ld\n", cur_iter);
    if (fliped) return;
    PIN_GetContextRegval(ctx, reg, flags_val);
    // ZF mask is 0x0040
    if (cur_iter - 1 == patch_point.iter2mut){
        printf("branch flip at %p\n", (void *)Ip);
        BOOL if_zero = true;
        for (size_t i = 0; i < reg_size; i++)
        {
            if (flags_val[i] != 0){
                if_zero = false;
                break;
            }
        }
        if (if_zero){
            flags_val[0] = 1;
        }else{
            for (size_t i = 0; i < reg_size; i++)
                flags_val[i] = 0;
        }
        fliped = true;
        PIN_Detach();
    }
    PIN_SetContextRegval(ctx, reg, flags_val);
    return;
}

VOID InstrumentIns(INS ins, ADDRINT baseAddr)
{
    //xed_iclass_enum_t ins_opcode = (xed_iclass_enum_t)INS_Opcode(ins);
    //printf("instruction@%p: %s\n", (void *)INS_Address(ins), INS_Disassemble(ins).c_str());
    ADDRINT addr_offset = (INS_Address(ins) - baseAddr);
    if (patch_point.addr != addr_offset && branch_addr != addr_offset) return;
    if (inst_set.count(addr_offset) == 1) return;
    inst_set.insert(addr_offset);

    IPOINT ipoint;
    REG reg2mut = REG_INVALID();
    REGSET regsetIn, regsetOut;
    UINT32 reg_size = 0;
    
    /// mov ins that determines branch taken
    if (addr_offset == branch_addr){
        printf("branch flip@%p, %s\n", (void *)addr_offset, INS_Disassemble(ins).c_str());
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
        flags_val = (UINT8 *)calloc(reg_size, 1);
        INS_InsertCall(ins, ipoint, (AFUNPTR)BranchFlip,
                        IARG_INST_PTR,// application IP
                        IARG_UINT32, reg2mut,
                        IARG_UINT32, reg_size,
                        IARG_PARTIAL_CONTEXT, &regsetIn, &regsetOut,
                        IARG_END);
        return;
    }

    printf("instruction@%p, mutation type: %ld, end flag=%d\n", (void *)addr_offset, patch_point.mut_type, detach_flag);

    /// data read and write
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
    if (reg_val == NULL) reg_val = (UINT8 *)calloc(reg_size, 1);

    switch (patch_point.mut_type)
    {
        case BYTE_FLIP:
            INS_InsertCall(ins, ipoint, (AFUNPTR)ByteFlip,
                        IARG_INST_PTR,// application IP
                        IARG_UINT32, reg2mut,
                        IARG_UINT32, reg_size,
                        IARG_PARTIAL_CONTEXT, &regsetIn, &regsetOut,
                        IARG_END);
            break;
        case BIT_FLIP:
            INS_InsertCall(ins, ipoint, (AFUNPTR)BitFlip,
                        IARG_INST_PTR,// application IP
                        IARG_UINT32, reg2mut,
                        IARG_UINT32, reg_size,
                        IARG_PARTIAL_CONTEXT, &regsetIn, &regsetOut,
                        IARG_END);
            break;
        case RANDOM_BYTE:
            patch_point.iter2mut = u32_dist(gen) % patch_point.iter_total;
            INS_InsertCall(ins, ipoint, (AFUNPTR)RandomByte,
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
                        IARG_PARTIAL_CONTEXT, &regsetIn, &regsetOut,
                        IARG_END);
            break;
        case RANDOM_BYTE0:
            patch_point.iter2mut = u32_dist(gen) % patch_point.iter_total;
            INS_InsertCall(ins, ipoint, (AFUNPTR)RandomByte0,
                        IARG_INST_PTR,// application IP
                        IARG_UINT32, reg2mut,
                        IARG_UINT32, reg_size,
                        IARG_PARTIAL_CONTEXT, &regsetIn, &regsetOut,
                        IARG_END);
            break;
        case HAVOC:
            INS_InsertCall(ins, ipoint, (AFUNPTR)Havoc,
                        IARG_INST_PTR,// application IP
                        IARG_UINT32, reg2mut,
                        IARG_UINT32, reg_size,
                        IARG_PARTIAL_CONTEXT, &regsetIn, &regsetOut,
                        IARG_END);
            break;
        default:
            printf("error: invalid mutation type\n");
            return;
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
    free(reg_val);
    free(flags_val);
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
    if (KnobNewAddr.Value() == "" || KnobNewMut.Value() == "" || KnobNewIterNum.Value() == "") return false;

    lib_blacklist.insert("ld-linux-x86-64.so.2");
    lib_blacklist.insert("[vdso]");
    lib_blacklist.insert("libc.so.6");

    patch_point.addr = Uint64FromString(KnobNewAddr.Value());
    patch_point.mut_type = std::stoi(KnobNewMut.Value());
    patch_point.iter_total = std::stoul(KnobNewIterNum.Value());
    patch_point.iter2mut = std::stoul(KnobNewIter2Mut.Value());
    patch_point.mut_offset = std::stoul(KnobNewOffset.Value());

    branch_addr = Uint64FromString(KnobNewBranchAddr.Value());
    u8_adder = std::stoul(KnobNewU8Adder.Value());

    printf("pp: %p, %ld, %ld, %ld, %p\n", (void *)patch_point.addr, patch_point.mut_type, patch_point.iter_total, patch_point.mut_offset, (void *)branch_addr);

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