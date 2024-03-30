#include "pin.H"
#include <iostream>
#include <stdlib.h>
#include <stdio.h>
#include <time.h>

using std::cerr;
using std::cout;
using std::dec;
using std::endl;
using std::flush;
using std::hex;

#define MAXMUTVALUE 1500 
#define MAX_INSNUM 50

static uint64_t read_count = 0;
static uint64_t write_count = 0;
static uint64_t total_count = 0;
static int injected = 0;
static uint64_t inst2mut;
//static uint64_t inst_count = 14000;
static uint64_t inst_count_max = 13680;
static uint64_t inst_count_min = 13000;

enum VALID_INS_TYPE{
    INS_TYPE_MEM_READ,
    INS_TYPE_MEM_WRITE,
    INS_TYPE_LOAD_ARGS
};

std::map<ADDRINT, std::string> instmap;
VOID MutateReg(ADDRINT Ip, REG reg, CONTEXT *ctx){
    srand(time(0));
    UINT32 injectValue = rand() % MAXMUTVALUE;
    if (reg == REG_ESI) injectValue = 4096;
    if (reg == REG_EDX) injectValue = 4;
    printf("instruction@0x%lx, inject value of register %s with %d\n", Ip, REG_StringShort(reg).c_str(), injectValue);
    PIN_SetContextRegval(ctx, reg, (UINT8 *)&injectValue);
    if (reg == REG_ESI){
        PIN_RemoveInstrumentation();
        PIN_Detach();
    }
    

}

VOID MutateRegRef(ADDRINT Ip, REG reg, UINT8 *reg_val){
    srand(time(0));
    UINT32 injectValue = rand() % MAXMUTVALUE;
    printf("instruction@0x%lx, inject value of register %s with %d\n", Ip, REG_StringShort(reg).c_str(), injectValue);
    memcpy(reg_val, &injectValue, sizeof(UINT32));
    PIN_RemoveInstrumentation();
    //PIN_Detach();

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

VOID InstrumentIns(INS ins, UINT64 insCount)
//VOID InstrumentIns(INS ins, VOID *v)
{   
    if (injected == 1) return;
    if (instmap.count(INS_Address(ins))) return; //FIXME ? Why there could be multiple instrument?

    xed_iclass_enum_t ins_opcode = (xed_iclass_enum_t)INS_Opcode(ins);

    //if (ins_opcode == XED_ICLASS_MOV && INS_OperandIsReg(ins, 0) && INS_OperandIsReg(ins, 1)){
    if (ins_opcode == XED_ICLASS_MOV && INS_OperandIsReg(ins, 0) && INS_OperandIsReg(ins, 1) && insCount < MAX_INSNUM){
        if (isValidIns(ins, INS_TYPE_LOAD_ARGS)){
            REG reg2mut = REG_INVALID();
            reg2mut = INS_OperandReg(ins, 1);
            if (!IsValidReg(reg2mut)) return;
            
            instmap[INS_Address(ins)] = INS_Disassemble(ins); 
            read_count++;
            total_count++;
            //printf("data read instruction@%p, %s, %s\n", (void *)INS_Address(ins), INS_Disassemble(ins).c_str(), REG_StringShort(reg2mut).c_str());
            printf("arg load instruction@%p, %s\n", (void *)INS_Address(ins), INS_Disassemble(ins).c_str());

            // test
            if (((INS_Address(ins) - 0x4e77) & 0x000000000000ffff) == 0){
                printf("find bits!\n");
                //injected = 1;
            }
            else if (((INS_Address(ins) - 0x4e7a) & 0x000000000000ffff) == 0){
                printf("find primes!!\n");
                injected = 1;
            }
            else{
                return;
            }
            
            // random select inst
            // if (total_count != inst2mut){
            //     return;
            // }else{
            //     injected = 1;
            // }
            
            // use REGSET
            REGSET regsetIn, regsetOut;
            REGSET_Insert(regsetIn, reg2mut);
            REGSET_Insert(regsetIn, REG_FullRegName(reg2mut));
            REGSET_Insert(regsetOut, reg2mut);
            REGSET_Insert(regsetOut, REG_FullRegName(reg2mut));

            INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR) MutateReg,
                            IARG_INST_PTR,// application IP
                            IARG_UINT32, reg2mut,
                            IARG_PARTIAL_CONTEXT, &regsetIn, &regsetOut,
                            IARG_END);
        }
    }
    
    // TODO: use IPOINT to remove similar code
    if (INS_IsMemoryRead(ins) && !INS_IsRet(ins)){
        switch(ins_opcode){
            case XED_ICLASS_MOV:
                break;
            default:
                return;
        }
        
        if (!INS_OperandIsReg(ins, 0)) return;

        REG reg2mut = REG_INVALID();
        reg2mut = INS_OperandReg(ins, 0);
        if (!IsValidReg(reg2mut)) return;
        
        instmap[INS_Address(ins)] = INS_Disassemble(ins); 
        read_count++;
        total_count++;
        //printf("data read instruction@%p, %s, %s\n", (void *)INS_Address(ins), INS_Disassemble(ins).c_str(), REG_StringShort(reg2mut).c_str());
        printf("data read instruction@%p, %s\n", (void *)INS_Address(ins), INS_Disassemble(ins).c_str());

        // random select inst
        // if (total_count != inst2mut){
        //     return;
        // }else{
        //     injected = 1;
        // }
        
        // test
        if (((INS_Address(ins) - 0x30b4) & 0x000000000000ffff) == 0){
            printf("find bits!\n");
            //injected = 1;
        }
        else if (((INS_Address(ins) - 0x30b7) & 0x000000000000ffff) == 0){
            printf("find primes!!\n");
            injected = 1;
        }
        else{
            return;
        }

        // use REGSET
        REGSET regsetIn, regsetOut;
        REGSET_Insert(regsetIn, reg2mut);
        REGSET_Insert(regsetIn, REG_FullRegName(reg2mut));
        REGSET_Insert(regsetOut, reg2mut);
        REGSET_Insert(regsetOut, REG_FullRegName(reg2mut));

        INS_InsertCall(ins, IPOINT_AFTER, (AFUNPTR) MutateReg,
                        IARG_INST_PTR,// application IP
                        IARG_UINT32, reg2mut,
                        IARG_PARTIAL_CONTEXT, &regsetIn, &regsetOut,
                        IARG_END);

        // use IARG_REG_REFERENCE
        // INS_InsertCall(ins, IPOINT_AFTER, (AFUNPTR) MutateRegRef,
        //                 IARG_INST_PTR,// application IP
        //                 IARG_UINT32, reg2mut,
        //                 IARG_REG_REFERENCE, reg2mut,
        //                 IARG_END);

    }

    if (INS_IsMemoryWrite(ins)){
        switch(ins_opcode){
            case XED_ICLASS_MOV:
                break;
            default:
                return;
        }

        if (!INS_OperandIsReg(ins, 1)) return;

        REG reg2mut = REG_INVALID();
        reg2mut = INS_OperandReg(ins, 1);
        if (!IsValidReg(reg2mut)) return;

        instmap[INS_Address(ins)] = INS_Disassemble(ins); 
        write_count++;
        total_count++;
        //printf("data write instruction@%p, %s, %s\n", (void *)INS_Address(ins), INS_Disassemble(ins).c_str(), REG_StringShort(reg2mut).c_str());
        printf("data write instruction@%p, %s\n", (void *)INS_Address(ins), INS_Disassemble(ins).c_str());

        // random select inst
        // if (total_count != inst2mut){
        //     return;
        // }else{
        //     injected = 1;
        // }

        // test
        if (((INS_Address(ins) - 0x30b4) & 0x000000000000ffff) == 0){
            printf("find bits!\n");
            //injected = 1;
        }
        else if (((INS_Address(ins) - 0x30b7) & 0x000000000000ffff) == 0){
            printf("find primes!!\n");
            injected = 1;
        }
        else{
            return;
        }

        // use regset
        REGSET regsetIn, regsetOut;
        REGSET_Insert(regsetIn, reg2mut);
        REGSET_Insert(regsetIn, REG_FullRegName(reg2mut));
        REGSET_Insert(regsetOut, reg2mut);
        REGSET_Insert(regsetOut, REG_FullRegName(reg2mut));
        INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR) MutateReg,
                        IARG_INST_PTR,// application IP
                        IARG_UINT32, reg2mut,
                        IARG_PARTIAL_CONTEXT, &regsetIn, &regsetOut,
                        IARG_END);

        // use IARG_REG_REFERENCE
        // INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR) MutateRegRef,
        //                 IARG_INST_PTR,// application IP
        //                 IARG_UINT32, reg2mut,
        //                 IARG_REG_REFERENCE, reg2mut,
        //                 IARG_END);

    }
    
}

// VOID InstrumentRtn(RTN rtn, VOID *v){
//     UINT64 insCount = 0;
//     RTN_Open(rtn);
//     //printf("Instrumenting routine: %s\n", RTN_Name(rtn).c_str());
//     for (INS ins = RTN_InsHead(rtn); INS_Valid(ins); ins = INS_Next(ins))
//     {   
//         insCount++;
//         InstrumentIns(ins, insCount);
//     }
 
//     RTN_Close(rtn);
// }

VOID InstrumentTrace(TRACE trace, VOID *v){
    UINT64 insCount = 0;
    for (BBL bbl = TRACE_BblHead(trace); BBL_Valid(bbl); bbl = BBL_Next(bbl)) {
        for(INS ins = BBL_InsHead(bbl); INS_Valid(ins); ins = INS_Next(ins)){
            insCount++;
            InstrumentIns(ins, insCount);
        }

    }
}

void Detatched(VOID *v){std::cerr << endl << "Detached at total count = " << total_count << endl;}

void Fini(INT32 code, void *v){
	printf("read counts: %ld\n", read_count);
    printf("write counts: %ld\n", write_count);
	printf("read number of insts: %ld\n", instmap.size());
}

void getRandomInst(){
    srand(time(0));
    //inst2mut = rand() % inst_count;
    inst2mut = rand() % (inst_count_max - inst_count_min) + inst_count_min;
    printf("instruction to inject is %ld\n", inst2mut);
}

INT32 Usage()
{
    // cerr << "This Pintool counts the number of times a routine is executed" << endl;
    // cerr << "and the number of instructions executed in a routine" << endl;
    // cerr << endl << KNOB_BASE::StringKnobSummary() << endl;
    return -1;
}

int main(INT32 argc, CHAR* argv[])
{   
    getRandomInst();
    PIN_InitSymbols();

    if (PIN_Init(argc, argv)) return Usage();
    //PIN_SetSyntaxATT();
    //INS_AddInstrumentFunction(InstrumentIns, 0);
    //RTN_AddInstrumentFunction(InstrumentRtn, 0);
    TRACE_AddInstrumentFunction(InstrumentTrace, 0);
    PIN_AddFiniFunction(Fini, 0);
    PIN_AddDetachFunction(Detatched, 0);
    PIN_StartProgram();
    return 0;
}