#include "pin.H"
#include <iostream>
#include <stdlib.h>
#include <stdio.h>
#include <time.h>
#include <set>
#include <queue>
#include <execinfo.h>

using std::cerr;
using std::cout;
using std::dec;
using std::endl;
using std::flush;
using std::hex;

#define MAXMUTVALUE 1500 
#define MAX_INSNUM 50
//static int injected = 0;
enum VALID_INS_TYPE{
    INS_TYPE_MEM_READ,
    INS_TYPE_MEM_WRITE,
    INS_TYPE_LOAD_ARGS
};
typedef struct patch_point{
    unsigned int addr;
    uint64_t injectValue;
} Patchpoint;
typedef std::vector<Patchpoint> Patchpoints;
std::set<PIN_THREAD_UID> uidSet;
struct _shmq{
    size_t max_size;
    PIN_MUTEX mutex;
    std::queue<INS> bbl_buf;
}shmq;
typedef struct instrument_args{
    INS ins;
    REG reg2mut;
    REGSET regsetin;
    REGSET regsetout;
}INST_ARGS;

std::queue<INST_ARGS> ins2process;
int global_exit = 0;
PIN_MUTEX mutex;

KNOB<ADDRINT> KnobNewAddr(KNOB_MODE_WRITEONCE, "pintool", "addr", "0", "specify nid to be replaced");
KNOB<UINT64> KnobNewVal(KNOB_MODE_WRITEONCE, "pintool", "val", "512", "specify bits");

VOID MutateReg(ADDRINT Ip, REG reg, UINT64 injectValue,CONTEXT *ctx){
    //srand(time(0));
    //UINT32 injectValue = rand() % MAXMUTVALUE;
    printf("instruction@0x%lx, inject value of register %s with %ld\n", Ip, REG_StringShort(reg).c_str(), injectValue);
    PIN_SetContextRegval(ctx, reg, (UINT8 *)&injectValue);
    PIN_RemoveInstrumentation();
    PIN_Detach();
    return;

}

VOID docount() { printf("instrument success!\n"); }

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

VOID FindIns(VOID* arg)
//VOID InstrumentIns(INS ins, VOID *v)
{   
    THREADID myThreadId = PIN_ThreadId();
    printf("I'm %d\n", myThreadId);
    //fflush(stdout);
    while(true){
        if(global_exit) return;

        PIN_MutexLock(&shmq.mutex);
        if (shmq.bbl_buf.size() == 0){
            PIN_MutexUnlock(&shmq.mutex);
            continue;
        }
        INS ins = shmq.bbl_buf.front();
        shmq.bbl_buf.pop();
        //std::cout << "Thread " << id << ", Consumed: " << data << std::endl; 
        //printf("Thread :%d, get a bbl\n", myThreadId);
        //fflush(stdout);
        PIN_MutexUnlock(&shmq.mutex);

        //for(INS ins = BBL_InsHead(bbl); INS_Valid(ins); ins = INS_Next(ins)){
        xed_iclass_enum_t ins_opcode = (xed_iclass_enum_t)INS_Opcode(ins);
        if (ins_opcode != XED_ICLASS_MOV) continue;
        //printf("instruction@%p: %s\n", (void *)INS_Address(ins), INS_Disassemble(ins).c_str());

        if (((INS_Address(ins) - KnobNewAddr.Value()) & 0x000000000000ffff) != 0) continue;

        global_exit = 1;
        printf("instruction@%p, inject value of %ld\n", (void *)INS_Address(ins), KnobNewVal.Value());
        // TODO: use IPOINT to remove similar code
        if (INS_IsMemoryRead(ins) && !INS_IsRet(ins)){
            if (!INS_OperandIsReg(ins, 0)) continue;
            REG reg2mut = REG_INVALID();
            reg2mut = INS_OperandReg(ins, 0);
            if (!IsValidReg(reg2mut)) continue;
            
            //printf("data read instruction@%p, %s, %s\n", (void *)INS_Address(ins), INS_Disassemble(ins).c_str(), REG_StringShort(reg2mut).c_str());
            //printf("data read instruction@%p, %s\n", (void *)INS_Address(ins), INS_Disassemble(ins).c_str()); 
            printf("data read instruction: %s\n", INS_Disassemble(ins).c_str());

            // use REGSET
            REGSET regsetIn, regsetOut;
            REGSET_Insert(regsetIn, reg2mut);
            REGSET_Insert(regsetIn, REG_FullRegName(reg2mut));
            REGSET_Insert(regsetOut, reg2mut);
            REGSET_Insert(regsetOut, REG_FullRegName(reg2mut));

            INST_ARGS ins_args;
            ins_args.ins = ins;
            ins_args.reg2mut = reg2mut;
            ins_args.regsetin = regsetIn;
            ins_args.regsetout = regsetOut;

            PIN_MutexLock(&mutex);
            ins2process.push(ins_args);
            PIN_MutexUnlock(&mutex);

            // INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR) MutateReg,
            //                 IARG_INST_PTR,// application IP
            //                 IARG_UINT32, reg2mut,
            //                 IARG_UINT64, KnobNewVal.Value(),
            //                 IARG_PARTIAL_CONTEXT, &regsetIn, &regsetOut,
            //                 IARG_END);

        }

        if (INS_IsMemoryWrite(ins)){
            if (!INS_OperandIsReg(ins, 1)) continue;
            REG reg2mut = REG_INVALID();
            reg2mut = INS_OperandReg(ins, 1);
            if (!IsValidReg(reg2mut)) continue;

            //printf("data write instruction@%p, %s, %s\n", (void *)INS_Address(ins), INS_Disassemble(ins).c_str(), REG_StringShort(reg2mut).c_str());
            //printf("data write instruction@%p, %s\n", (void *)INS_Address(ins), INS_Disassemble(ins).c_str());
            printf("data write instruction: %s\n", INS_Disassemble(ins).c_str());

            // use regset
            REGSET regsetIn, regsetOut;
            REGSET_Insert(regsetIn, reg2mut);
            REGSET_Insert(regsetIn, REG_FullRegName(reg2mut));
            REGSET_Insert(regsetOut, reg2mut);
            REGSET_Insert(regsetOut, REG_FullRegName(reg2mut));

            INST_ARGS ins_args;
            ins_args.ins = ins;
            ins_args.reg2mut = reg2mut;
            ins_args.regsetin = regsetIn;
            ins_args.regsetout = regsetOut;

            PIN_MutexLock(&mutex);
            ins2process.push(ins_args);
            PIN_MutexUnlock(&mutex);

            // INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR) MutateReg,
            //                 IARG_INST_PTR,// application IP
            //                 IARG_UINT32, reg2mut,
            //                 IARG_UINT64, KnobNewVal.Value(),
            //                 IARG_PARTIAL_CONTEXT, &regsetIn, &regsetOut,
            //                 IARG_END);

        }

    
        //}
        
    }
    
}

VOID InstrumentIns(){
    while(!ins2process.empty()){
        INST_ARGS inst_args = ins2process.front();
        ins2process.pop();
        INS_InsertCall(inst_args.ins, IPOINT_BEFORE, (AFUNPTR) MutateReg,
                            IARG_INST_PTR,// application IP
                            IARG_UINT32, inst_args.reg2mut,
                            IARG_UINT64, KnobNewVal.Value(),
                            IARG_PARTIAL_CONTEXT, &inst_args.regsetin, &inst_args.regsetout,
                            IARG_END);
            
    }
}

// XXX: cannot use routine because the changed register value will not saved
VOID InstrumentTrace(TRACE trace, VOID *v){
    for (BBL bbl = TRACE_BblHead(trace); BBL_Valid(bbl); bbl = BBL_Next(bbl)) {
        //printf("instruction: %s\n", INS_Disassemble(ins).c_str());
        for(INS ins = BBL_InsHead(bbl); INS_Valid(ins); ins = INS_Next(ins)){
            while(1){
                if (global_exit){
                    InstrumentIns();
                    return;
                }
                PIN_MutexLock(&shmq.mutex);
                if (shmq.bbl_buf.size() > shmq.max_size){
                    PIN_MutexUnlock(&shmq.mutex);
                    continue;
                }
                shmq.bbl_buf.push(ins);
                //printf("produced a bbl \n");
                PIN_MutexUnlock(&shmq.mutex);
                break;
            }   
        }
        
    }
}

static VOID RecordToolThreadCreated(PIN_THREAD_UID threadUid)
{
    BOOL insertStatus;
    insertStatus = (uidSet.insert(threadUid)).second;
    if (!insertStatus)
    {
        fprintf(stderr, "UID is not unique");
        fflush(stderr);
        exit(-1);
    }
}

static VOID PrepareForFini(VOID* v)
{
    for (std::set< PIN_THREAD_UID >::iterator it = uidSet.begin(); it != uidSet.end(); ++it)
    {
        //printf("Waiting for exit of thread uid %ld.\n", *it);
        //fflush(stdout);
        INT32 threadExitCode;
        BOOL waitStatus = PIN_WaitForThreadTermination(*it, PIN_INFINITE_TIMEOUT, &threadExitCode);
        if (!waitStatus)
        {
            fprintf(stderr, "PIN_WaitForThreadTermination(secondary thread) failed");
            fflush(stderr);
        }
    }
}


void Detatched(VOID *v){std::cerr << endl << "Detached at addr: " << KnobNewAddr.Value() << endl;}

void Fini(INT32 code, void *v){
	// printf("read counts: %ld\n", read_count);
    // printf("write counts: %ld\n", write_count);
	// printf("read number of insts: %ld\n", instmap.size());

    PIN_MutexFini(&shmq.mutex);
    PIN_MutexFini(&mutex);
    printf("size of ins: %ld\n", ins2process.size());

    return;
}

INT32 Usage()
{
    // cerr << "This Pintool counts the number of times a routine is executed" << endl;
    // cerr << "and the number of instructions executed in a routine" << endl;
    cerr << endl << KNOB_BASE::StringKnobSummary() << endl;
    return -1;
}

int main(INT32 argc, CHAR* argv[])
{
    int num_thd = 4;
    if (PIN_Init(argc, argv)) return Usage();

    PIN_MutexInit(&shmq.mutex);
    shmq.max_size = 4096;

    //PIN_SetSyntaxATT();
    //INS_AddInstrumentFunction(InstrumentIns, 0);
    TRACE_AddInstrumentFunction(InstrumentTrace, 0);
    PIN_AddFiniFunction(Fini, 0);
    PIN_AddPrepareForFiniFunction(PrepareForFini, 0);
    PIN_AddDetachFunction(Detatched, 0);

    for (int i = 0; i < num_thd; i++)
    {
        PIN_THREAD_UID threadUid;
        THREADID threadId = PIN_SpawnInternalThread(FindIns, NULL, 0, &threadUid);
        if (threadId == INVALID_THREADID)
        {
            fprintf(stderr, "PIN_SpawnInternalThread(BufferProcessingThread) failed");
            fflush(stderr);
            exit(-1);
        }
        //printf("created internal-tool BufferProcessingThread %d, uid = %ld\n", threadId, threadUid);
        fflush(stdout);
        RecordToolThreadCreated(threadUid);
    }

    PIN_StartProgram();
    return 0;
}