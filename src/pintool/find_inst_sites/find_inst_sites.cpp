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

#define MAX_INSNUM 50

static uint64_t total_count = 0;

enum VALID_INS_TYPE{
    INS_TYPE_MEM_READ,
    INS_TYPE_MEM_WRITE,
    INS_TYPE_LOAD_ARGS
};
std::map<ADDRINT, std::string> instmap;

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
    if (instmap.count(INS_Address(ins))) return; //FIXME ? Why there could be multiple instrument?
    xed_iclass_enum_t ins_opcode = (xed_iclass_enum_t)INS_Opcode(ins);
    if (ins_opcode != XED_ICLASS_MOV) return;

    //if (ins_opcode == XED_ICLASS_MOV && INS_OperandIsReg(ins, 0) && INS_OperandIsReg(ins, 1)){
    if (INS_OperandIsReg(ins, 0) && INS_OperandIsReg(ins, 1) && insCount < MAX_INSNUM){
        if (isValidIns(ins, INS_TYPE_LOAD_ARGS)){
            REG reg2mut = REG_INVALID();
            reg2mut = INS_OperandReg(ins, 1);
            if (!IsValidReg(reg2mut)) return;
            
            instmap[INS_Address(ins)] = INS_Disassemble(ins); 
            total_count++;
            //printf("arg load instruction@%p, %s\n", (void *)INS_Address(ins), INS_Disassemble(ins).c_str());
            //printf("arg load instruction: %s\n",  INS_Disassemble(ins).c_str());
            printf("%p,%s\n", (void *)INS_Address(ins), INS_Disassemble(ins).c_str());

        }
    }

    // TODO: use IPOINT to remove similar code
    if (INS_IsMemoryRead(ins) && !INS_IsRet(ins)){
        if (!INS_OperandIsReg(ins, 0)) return;

        REG reg2mut = REG_INVALID();
        reg2mut = INS_OperandReg(ins, 0);
        if (!IsValidReg(reg2mut)) return;
        
        instmap[INS_Address(ins)] = INS_Disassemble(ins); 
        total_count++;
        //printf("data read instruction@%p, %s\n", (void *)INS_Address(ins), INS_Disassemble(ins).c_str()); 
        //printf("data read instruction: %s\n", INS_Disassemble(ins).c_str()); 
        printf("%p,%s\n", (void *)INS_Address(ins), INS_Disassemble(ins).c_str());

    }

    if (INS_IsMemoryWrite(ins)){
        if (!INS_OperandIsReg(ins, 1)) return;

        REG reg2mut = REG_INVALID();
        reg2mut = INS_OperandReg(ins, 1);
        if (!IsValidReg(reg2mut)) return;

        instmap[INS_Address(ins)] = INS_Disassemble(ins); 
        total_count++;
        //printf("data write instruction@%p, %s\n", (void *)INS_Address(ins), INS_Disassemble(ins).c_str());
        //printf("data write instruction: %s\n",  INS_Disassemble(ins).c_str());
        printf("%p,%s\n", (void *)INS_Address(ins), INS_Disassemble(ins).c_str());
    }
    
}

// XXX: cannot use routine because the changed register value will not saved
VOID InstrumentTrace(TRACE trace, VOID *v){
    UINT64 insCount = 0;
    for (BBL bbl = TRACE_BblHead(trace); BBL_Valid(bbl); bbl = BBL_Next(bbl)) {
        for(INS ins = BBL_InsHead(bbl); INS_Valid(ins); ins = INS_Next(ins)){
            insCount++;
            InstrumentIns(ins, insCount);
        }

    }
}

void Fini(INT32 code, void *v){
	// printf("read counts: %ld\n", read_count);
    // printf("write counts: %ld\n", write_count);
	//printf("total number of patchpoints: %ld", instmap.size());
    return;
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
    if (PIN_Init(argc, argv)) return Usage();
    //PIN_SetSyntaxATT();
    //INS_AddInstrumentFunction(InstrumentIns, 0);
    TRACE_AddInstrumentFunction(InstrumentTrace, 0);
    PIN_AddFiniFunction(Fini, 0);
    PIN_StartProgram();
    return 0;
}