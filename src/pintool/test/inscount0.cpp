/*
 * Copyright (C) 2004-2021 Intel Corporation.
 * SPDX-License-Identifier: MIT
 */

#include <iostream>
#include <fstream>
#include <vector>
#include "pin.H"
using std::cerr;
using std::endl;
using std::ios;
using std::ofstream;
using std::string;

ofstream OutFile;

// The running count of instructions is kept here
// make it static to help the compiler optimize docount
static UINT64 icount = 0;
KNOB< string > addr(KNOB_MODE_WRITEONCE, "pintool", "addr", "0", "Address and count to trigger a start");
KNOB< string > injectValue(KNOB_MODE_WRITEONCE, "pintool", "value", "0", "Address and count to trigger a start");
std::vector<ADDRINT> addrs;
std::vector<UINT64> values;
// This function is called before every instruction is executed
VOID docount() { icount++; }

// Pin calls this function every time a new instruction is encountered
VOID Instruction(INS ins, VOID* v)
{
    // Insert a call to docount before every instruction, no arguments are passed
    INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)docount, IARG_END);
}

KNOB< string > KnobOutputFile(KNOB_MODE_WRITEONCE, "pintool", "o", "inscount.out", "specify output file name");

// This function is called when the application exits
VOID Fini(INT32 code, VOID* v)
{
    // Write to a file since cout and cerr maybe closed by the application
    OutFile.setf(ios::showbase);
    OutFile << "Count " << icount << endl;
    OutFile.close();
}

/* ===================================================================== */
/* Print Help Message                                                    */
/* ===================================================================== */

INT32 Usage()
{
    cerr << "This tool counts the number of dynamic instructions executed" << endl;
    cerr << endl << KNOB_BASE::StringKnobSummary() << endl;
    return -1;
}

/* ===================================================================== */
/* Main                                                                  */
/* ===================================================================== */
/*   argc, argv are the entire command line: pin -t <toolname> -- ...    */
/* ===================================================================== */

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

int main(int argc, char* argv[])
{
    // Initialize pin
    if (PIN_Init(argc, argv)) return Usage();

    OutFile.open(KnobOutputFile.Value().c_str());

    // UINT32 num_of_values = test.NumberOfValues();
    // for (UINT32 i = 0; i < num_of_values; ++i) {
    //     std::cout << test.Value(i) << std::endl;
    //     // Process the filename as needed
    // }
    std::vector<std::string> args1 = get_tokens(addr.Value(), ",");
    std::vector<std::string> args2 = get_tokens(injectValue.Value(), ",");
    std::vector<std::string>::iterator it;
    size_t i;
    for (i = 0, it = args1.begin(); it != args1.end(); it++, i++){
        addrs.push_back(Uint64FromString(*it));
        std::cout << addrs[i] << "," << *it << std::endl;
    }
    for (i = 0, it = args2.begin(); it != args2.end(); it++, i++){
        values.push_back(Uint64FromString(*it));
        std::cout << values[i] << "," << *it << std::endl;
    }



    // Register Instruction to be called to instrument instructions
    INS_AddInstrumentFunction(Instruction, 0);

    // Register Fini to be called when the application exits
    PIN_AddFiniFunction(Fini, 0);

    // Start the program, never returns
    PIN_StartProgram();

    return 0;
}
