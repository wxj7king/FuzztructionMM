#include "pin.H"
#include <iostream>
using std::cerr;
using std::cout;
using std::dec;
using std::endl;
using std::flush;
using std::hex;
 
typedef VOID* (*FP_OBJNID2SN)(int);
typedef VOID* (*FP_OBJNID2LN)(int);
typedef int (*FP_GENKRY)(void*, int, int, void*, void*);
// AES-128-CBC: 419
#define AES128_NID 419

KNOB<int> KnobNewNid(KNOB_MODE_WRITEONCE, "pintool", "nid", "419", "specify nid to be replaced");
KNOB<int> KnobNewBits(KNOB_MODE_WRITEONCE, "pintool", "bits", "512", "specify bits");
KNOB<int> KnobNewPrimes(KNOB_MODE_WRITEONCE, "pintool", "primes", "2", "specify primes");

ADDRINT func_ret_in_EVP_add_cipher;
ADDRINT func_ret_in_EVP_add_cipher2;
int _first_nid2sn = 1;
int _first_nid2ln = 1;

// This is the replacement routine.
VOID* NewOBJ_nid2sn(FP_OBJNID2SN orgFuncptr, int nid, ADDRINT returnIp)
{   

    int replaced_nid = KnobNewNid.Value();
    int new_nid = nid;
    if (_first_nid2sn){
        func_ret_in_EVP_add_cipher = returnIp;
        _first_nid2sn = 0;
    }
    // generate valid key file that the encrytion name matches the cipher
    if (nid == AES128_NID && returnIp == func_ret_in_EVP_add_cipher){
        new_nid = replaced_nid;
        printf("nid2sn: %d to %d\n", nid, new_nid);
    }

    if (nid == replaced_nid && returnIp == func_ret_in_EVP_add_cipher){
        new_nid = AES128_NID;
        printf("nid2sn: %d to %d\n", nid, new_nid);
    }
    // generate invalid key file that the encrytion name mismatches the cipher
    /*
    if (nid == AES128_NID){
        new_nid = replaced_nid;
        printf("nid2sn: %d to %d\n", nid, new_nid);
    }

    if (nid == replaced_nid){
        new_nid = AES128_NID;
        printf("nid2sn: %d to %d\n", nid, new_nid);
    }*/

    cout << "NewOBJ_nid2sn (" << hex << ADDRINT(orgFuncptr) << ", " << dec << nid << ", " << hex << returnIp << ")" << endl << flush;
    VOID* v = orgFuncptr(new_nid);
    return v;
}


VOID* NewOBJ_nid2ln(FP_OBJNID2LN orgFuncptr, int nid, ADDRINT returnIp)
{   

    int replaced_nid = KnobNewNid.Value();
    int new_nid = nid;
    if (_first_nid2ln){
        func_ret_in_EVP_add_cipher2 = returnIp;
        _first_nid2ln = 0;
    }
    // generate valid key file that the encrytion name matches the cipher
    if (nid == AES128_NID && returnIp == func_ret_in_EVP_add_cipher2){
        new_nid = replaced_nid;
        printf("nid2sn: %d to %d\n", nid, new_nid);
    }

    if (nid == replaced_nid && returnIp == func_ret_in_EVP_add_cipher2){
        new_nid = AES128_NID;
        printf("nid2sn: %d to %d\n", nid, new_nid);
    }
    // generate invalid key file that the encrytion name mismatches the cipher
    /*
    if (nid == AES128_NID){
        new_nid = replaced_nid;
        printf("nid2sn: %d to %d\n", nid, new_nid);
    }

    if (nid == replaced_nid){
        new_nid = AES128_NID;
        printf("nid2sn: %d to %d\n", nid, new_nid);
    }*/
    cout << "NewOBJ_nid2ln (" << hex << ADDRINT(orgFuncptr) << ", " << dec << nid << ", " << hex << returnIp << ")" << endl << flush;
    VOID* v = orgFuncptr(new_nid);
    return v;
}

int New_genkey(FP_GENKRY orgFuncptr, void* rsa, int bits, int primes, void* e_value, void* cb, ADDRINT returnIp)
{   
    int new_bits = KnobNewBits.Value();
    int new_primes = KnobNewPrimes.Value();
    cout << "New_genkey (" << hex << ADDRINT(orgFuncptr) << "..., " << dec << bits << ", " << dec << primes << ", " << hex << returnIp << "...)" << endl << flush;
    int v = orgFuncptr(rsa, new_bits, new_primes, e_value, cb);
    return v;
}

VOID ImageLoad(IMG img, VOID* v)
{
    RTN nid2sn_rtn = RTN_FindByName(img, "OBJ_nid2sn");
    if (RTN_Valid(nid2sn_rtn))
    {
        if (RTN_IsSafeForProbedReplacement(nid2sn_rtn))
        {
            cout << "Replacing OBJ_nid2sn in " << IMG_Name(img) << endl;
            PROTO proto_obj_nid2sn = PROTO_Allocate(PIN_PARG(void*), CALLINGSTD_DEFAULT, "OBJ_nid2sn", PIN_PARG(int), PIN_PARG_END());
            RTN_ReplaceSignatureProbed(nid2sn_rtn, 
                                       AFUNPTR(NewOBJ_nid2sn), 
                                       IARG_PROTOTYPE, proto_obj_nid2sn, 
                                       IARG_ORIG_FUNCPTR,
                                       IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
                                       IARG_RETURN_IP, 
                                       IARG_END);
 
            PROTO_Free(proto_obj_nid2sn);
        }
        else
        {
            cout << "Skip replacing OBJ_nid2sn in " << IMG_Name(img) << " since it is not safe." << endl;
        }
    }

    RTN nid2ln_rtn = RTN_FindByName(img, "OBJ_nid2ln");
    if (RTN_Valid(nid2ln_rtn))
    {
        if (RTN_IsSafeForProbedReplacement(nid2ln_rtn))
        {
            cout << "Replacing OBJ_nid2ln in " << IMG_Name(img) << endl;
            PROTO proto_obj_nid2ln = PROTO_Allocate(PIN_PARG(void*), CALLINGSTD_DEFAULT, "OBJ_nid2ln", PIN_PARG(int), PIN_PARG_END());
            RTN_ReplaceSignatureProbed(nid2ln_rtn, 
                                       AFUNPTR(NewOBJ_nid2ln), 
                                       IARG_PROTOTYPE, proto_obj_nid2ln, 
                                       IARG_ORIG_FUNCPTR,
                                       IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
                                       IARG_RETURN_IP, 
                                       IARG_END);
 
            PROTO_Free(proto_obj_nid2ln);
        }
        else
        {
            cout << "Skip replacing OBJ_nid2ln in " << IMG_Name(img) << " since it is not safe." << endl;
        }
    }

    RTN genkey_rtn = RTN_FindByName(img, "RSA_generate_multi_prime_key");
    if (RTN_Valid(genkey_rtn))
    {
        if (RTN_IsSafeForProbedReplacement(genkey_rtn))
        {
            cout << "Replacing RSA_generate_multi_prime_key in " << IMG_Name(img) << endl;
            PROTO proto_genkey = PROTO_Allocate(PIN_PARG(int), CALLINGSTD_STDCALL, "RSA_generate_multi_prime_key", PIN_PARG(void*), PIN_PARG(int), PIN_PARG(int), PIN_PARG(void*), PIN_PARG(void*), PIN_PARG_END());
            RTN_ReplaceSignatureProbed(genkey_rtn, 
                                       AFUNPTR(New_genkey), 
                                       IARG_PROTOTYPE, proto_genkey, 
                                       IARG_ORIG_FUNCPTR,
                                       IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
                                       IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
                                       IARG_FUNCARG_ENTRYPOINT_VALUE, 2,
                                       IARG_FUNCARG_ENTRYPOINT_VALUE, 3,
                                       IARG_FUNCARG_ENTRYPOINT_VALUE, 4,
                                       IARG_RETURN_IP, 
                                       IARG_END);
 
            PROTO_Free(proto_genkey);
        }
        else
        {
            cout << "Skip replacing RSA_generate_multi_prime_key in " << IMG_Name(img) << " since it is not safe." << endl;
        }
    }

}

INT32 Usage()
{
    cerr << "This tool instrument openssl genrsa with new encryption format, bits and primes" << endl;
    cerr << endl << KNOB_BASE::StringKnobSummary() << endl;
    return -1;
}
 
/* ===================================================================== */
/* Main: Initialize and start Pin in Probe mode.                         */
/* ===================================================================== */
 
int main(INT32 argc, CHAR* argv[])
{

    PIN_InitSymbols();
    PIN_Init(argc, argv);
    IMG_AddInstrumentFunction(ImageLoad, 0);
    PIN_StartProgramProbed();
    return 0;
}