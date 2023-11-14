#include "pin.H"

void mallocBefore(ADDRINT size){ 
    if (size == 419){printf("OBJ_nid2sn(%ld)\n", size); }
}

void mallocAfter(ADDRINT ret){ printf("\tOBJ_nid2sn returns 0x%lx\n", ret); }
void Image(IMG img, void *v) { // jitting time routine
    RTN mallocRtn = RTN_FindByName(img, "OBJ_nid2sn");
    if (RTN_Valid(mallocRtn)) {
        RTN_Open(mallocRtn);
        RTN_InsertCall(mallocRtn, IPOINT_BEFORE, (AFUNPTR)mallocBefore,
        IARG_FUNCARG_ENTRYPOINT_VALUE, 0, IARG_END);
        RTN_InsertCall(mallocRtn, IPOINT_AFTER, (AFUNPTR)mallocAfter,
        IARG_FUNCRET_EXITPOINT_VALUE, IARG_END);
        RTN_Close(mallocRtn);
    } 
} 

int main(int argc, char **argv) {
    PIN_InitSymbols(); 
    PIN_Init(argc, argv);
    IMG_AddInstrumentFunction(Image, 0);
    PIN_StartProgram(); // never returns
    return 0;
} 
