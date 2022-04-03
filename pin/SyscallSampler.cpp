#include "pin.H"
#include <iostream>
#include <fstream>

#include <execinfo.h>
#include <vector>
#include <set>
#include <string>
#include <sstream>
#include "common.h"

#define DEBUG_LOG (true)


/* ================================================================== */
//                         Global variables
/* ================================================================== */

std::ostream* out = &std::cerr;
std::vector<BasicSample*> samples;

/* ===================================================================== */
//                          Command line switches
/* ===================================================================== */

KNOB<std::string> KnobOutputFile(KNOB_MODE_WRITEONCE, "pintool", "o", "sampler.json", "Specify file name for MyPinTool output");

/* ===================================================================== */
//                                Utilities
/* ===================================================================== */

INT32 Usage()
{
    std::cerr << "#TODO" << std::endl;
    std::cerr << KNOB_BASE::StringKnobSummary() << std::endl;

    return -1;
}

/* ===================================================================== */
//                               Callbacks
/* ===================================================================== */

void dumpSamples()
{
    *out << "[" << std::endl;
    for (BasicSample* sample : samples)
    {
        sample->printJson(out, "\t");
    }
    *out << std::endl << "]" << std::endl;
}

void onAppStart(VOID* v)
{
}

void onAppExit(INT32 code, VOID* v)
{
    dumpSamples();
}

void onSyscall(THREADID threadId, CONTEXT *ctxt, SYSCALL_STANDARD std, VOID *v)
{
    SyscallSample *sample = new SyscallSample();
    sample->id = PIN_GetSyscallNumber(ctxt, std);

    PIN_LockClient();
    {
        void* buf[512];
        int nptrs = PIN_Backtrace(ctxt, buf, sizeof(buf) / sizeof(buf[0]));
        char** bt = backtrace_symbols(buf, nptrs);
        for (int i = nptrs - 1; i >= 0; i--)
        {
            for (int j = std::strlen(bt[i]) - 1; j >= 0 && bt[i][j] == ' '; j--)
            {
                bt[i][j] = '\0';
            }
            sample->trace.push_back(bt[i]);
        }
        free(bt);
    }
    PIN_UnlockClient();

    samples.push_back(sample);
}

/* ===================================================================== */
//                                 Main
/* ===================================================================== */

void init()
{
    std::string outputFileName = KnobOutputFile.Value();
    if (!outputFileName.empty())
    {
        out = new std::ofstream(outputFileName.c_str());
    }
}

int main(int argc, char* argv[])
{
    PIN_InitSymbols();
    if (PIN_Init(argc, argv))
    {
        return Usage();
    }

    init();

    PIN_AddApplicationStartFunction(onAppStart, 0);
    PIN_AddFiniFunction(onAppExit, 0);
    PIN_AddSyscallEntryFunction(onSyscall, 0);

    PIN_StartProgram();
    return 0;
}
