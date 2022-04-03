#include "pin.H"
#include <iostream>
#include <fstream>

#include <vector>
#include <set>
#include <string>
#include <sstream>
#include "common.h"

#define DEBUG_LOG (true)
#define CALLTREE_LOG (false)

/* ================================================================== */
//                         Global variables
/* ================================================================== */

std::ostream* out = &std::cerr;
std::vector<std::string> funcNames;
std::vector<std::string> funcTrace;

std::set<std::string> rtnToBeInjected;
std::vector<std::string> targetRtnNames;
std::vector<BasicSample*> samples;

int printedDepth = 0;
THREADID myThreadId = INVALID_THREADID;

/* ===================================================================== */
//                          Command line switches
/* ===================================================================== */

KNOB<std::string> KnobOutputFile(KNOB_MODE_WRITEONCE, "pintool", "o", "", "Specify file name for MyPinTool output");
KNOB<std::string> KnobTargetRtnNamesFile(KNOB_MODE_WRITEONCE, "pintool", "t", "", "Specify name of target routines to record start-end");
KNOB<BOOL> KnobRecordSyscallTrace(KNOB_MODE_WRITEONCE, "pintool", "s", "", "Record traces at syscall sample");

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
    if (DEBUG_LOG)
    {
        for (const std::string &name : rtnToBeInjected)
        {
            std::cerr << "warn: failed to located routine " << name << " in all image" << std::endl;
        }
    }
    dumpSamples();
}

void onThreadStart(THREADID threadId, CONTEXT* ctxt, INT32 flags, VOID* v)
{
    if (DEBUG_LOG) std::cerr << "Thread #" << threadId << " started" << std::endl;
    if (myThreadId == INVALID_THREADID)
    {
        myThreadId = threadId;
    }
}

void onSyscall(THREADID threadId, CONTEXT *ctxt, SYSCALL_STANDARD std, VOID *v)
{
    if (threadId != myThreadId) return;

    SyscallSample *sample = new SyscallSample();
    sample->id = PIN_GetSyscallNumber(ctxt, std);
    if (CALLTREE_LOG) std::cerr << std::string(funcTrace.size() * 2, ' ') << "syscall: " << getSyscallName(sample->id) << std::endl;

    samples.push_back(sample);
}

void beforeFunctionCall(THREADID threadId, UINT32 funcNameIdx)
{
    if (threadId != myThreadId) return;

    if (CALLTREE_LOG) std::cerr << std::string(funcTrace.size() * 2, ' ') << "function start: " << funcNames[funcNameIdx] << std::endl;
    funcTrace.push_back(funcNames[funcNameIdx]);

    samples.push_back(new FunctionActionSample(funcNames[funcNameIdx], "func_start"));
}

void afterFunctionCall(THREADID threadId, UINT32 funcNameIdx)
{
    if (threadId != myThreadId) return;

    if (funcTrace.empty())
    {
        if (DEBUG_LOG) std::cerr << "warn: func trace stack is empty" << std::endl;
    }
    else
    {
        if (DEBUG_LOG)
        {
            std::string topName = *funcTrace.rbegin();
            if (topName != funcNames[funcNameIdx]) std::cerr << "mismatch: " << funcNames[funcNameIdx] << " " << topName << std::endl;
        }
        funcTrace.pop_back();
    }
    if (CALLTREE_LOG) std::cerr << std::string(funcTrace.size() * 2, ' ') << "function end: " << funcNames[funcNameIdx] << std::endl;

    samples.push_back(new FunctionActionSample(funcNames[funcNameIdx], "func_end"));
}

void onImageLoaded(IMG img, VOID* v)
{
//    if (DEBUG_LOG) std::cerr << "IMG " << IMG_Name(img) << std::endl;

    for (const std::string &name : targetRtnNames)
    {
        RTN rtn = RTN_FindByName(img, name.c_str());
        if (RTN_Valid(rtn))
        {
            std::string rtnName = PIN_UndecorateSymbolName(RTN_Name(rtn), UNDECORATION_COMPLETE);

            funcNames.push_back(std::string(rtnName));
            UINT32 idx = funcNames.size() - 1;
            RTN_Open(rtn);
            {
                RTN_InsertCall(
                    rtn, IPOINT_BEFORE, (AFUNPTR)beforeFunctionCall,
                    IARG_THREAD_ID,
                    IARG_UINT32, idx,
                    IARG_END
                );
                RTN_InsertCall(
                    rtn, IPOINT_AFTER, (AFUNPTR)afterFunctionCall,
                    IARG_THREAD_ID,
                    IARG_UINT32, idx,
                    IARG_END
                );
            }
            RTN_Close(rtn);

            rtnToBeInjected.erase(name);
        }
    }
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

    std::string rtnFileName = KnobTargetRtnNamesFile.Value();
    if (!rtnFileName.empty())
    {
        std::ifstream ifs(rtnFileName.c_str());
        std::string line;
        while (std::getline(ifs, line))
        {
            if (!line.empty())
            {
                targetRtnNames.push_back(line);
                rtnToBeInjected.insert(line);
            }
        }
        ifs.close();
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
    PIN_AddThreadStartFunction(onThreadStart, NULL);
    PIN_AddSyscallEntryFunction(onSyscall, 0);
    IMG_AddInstrumentFunction(onImageLoaded, 0);

    PIN_StartProgram();
    return 0;
}
