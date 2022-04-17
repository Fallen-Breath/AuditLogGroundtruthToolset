#include "pin.H"
#include <iostream>
#include <fstream>

#include <vector>
#include <set>
#include <string>
#include <sstream>
#include <cmath>
#include "common.h"

#define DEBUG_LOG (true)
#define CALLTREE_LOG (false)

/* ================================================================== */
//                         Global variables
/* ================================================================== */

std::ostream* out = &std::cerr;
std::vector<std::string> funcNames;
std::vector<std::string> funcStack;

std::set<std::string> rtnToBeInjected;
std::vector<std::string> targetRtnNames;
std::vector<BasicSample*> samples;

int printedDepth = 0;
THREADID myThreadId = INVALID_THREADID;

/* ===================================================================== */
//                          Command line switches
/* ===================================================================== */

KNOB<std::string> KnobOutputFile(KNOB_MODE_WRITEONCE, "pintool", "o", "tracer.json", "Specify file name for MyPinTool output");
KNOB<std::string> KnobTargetRtnNamesFile(KNOB_MODE_WRITEONCE, "pintool", "i", "", "Specify name of text file storing target routines to record start-end");
KNOB<BOOL> KnobDoReport(KNOB_MODE_WRITEONCE, "pintool", "r", "", "export a read-able result to console");

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

void onAppStart(VOID* v)
{
}

void onAppExit(INT32 code, VOID* v)
{
    if (DEBUG_LOG)
    {
        for (const std::string &name : rtnToBeInjected)
        {
            LOG("warn: failed to located routine " + name + " in all image\n");
        }
    }
    dumpSamples(out, samples);
    if (KnobDoReport.Value())
    {
        int indent = 0;
        for (BasicSample* sample : samples)
        {
            int delta = 0;
            std::string msg;
            if (sample->getType() == "syscall")
            {
                msg = "syscall: " + getSyscallName(((SyscallSample*)sample)->id);
            }
            else if (sample->getType() == "func_start")
            {
                msg = "func_start: " + ((FunctionActionSample*)sample)->funcName;
                delta += 1;
            }
            else if (sample->getType() == "func_end")
            {
                msg = "func_end: " + ((FunctionActionSample*)sample)->funcName;
                indent = std::max(0, indent - 1);
            }
            std::cerr << std::string(indent * 4, ' ') << msg << std::endl;
            indent += delta;
        }
    }
}

void onThreadStart(THREADID threadId, CONTEXT* ctxt, INT32 flags, VOID* v)
{
//    if (DEBUG_LOG) std::cerr << "Thread #" << threadId << " started" << std::endl;
    if (myThreadId == INVALID_THREADID)
    {
        myThreadId = threadId;
    }
}

void onSyscall(THREADID threadId, CONTEXT *ctxt, SYSCALL_STANDARD std, VOID *v)
{
    if (threadId != myThreadId) return;

    for (int i = printedDepth; i < (int)funcStack.size(); i++)
    {
        samples.push_back(new FunctionActionSample(funcStack[i], "func_start"));
    }
    printedDepth = funcStack.size();

    SyscallSample *sample = new SyscallSample();
    sample->id = PIN_GetSyscallNumber(ctxt, std);
    sample->showTrace = false;
    if (CALLTREE_LOG) LOG(std::string(funcStack.size() * 2, ' ') + "syscall: " + getSyscallName(sample->id) + "\n");

    samples.push_back(sample);
}

void beforeFunctionCall(THREADID threadId, UINT32 funcNameIdx)
{
    if (threadId != myThreadId) return;

    std::string funcName = funcNames[funcNameIdx];

    if (CALLTREE_LOG) LOG(std::string(funcStack.size() * 2, ' ') + "function start: " + funcName + "\n");

    funcStack.push_back(funcName);
}

void afterFunctionCall(THREADID threadId, UINT32 funcNameIdx)
{
    if (threadId != myThreadId) return;

    std::string funcName = funcNames[funcNameIdx];

    if (funcStack.empty())
    {
        LOG("warn: func trace stack is empty\n");
    }
    else
    {
        std::string topName = *funcStack.rbegin();

        if (printedDepth == (int)funcStack.size())
        {
            samples.push_back(new FunctionActionSample(funcName, "func_end"));
            printedDepth = std::max(0, printedDepth - 1);
        }

        if (topName != funcName) LOG("mismatch: " + funcName + " " + topName + "\n");
        funcStack.pop_back();
    }
    if (CALLTREE_LOG) LOG(std::string(funcStack.size() * 2, ' ') + "function end: " + funcName + "\n");
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
