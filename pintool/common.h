#ifndef COMMON_H
#define COMMON_H

#include <string>
#include <sstream>
#include <vector>


/* ================================================================== */
//                             Classes
/* ================================================================== */

class BasicSample
{
public:
    virtual void printJson(std::ostream* out, std::string indent) = 0;
    virtual const std::string& getType();
};

class SyscallSample: public BasicSample
{
public:
    SyscallSample();
    const std::string& getType();
    ADDRINT id;
    bool showTrace;
    std::vector<std::string> trace;
    void printJson(std::ostream* out, std::string indent);
};

class FunctionActionSample: public BasicSample
{
public:
    FunctionActionSample(const std::string &funcName, const std::string &type): funcName(funcName), type(type) {}
    FunctionActionSample(const FunctionActionSample &sample);
    const std::string& getType();
    std::string funcName;
    std::string type;
    void printJson(std::ostream* out, std::string indent);
};

/* ================================================================== */
//                              Utils
/* ================================================================== */

std::string getSyscallName(int syscallId);
void dumpSamples(std::ostream* out, const std::vector<BasicSample*> &samples);

#endif
