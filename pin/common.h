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
protected:
    static bool firstSamplePrinted;
    void printJsonDivider(std::ostream* out);
};

class SyscallSample: public BasicSample
{
public:
    ADDRINT id;
    std::vector<std::string> trace;
    void printJson(std::ostream* out, std::string indent);
};

class FunctionActionSample: public BasicSample
{
public:
    FunctionActionSample(const std::string &funcName, const std::string &type): funcName(funcName), type(type) {}
    std::string funcName;
    std::string type;
    void printJson(std::ostream* out, std::string indent);
};

/* ================================================================== */
//                              Utils
/* ================================================================== */

std::string getSyscallName(int syscallId);

#endif
