#include "pin.H"
#include <iostream>
#include <fstream>

#include <execinfo.h>
#include <vector>
#include <stack>
#include <string>
#include <sstream>

#define DEBUG_LOG (false)

/* ================================================================== */
//                             Classes
/* ================================================================== */

class BasicSample
{
public:
    virtual void printJson(std::string indent) = 0;
protected:
    static bool firstSamplePrinted;
    void printJsonDivider();
};
bool BasicSample::firstSamplePrinted = true;

class SyscallSample: public BasicSample
{
public:
    ADDRINT id;
    std::vector<std::string> trace;
    void printJson(std::string indent);
};

class FunctionActionSample: public BasicSample
{
public:
    FunctionActionSample(const std::string &funcName, const std::string &type): funcName(funcName), type(type) {}
    std::string funcName;
    std::string type;
    void printJson(std::string indent);
};

/* ================================================================== */
//                         Global variables
/* ================================================================== */

std::ostream* out = &std::cerr;
std::vector<std::string> funcNames;
std::vector<std::string> funcTrace;

std::vector<std::string> targetRtnNames;
std::vector<BasicSample*> samples;

int printedDepth = 0;
THREADID myThreadId = INVALID_THREADID;

const char* syscallNames[335] = {"read","write","open","close","stat","fstat","lstat","poll","lseek","mmap","mprotect","munmap","brk","rt_sigaction","rt_sigprocmask","rt_sigreturn","ioctl","pread64","pwrite64","readv","writev","access","pipe","select","sched_yield","mremap","msync","mincore","madvise","shmget","shmat","shmctl","dup","dup2","pause","nanosleep","getitimer","alarm","setitimer","getpid","sendfile","socket","connect","accept","sendto","recvfrom","sendmsg","recvmsg","shutdown","bind","listen","getsockname","getpeername","socketpair","setsockopt","getsockopt","clone","fork","vfork","execve","exit","wait4","kill","uname","semget","semop","semctl","shmdt","msgget","msgsnd","msgrcv","msgctl","fcntl","flock","fsync","fdatasync","truncate","ftruncate","getdents","getcwd","chdir","fchdir","rename","mkdir","rmdir","creat","link","unlink","symlink","readlink","chmod","fchmod","chown","fchown","lchown","umask","gettimeofday","getrlimit","getrusage","sysinfo","times","ptrace","getuid","syslog","getgid","setuid","setgid","geteuid","getegid","setpgid","getppid","getpgrp","setsid","setreuid","setregid","getgroups","setgroups","setresuid","getresuid","setresgid","getresgid","getpgid","setfsuid","setfsgid","getsid","capget","capset","rt_sigpending","rt_sigtimedwait","rt_sigqueueinfo","rt_sigsuspend","sigaltstack","utime","mknod","uselib","personality","ustat","statfs","fstatfs","sysfs","getpriority","setpriority","sched_setparam","sched_getparam","sched_setscheduler","sched_getscheduler","sched_get_priority_max","sched_get_priority_min","sched_rr_get_interval","mlock","munlock","mlockall","munlockall","vhangup","modify_ldt","pivot_root","_sysctl","prctl","arch_prctl","adjtimex","setrlimit","chroot","sync","acct","settimeofday","mount","umount2","swapon","swapoff","reboot","sethostname","setdomainname","iopl","ioperm","create_module","init_module","delete_module","get_kernel_syms","query_module","quotactl","nfsservctl","getpmsg","putpmsg","afs_syscall","tuxcall","security","gettid","readahead","setxattr","lsetxattr","fsetxattr","getxattr","lgetxattr","fgetxattr","listxattr","llistxattr","flistxattr","removexattr","lremovexattr","fremovexattr","tkill","time","futex","sched_setaffinity","sched_getaffinity","set_thread_area","io_setup","io_destroy","io_getevents","io_submit","io_cancel","get_thread_area","lookup_dcookie","epoll_create","epoll_ctl_old","epoll_wait_old","remap_file_pages","getdents64","set_tid_address","restart_syscall","semtimedop","fadvise64","timer_create","timer_settime","timer_gettime","timer_getoverrun","timer_delete","clock_settime","clock_gettime","clock_getres","clock_nanosleep","exit_group","epoll_wait","epoll_ctl","tgkill","utimes","vserver","mbind","set_mempolicy","get_mempolicy","mq_open","mq_unlink","mq_timedsend","mq_timedreceive","mq_notify","mq_getsetattr","kexec_load","waitid","add_key","request_key","keyctl","ioprio_set","ioprio_get","inotify_init","inotify_add_watch","inotify_rm_watch","migrate_pages","openat","mkdirat","mknodat","fchownat","futimesat","newfstatat","unlinkat","renameat","linkat","symlinkat","readlinkat","fchmodat","faccessat","pselect6","ppoll","unshare","set_robust_list","get_robust_list","splice","tee","sync_file_range","vmsplice","move_pages","utimensat","epoll_pwait","signalfd","timerfd_create","eventfd","fallocate","timerfd_settime","timerfd_gettime","accept4","signalfd4","eventfd2","epoll_create1","dup3","pipe2","inotify_init1","preadv","pwritev","rt_tgsigqueueinfo","perf_event_open","recvmmsg","fanotify_init","fanotify_mark","prlimit64","name_to_handle_at","open_by_handle_at","clock_adjtime","syncfs","sendmmsg","setns","getcpu","process_vm_readv","process_vm_writev","kcmp","finit_module","sched_setattr","sched_getattr","renameat2","seccomp","getrandom","memfd_create","kexec_file_load","bpf","execveat","userfaultfd","membarrier","mlock2","copy_file_range","preadv2","pwritev2","pkey_mprotect","pkey_alloc","pkey_free","statx","io_pgetevents","rseq"};

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

std::string getSyscallName(int syscallId)
{
    if (syscallId < 335)
    {
        return std::string(syscallNames[syscallId]);
    }
    std::ostringstream ss;
    ss << "unknown(" << syscallId << ")";
    return ss.str();
}

/* ===================================================================== */
//                             Class Impls
/* ===================================================================== */

void BasicSample::printJsonDivider()
{
    if (firstSamplePrinted)
    {
        firstSamplePrinted = false;
    }
    else
    {
        *out << "," << std::endl;
    }
}

void SyscallSample::printJson(std::string indent)
{
    printJsonDivider();
    *out << indent << "{" << std::endl;

    *out << indent << "\t\"type\": \"syscall\"," << std::endl;
    *out << indent << "\t\"syscallId\": " << this->id << "," << std::endl;
    *out << indent << "\t\"syscallName\": \"" << getSyscallName(this->id) << "\"," << std::endl;
    *out << indent << "\t\"trace\": [" << std::endl;
    for (int j = 0; j < (int)this->trace.size(); j++)
    {
        *out << indent << "\t\t\"" << this->trace[j] << "\"";
        if (j < (int)this->trace.size() - 1)
        {
            *out << ",";
        }
        *out << std::endl;
    }
    *out << indent << "\t]" << std::endl;
    *out << indent << "}";
}

void FunctionActionSample::printJson(std::string indent)
{
    printJsonDivider();
    *out << "\t{" << std::endl;
    *out << "\t\t\"type\": \"" << this->type << "\"," << std::endl;
    *out << "\t\t\"func_name\": \"" << this->funcName << "\"" << std::endl;
    *out << "\t}";
}

/* ===================================================================== */
//                               Callbacks
/* ===================================================================== */

void dumpSamples()
{
    *out << "[" << std::endl;
    for (BasicSample* sample : samples)
    {
        sample->printJson("\t");
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
    if (DEBUG_LOG) std::cerr << std::string(funcTrace.size() * 2, ' ') << "syscall: " << getSyscallName(sample->id) << std::endl;

    if (KnobRecordSyscallTrace.Value())
    {
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
    }

    samples.push_back(sample);
}

void beforeFunctionCall(THREADID threadId, UINT32 funcNameIdx)
{
    if (threadId != myThreadId) return;

    if (DEBUG_LOG) std::cerr << std::string(funcTrace.size() * 2, ' ') << "function start: " << funcNames[funcNameIdx] << std::endl;
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
        funcTrace.pop_back();
    }
    if (DEBUG_LOG) std::cerr << std::string(funcTrace.size() * 2, ' ') << "function end: " << funcNames[funcNameIdx] << std::endl;

    samples.push_back(new FunctionActionSample(funcNames[funcNameIdx], "func_end"));
}

void onImageLoaded(IMG img, VOID* v)
{
    if (DEBUG_LOG) std::cerr << "IMG " << IMG_Name(img) << std::endl;

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
