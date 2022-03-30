/*
 * Copyright (C) 2007-2021 Intel Corporation.
 * SPDX-License-Identifier: MIT
 */

/*! @file
 *  This is an example of the PIN tool that demonstrates some basic PIN APIs 
 *  and could serve as the starting point for developing your first PIN tool
 */

#include "pin.H"
#include <iostream>
#include <fstream>

#include <execinfo.h>
#include <vector>
#include <string>
#include <sstream>

using std::cerr;
using std::endl;
using std::string;

/* ================================================================== */
// Global variables
/* ================================================================== */

class SyscallSample
{
public:
	ADDRINT id;
	std::vector<string> trace;
	void printJson(string indent);
};
bool firstSamplePrinted = true;
std::ostream* out = &cerr;
std::vector<string> funcNames;
std::stack<string> funcTrace;

int funcCallIndent = 0;

const char* syscallNames[335] = {"read","write","open","close","stat","fstat","lstat","poll","lseek","mmap","mprotect","munmap","brk","rt_sigaction","rt_sigprocmask","rt_sigreturn","ioctl","pread64","pwrite64","readv","writev","access","pipe","select","sched_yield","mremap","msync","mincore","madvise","shmget","shmat","shmctl","dup","dup2","pause","nanosleep","getitimer","alarm","setitimer","getpid","sendfile","socket","connect","accept","sendto","recvfrom","sendmsg","recvmsg","shutdown","bind","listen","getsockname","getpeername","socketpair","setsockopt","getsockopt","clone","fork","vfork","execve","exit","wait4","kill","uname","semget","semop","semctl","shmdt","msgget","msgsnd","msgrcv","msgctl","fcntl","flock","fsync","fdatasync","truncate","ftruncate","getdents","getcwd","chdir","fchdir","rename","mkdir","rmdir","creat","link","unlink","symlink","readlink","chmod","fchmod","chown","fchown","lchown","umask","gettimeofday","getrlimit","getrusage","sysinfo","times","ptrace","getuid","syslog","getgid","setuid","setgid","geteuid","getegid","setpgid","getppid","getpgrp","setsid","setreuid","setregid","getgroups","setgroups","setresuid","getresuid","setresgid","getresgid","getpgid","setfsuid","setfsgid","getsid","capget","capset","rt_sigpending","rt_sigtimedwait","rt_sigqueueinfo","rt_sigsuspend","sigaltstack","utime","mknod","uselib","personality","ustat","statfs","fstatfs","sysfs","getpriority","setpriority","sched_setparam","sched_getparam","sched_setscheduler","sched_getscheduler","sched_get_priority_max","sched_get_priority_min","sched_rr_get_interval","mlock","munlock","mlockall","munlockall","vhangup","modify_ldt","pivot_root","_sysctl","prctl","arch_prctl","adjtimex","setrlimit","chroot","sync","acct","settimeofday","mount","umount2","swapon","swapoff","reboot","sethostname","setdomainname","iopl","ioperm","create_module","init_module","delete_module","get_kernel_syms","query_module","quotactl","nfsservctl","getpmsg","putpmsg","afs_syscall","tuxcall","security","gettid","readahead","setxattr","lsetxattr","fsetxattr","getxattr","lgetxattr","fgetxattr","listxattr","llistxattr","flistxattr","removexattr","lremovexattr","fremovexattr","tkill","time","futex","sched_setaffinity","sched_getaffinity","set_thread_area","io_setup","io_destroy","io_getevents","io_submit","io_cancel","get_thread_area","lookup_dcookie","epoll_create","epoll_ctl_old","epoll_wait_old","remap_file_pages","getdents64","set_tid_address","restart_syscall","semtimedop","fadvise64","timer_create","timer_settime","timer_gettime","timer_getoverrun","timer_delete","clock_settime","clock_gettime","clock_getres","clock_nanosleep","exit_group","epoll_wait","epoll_ctl","tgkill","utimes","vserver","mbind","set_mempolicy","get_mempolicy","mq_open","mq_unlink","mq_timedsend","mq_timedreceive","mq_notify","mq_getsetattr","kexec_load","waitid","add_key","request_key","keyctl","ioprio_set","ioprio_get","inotify_init","inotify_add_watch","inotify_rm_watch","migrate_pages","openat","mkdirat","mknodat","fchownat","futimesat","newfstatat","unlinkat","renameat","linkat","symlinkat","readlinkat","fchmodat","faccessat","pselect6","ppoll","unshare","set_robust_list","get_robust_list","splice","tee","sync_file_range","vmsplice","move_pages","utimensat","epoll_pwait","signalfd","timerfd_create","eventfd","fallocate","timerfd_settime","timerfd_gettime","accept4","signalfd4","eventfd2","epoll_create1","dup3","pipe2","inotify_init1","preadv","pwritev","rt_tgsigqueueinfo","perf_event_open","recvmmsg","fanotify_init","fanotify_mark","prlimit64","name_to_handle_at","open_by_handle_at","clock_adjtime","syncfs","sendmmsg","setns","getcpu","process_vm_readv","process_vm_writev","kcmp","finit_module","sched_setattr","sched_getattr","renameat2","seccomp","getrandom","memfd_create","kexec_file_load","bpf","execveat","userfaultfd","membarrier","mlock2","copy_file_range","preadv2","pwritev2","pkey_mprotect","pkey_alloc","pkey_free","statx","io_pgetevents","rseq"};

/* ===================================================================== */
// Command line switches
/* ===================================================================== */

KNOB<string> KnobOutputFile(KNOB_MODE_WRITEONCE, "pintool", "o", "", "specify file name for MyPinTool output");
KNOB<BOOL> KnobCount(KNOB_MODE_WRITEONCE, "pintool", "count", "1", "count instructions, basic blocks and threads in the application");

/* ===================================================================== */
// Utilities
/* ===================================================================== */

INT32 Usage()
{
	cerr << "#TODO" << endl;
	cerr << KNOB_BASE::StringKnobSummary() << endl;

	return -1;
}

string getSyscallName(int syscallId)
{
	if (syscallId < 335)
	{
		return string(syscallNames[syscallId]);
	}
	std::ostringstream ss;
	ss << syscallId;
	return string("unknown(") + ss.str() + ")";
}

void printSample(const SyscallSample &sample)
{
	string syscallName = getSyscallName(sample.id);
	*out << "== syscall " << syscallName << " (id=" << sample.id << ")" << endl;
	for (int i = 0; i < (int)sample.trace.size(); i++)
	{
		*out << "  " << sample.trace[i] << endl;
	}
}

void printJsonDivider()
{
	if (firstSamplePrinted)
	{
		firstSamplePrinted = false;
	}
	else
	{
		*out << "," << endl;
	}
}

void SyscallSample::printJson(string indent)
{
    printJsonDivider();
	*out << indent << "{" << endl;

	*out << indent << "\t\"type\": \"syscall\"," << endl;
	*out << indent << "\t\"syscallId\": " << this->id << "," << endl;
	*out << indent << "\t\"syscallName\": \"" << getSyscallName(this->id) << "\"," << endl;
	*out << indent << "\t\"trace\": [" << endl;
	for (int j = 0; j < (int)this->trace.size(); j++)
	{
		*out << indent << "\t\t\"" << this->trace[j] << "\"";
		if (j < (int)this->trace.size() - 1)
		{
			*out << ",";
		}
		*out << endl;
	}
	*out << indent << "\t]" << endl;
	*out << indent << "}";
}

/* ===================================================================== */
// Callbacks
/* ===================================================================== */

void onAppStart(VOID* v)
{
	*out << "[" << endl;
}

void onAppExit(INT32 code, VOID* v)
{
	*out << "]" << endl;
}

void onSyscall(THREADID threadIndex, CONTEXT *ctxt, SYSCALL_STANDARD std, VOID *v)
{
	SyscallSample sample;
	sample.id = PIN_GetSyscallNumber(ctxt, std);
	cerr << string(funcCallIndent * 2, ' ') << "syscall: " << getSyscallName(sample.id) << endl;

	PIN_LockClient();
	{
		void* buf[128];
		int nptrs = PIN_Backtrace(ctxt, buf, sizeof(buf) / sizeof(buf[0]));
		char** bt = backtrace_symbols(buf, nptrs);
		for (int i = nptrs - 1; i >= 0; i--)
		{
		    for (int j = std::strlen(bt[i]) - 1; j >= 0 && bt[i][j] == ' '; j--)
		    {
		        bt[i][j] = '\0';
		    }
			sample.trace.push_back(bt[i]);
		}
		free(bt);
	}
	PIN_UnlockClient();
	
	sample.printJson("\t");
}

const char* funcs_c[] = {"func1", "func2", "func3", "_Z5func3v", "func"};
// const char* funcs_c[] = {};

void beforeFunctionCall(UINT32 funcNameIdx)
{
	cerr << string(funcCallIndent * 2, ' ') << "function start: " << funcNames[funcNameIdx] << endl;
	funcCallIndent++;

    printJsonDivider();
	*out << "\t{" << endl;
	*out << "\t\t\"type\": \"func_start\"," << endl;
	*out << "\t\t\"func_name\": \"" << funcNames[funcNameIdx] << "\"" << endl;
	*out << "\t}";
}

void afterFunctionCall(UINT32 funcNameIdx)
{
	funcCallIndent--;
	if (funcCallIndent < 0) { cerr << "?" << endl; funcCallIndent = 0;}
	cerr << string(funcCallIndent * 2, ' ') << "function end: " << funcNames[funcNameIdx] << endl;

    printJsonDivider();
	*out << "\t{" << endl;
	*out << "\t\t\"type\": \"func_end\"," << endl;
	*out << "\t\t\"func_name\": \"" << funcNames[funcNameIdx] << "\"" << endl;
	*out << "\t}";
}

void onImageLoaded(IMG img, VOID* v)
{
	if (1)
	{
		for (SEC sec = IMG_SecHead(img); SEC_Valid(sec); sec = SEC_Next(sec))
		{
			for (RTN rtn = SEC_RtnHead(sec); RTN_Valid(rtn); rtn = RTN_Next(rtn))
			{
				string rtnName = PIN_UndecorateSymbolName(RTN_Name(rtn), UNDECORATION_COMPLETE);

				funcNames.push_back(string(rtnName));
				UINT32 idx = funcNames.size() - 1;
//				cerr << "pushback " << rtnName << " " << idx << endl;
				RTN_Open(rtn);
				{
					RTN_InsertCall(
						rtn, IPOINT_BEFORE, (AFUNPTR)beforeFunctionCall,
						IARG_UINT32, idx,
						IARG_END
					);
					RTN_InsertCall(
						rtn, IPOINT_AFTER, (AFUNPTR)afterFunctionCall,
						IARG_UINT32, idx,
						IARG_END
					);
				}
				RTN_Close(rtn);
			}
		}
	}
}

int main(int argc, char* argv[])
{
	PIN_InitSymbols();
	
	// Initialize PIN library. Print help message if -h(elp) is specified
	// in the command line or the command line is invalid
	if (PIN_Init(argc, argv))
	{
		return Usage();
	}

	string fileName = KnobOutputFile.Value();

	if (!fileName.empty())
	{
		out = new std::ofstream(fileName.c_str());
		// cerr << "Output file: " << fileName << endl;
	}

	PIN_AddApplicationStartFunction(onAppStart, 0);
	PIN_AddFiniFunction(onAppExit, 0);
	PIN_AddSyscallEntryFunction(onSyscall, 0);
	IMG_AddInstrumentFunction(onImageLoaded, 0);

	PIN_StartProgram();

	return 0;
}

/* ===================================================================== */
/* eof */
/* ===================================================================== */
