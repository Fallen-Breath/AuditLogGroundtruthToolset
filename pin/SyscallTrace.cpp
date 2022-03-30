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

struct SyscallSample
{
	ADDRINT id;
	std::vector<string> trace;
};

std::vector<SyscallSample> samples;

std::ostream* out = &cerr;

const char* syscallNames[335] = {"read","write","open","close","stat","fstat","lstat","poll","lseek","mmap","mprotect","munmap","brk","rt_sigaction","rt_sigprocmask","rt_sigreturn","ioctl","pread64","pwrite64","readv","writev","access","pipe","select","sched_yield","mremap","msync","mincore","madvise","shmget","shmat","shmctl","dup","dup2","pause","nanosleep","getitimer","alarm","setitimer","getpid","sendfile","socket","connect","accept","sendto","recvfrom","sendmsg","recvmsg","shutdown","bind","listen","getsockname","getpeername","socketpair","setsockopt","getsockopt","clone","fork","vfork","execve","exit","wait4","kill","uname","semget","semop","semctl","shmdt","msgget","msgsnd","msgrcv","msgctl","fcntl","flock","fsync","fdatasync","truncate","ftruncate","getdents","getcwd","chdir","fchdir","rename","mkdir","rmdir","creat","link","unlink","symlink","readlink","chmod","fchmod","chown","fchown","lchown","umask","gettimeofday","getrlimit","getrusage","sysinfo","times","ptrace","getuid","syslog","getgid","setuid","setgid","geteuid","getegid","setpgid","getppid","getpgrp","setsid","setreuid","setregid","getgroups","setgroups","setresuid","getresuid","setresgid","getresgid","getpgid","setfsuid","setfsgid","getsid","capget","capset","rt_sigpending","rt_sigtimedwait","rt_sigqueueinfo","rt_sigsuspend","sigaltstack","utime","mknod","uselib","personality","ustat","statfs","fstatfs","sysfs","getpriority","setpriority","sched_setparam","sched_getparam","sched_setscheduler","sched_getscheduler","sched_get_priority_max","sched_get_priority_min","sched_rr_get_interval","mlock","munlock","mlockall","munlockall","vhangup","modify_ldt","pivot_root","_sysctl","prctl","arch_prctl","adjtimex","setrlimit","chroot","sync","acct","settimeofday","mount","umount2","swapon","swapoff","reboot","sethostname","setdomainname","iopl","ioperm","create_module","init_module","delete_module","get_kernel_syms","query_module","quotactl","nfsservctl","getpmsg","putpmsg","afs_syscall","tuxcall","security","gettid","readahead","setxattr","lsetxattr","fsetxattr","getxattr","lgetxattr","fgetxattr","listxattr","llistxattr","flistxattr","removexattr","lremovexattr","fremovexattr","tkill","time","futex","sched_setaffinity","sched_getaffinity","set_thread_area","io_setup","io_destroy","io_getevents","io_submit","io_cancel","get_thread_area","lookup_dcookie","epoll_create","epoll_ctl_old","epoll_wait_old","remap_file_pages","getdents64","set_tid_address","restart_syscall","semtimedop","fadvise64","timer_create","timer_settime","timer_gettime","timer_getoverrun","timer_delete","clock_settime","clock_gettime","clock_getres","clock_nanosleep","exit_group","epoll_wait","epoll_ctl","tgkill","utimes","vserver","mbind","set_mempolicy","get_mempolicy","mq_open","mq_unlink","mq_timedsend","mq_timedreceive","mq_notify","mq_getsetattr","kexec_load","waitid","add_key","request_key","keyctl","ioprio_set","ioprio_get","inotify_init","inotify_add_watch","inotify_rm_watch","migrate_pages","openat","mkdirat","mknodat","fchownat","futimesat","newfstatat","unlinkat","renameat","linkat","symlinkat","readlinkat","fchmodat","faccessat","pselect6","ppoll","unshare","set_robust_list","get_robust_list","splice","tee","sync_file_range","vmsplice","move_pages","utimensat","epoll_pwait","signalfd","timerfd_create","eventfd","fallocate","timerfd_settime","timerfd_gettime","accept4","signalfd4","eventfd2","epoll_create1","dup3","pipe2","inotify_init1","preadv","pwritev","rt_tgsigqueueinfo","perf_event_open","recvmmsg","fanotify_init","fanotify_mark","prlimit64","name_to_handle_at","open_by_handle_at","clock_adjtime","syncfs","sendmmsg","setns","getcpu","process_vm_readv","process_vm_writev","kcmp","finit_module","sched_setattr","sched_getattr","renameat2","seccomp","getrandom","memfd_create","kexec_file_load","bpf","execveat","userfaultfd","membarrier","mlock2","copy_file_range","preadv2","pwritev2","pkey_mprotect","pkey_alloc","pkey_free","statx","io_pgetevents","rseq"};

/* ===================================================================== */
// Command line switches
/* ===================================================================== */
KNOB< string > KnobOutputFile(KNOB_MODE_WRITEONCE, "pintool", "o", "", "specify file name for MyPinTool output");

KNOB< BOOL > KnobCount(KNOB_MODE_WRITEONCE, "pintool", "count", "1",
					   "count instructions, basic blocks and threads in the application");

/* ===================================================================== */
// Utilities
/* ===================================================================== */

/*!
 *  Print out help message.
 */
INT32 Usage()
{
	cerr << "This tool prints out the number of dynamically executed " << endl
		 << "instructions, basic blocks and threads in the application." << endl
		 << endl;

	cerr << KNOB_BASE::StringKnobSummary() << endl;

	return -1;
}

std::string getSyscallName(int syscallId)
{
	if (syscallId < 335)
	{
		return string(syscallNames[syscallId]);
	}
	std::ostringstream ss;
	ss << syscallId;
	return string("unknown(") + ss.str() + ")";
}

VOID printSample(const SyscallSample &sample)
{
	string syscallName = getSyscallName(sample.id);
	*out << "== syscall " << syscallName << " (id=" << sample.id << ")" << endl;
	for (int i = 0; i < (int)sample.trace.size(); i++)
	{
		*out << "  " << sample.trace[i] << endl;
	}
}

VOID Fini(INT32 code, VOID* v)
{
	*out << "[" << endl;
	for (int i = 0; i < (int)samples.size(); i++)
	{
		// printSample(samples[i]);
		const SyscallSample &sample = samples[i]; 
		*out << "\t{" << endl;
		
		*out << "\t\t\"syscallId\": \"" << sample.id << "\"," << endl;
		*out << "\t\t\"syscallName\": \"" << getSyscallName(sample.id) << "\"," << endl;
		*out << "\t\t\"trace\": [" << endl;
		for (int j = 0; j < (int)sample.trace.size(); j++)
		{
			*out << "\t\t\t\"" << sample.trace[j] << "\"";
			if (j < (int)samples.size() - 1)
			{
				*out << ",";
			}
			*out << endl;
		}
		*out << "\t\t]" << endl;
		
		*out << "\t}";
		if (i < (int)samples.size() - 1)
		{
			*out << ",";
		}
		*out << endl;
	}
	*out << "]" << endl;
}

VOID syscallTest(THREADID threadIndex, CONTEXT *ctxt, SYSCALL_STANDARD std, VOID *v)
{
	SyscallSample sample;
	sample.id = PIN_GetSyscallNumber(ctxt, std);

	PIN_LockClient();
	{
		void* buf[128];
		int nptrs = PIN_Backtrace(ctxt, buf, sizeof(buf) / sizeof(buf[0]));
		char** bt = backtrace_symbols(buf, nptrs);
		for (int i = nptrs - 1; i >= 0; i--)
		{
			sample.trace.push_back(bt[i]);
		}
	}
	PIN_UnlockClient();
	
	samples.push_back(sample);
}

// const char* funcs_c[] = {"func1", "func2", "func3", "_Z5func3v", "do_cmdline"};
const char* funcs_c[] = {};

VOID beforeFunctionCall(CHAR* name) {
	*out << "function start: " << name << std::endl;
}
VOID afterFunctionCall(CHAR* name, ADDRINT ret) {
	//fout << "function end: " << name << std::endl;
}

VOID Image(IMG img, VOID* v)
{
	if (0)
	{
	*out << "IMG " << IMG_Name(img) << std::endl;
	for( SEC sec= IMG_SecHead(img); SEC_Valid(sec); sec = SEC_Next(sec) )
	{	
		*out << "  SEC " << SEC_Name(sec) << std::endl;
		
		
		
		for( RTN rtn= SEC_RtnHead(sec); RTN_Valid(rtn); rtn = RTN_Next(rtn) )
		{
			*out << "	RTN " << RTN_Name(rtn) << std::endl;
			
			continue; //////////////////
			
			RTN_Open(rtn);
			{
				for( INS ins= RTN_InsHead(rtn); INS_Valid(ins); ins = INS_Next(ins) )
				{
					*out << "	  INS " << INS_Mnemonic(ins) << std::endl;
				}
			}
			RTN_Close(rtn);
		}
	}
	}
	
	int addrs[] = {0x00000122a, 0x00000002e, 0x0000010ee, 0x0000240ba};
	for (int addr : addrs)
	{
		RTN rtn = RTN_FindByAddress(addr);
		if (RTN_Valid(rtn))
		{
			*out << "FOUND addr " << addr << ": " << std::endl;
		}
	}

	for (const char* FUNC : funcs_c) 
	{
		RTN funcRtn = RTN_FindByName(img, FUNC);
		if (RTN_Valid(funcRtn))
		{
			RTN_Open(funcRtn);
			{
				RTN_InsertCall(
					funcRtn, IPOINT_BEFORE, (AFUNPTR)beforeFunctionCall, 
					IARG_ADDRINT, FUNC, 
					IARG_END
				);
				RTN_InsertCall(
					funcRtn, IPOINT_AFTER, (AFUNPTR)afterFunctionCall, 
					IARG_ADDRINT, FUNC, 
					IARG_FUNCRET_EXITPOINT_VALUE, 
					IARG_END
				);
			}
			RTN_Close(funcRtn);
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
		cerr << "Output file: " << fileName << endl;
	}
	
	PIN_AddFiniFunction(Fini, 0);
	PIN_AddSyscallEntryFunction(syscallTest, 0);
	IMG_AddInstrumentFunction(Image, 0);

	PIN_StartProgram();

	return 0;
}

/* ===================================================================== */
/* eof */
/* ===================================================================== */
