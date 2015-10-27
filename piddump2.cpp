/*
one of the five subsystems for distributed fuzzing @ https://github.com/mikeguidry/dfuzz
PID Dump -
Dumps all memory inside of a process for insertion into the fuzzer..

NOTICE: a bit of this code has been grabbed from other places.. although ive written a lot & rewrote some
*/
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <shlwapi.h>
#include <Tlhelp32.h>
#include <dbghelp.h>
#include "debug.h"
#pragma comment(lib, "dbghelp.lib")
#pragma comment(lib, "shlwapi.lib")

BOOL  AddDebugPrivilege();
int StepUpFrame(int PID, HANDLE hThread, DWORD_PTR TID);
void CaptureSegs(HANDLE hThread, CONTEXT *ctx);

// ugly global variable.. i pulled this together from other code
HANDLE hProcess;
int thread_count_location = 0;
DWORD_PTR G_thread_count = 0;

typedef struct _thread_info {
	struct _thread_info *next;
	DWORD_PTR ThreadID;
	DWORD_PTR StackLow;
	DWORD_PTR StackHigh;
	DWORD_PTR PEB;
	DWORD_PTR TLS;

	CONTEXT ctx;
} ThreadInfo;

ThreadInfo *thread_list = NULL;

ThreadInfo *ThreadFind(DWORD_PTR ThreadID) {
	ThreadInfo *tinfo = thread_list;

	while (tinfo != NULL) {
		if (tinfo->ThreadID == ThreadID)
			return tinfo;

		tinfo = tinfo->next;
	}

	return NULL;
}

int ThreadAdd(DWORD_PTR ThreadID, FILE *fd, DWORD_PTR EIP) {
	int ret = 0;
	// first save the current context
	HANDLE hThread = OpenThread(THREAD_ALL_ACCESS, FALSE, ThreadID);

	printf("ThreadAdd ID %X hThread %X FD %X\n", ThreadID, hThread, fd);
	
	if (hThread != NULL) {
		ThreadInfo *tinfo = (ThreadInfo *)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(ThreadInfo));

		if (tinfo != NULL) {
			CONTEXT ctx;
			ctx.ContextFlags = CONTEXT_FULL;
			if (GetThreadContext(hThread, &ctx) != 0) {
			
				LDT_ENTRY ldtSel;
				if (GetThreadSelectorEntry(hThread, ctx.SegFs, &ldtSel)) {
				
					// this isnt FS BASE.. its TIB base!
					DWORD_PTR fs_base = (ldtSel.HighWord.Bits.BaseHi << 24 ) | ( ldtSel.HighWord.Bits.BaseMid << 16 ) | ( ldtSel.BaseLow );
					fwprintf(stdout, L"[i] FS:[0] (TIB) is @ 0x%08X\n", fs_base);

					tinfo->StackHigh
					// now we need stack low and stack high...
					DWORD_PTR stacklow_addr = fs_base + 0x04;
					DWORD_PTR stackhigh_addr = fs_base + 0x08;
					DWORD_PTR peb_addr = fs_base + 0x30;
					DWORD_PTR tls_addr = fs_base + 0x2C;
					DWORD_PTR stacklow, stackhigh;
					DWORD_PTR peb, tls;

					DWORD read = 0;
					ReadProcessMemory(hProcess, (const void *)stacklow_addr, &stacklow, sizeof(DWORD_PTR), &read);
					ReadProcessMemory(hProcess, (const void *)stackhigh_addr, &stackhigh, sizeof(DWORD_PTR), &read);
					ReadProcessMemory(hProcess, (const void *)peb_addr, &peb, sizeof(DWORD_PTR), &read);
					ReadProcessMemory(hProcess, (const void *)tls_addr, &tls, sizeof(DWORD_PTR), &read);

					fwrite((void *)&ThreadID, 1, sizeof(DWORD_PTR), fd);
					fwrite((void *)&fs_base, 1, sizeof(DWORD_PTR), fd);
					fwrite((void *)&stacklow, 1, sizeof(DWORD_PTR), fd);
					fwrite((void *)&stackhigh, 1, sizeof(DWORD_PTR), fd);
					fwrite((void *)&peb, 1, sizeof(DWORD_PTR), fd);
					fwrite((void *)&tls, 1, sizeof(DWORD_PTR), fd);
					// before we write the context (with segments).. lets convert them to flat mode (without LDT/GDT)...
					// im sure ill have to implement that VERy shortly..
					//DWORD_PTR CaptureSegs(HANDLE hThread, CONTEXT *ctx)

					CaptureSegs(hThread, &ctx);
					fwrite((void *)&ctx, 1, sizeof(CONTEXT), fd);

				
					ret = 1;
				} else ret = 0;
			} else ret = 0;
		}

		CloseHandle(hThread);
	} else
		ret = -1;
	
	return ret;
}


int DumpModules(int pid, FILE *fd) {
	HANDLE hTH;
	MODULEENTRY32 me;
	DWORD_PTR count = 0;
	
	if ((hTH = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, pid)) != INVALID_HANDLE_VALUE) {
		me.dwSize = sizeof(me);
		
		int tret = 0;
		for (tret = Module32First(hTH, &me); tret; tret = Module32Next(hTH, &me)) {
			count++;
		}
		// write module count..
		fwrite((void *)&count, 1, sizeof(DWORD_PTR), fd);
		
		// write module information..
		for (tret = Module32First(hTH, &me); tret; tret = Module32Next(hTH, &me)) {
			fwrite((void *)&me, 1, sizeof(MODULEENTRY32), fd);
		}

		CloseHandle(hTH);
	} else {
		printf("couldnt enumerate modules of process!\n");
		exit(-1);
		return -1;
	}

	return 1;
}


int FindModuleBase(int pid, char *module) {
	HANDLE hTH;
	MODULEENTRY32 me;
	DWORD_PTR ret = 0;
	
	if ((hTH = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, pid)) != INVALID_HANDLE_VALUE) {
		me.dwSize = sizeof(me);
		
		int tret = 0;
		for (tret = Module32First(hTH, &me); tret; tret = Module32Next(hTH, &me)) {
			if (me.th32ProcessID == pid)
				if (StrStrI(me.szModule, module) != NULL) {
					ret = (DWORD_PTR)me.modBaseAddr;
					break;
				}
		}
		
		CloseHandle(hTH);
	}
	return ret;
}



// dump a processes memory to disk
int DumpMemory(FILE *fd) {

	MEMORYSTATUSEX MemStatEx;
	
	MemStatEx.dwLength = sizeof(MemStatEx);
	GlobalMemoryStatusEx(&MemStatEx);
	
	//if(MemStatEx.ullTotalVirtual == 0xC0000000)
	DWORD_PTR limit = MemStatEx.ullTotalVirtual;

	DWORD Total = 0;
	DWORD Accessed = 0;

	// For each page in memory
	for(int i = 0; i < limit;) {
		// Mem info
		MEMORY_BASIC_INFORMATION MemInfo;
		
		// Query the page
		SIZE_T sRet = VirtualQueryEx(hProcess,(LPCVOID)i,&MemInfo,sizeof(MemInfo));
		
		// So... are there some pages there ?
		if(sRet == 0 || MemInfo.State == MEM_FREE || MemInfo.State == MEM_RESERVE) {
            // We can skip lots of pages or only one..
            if(sRet == 0)
            {
				// Try the next page I guess
				i += 0x1000;
				Total++;
            } else {
				// Skip the whole block
				i += MemInfo.RegionSize;
				Total += MemInfo.RegionSize / 0x1000;
            }
			
            // Let's print out something
            if((Total & 0xff) == 0) {
				printf("Reading memory at %.8x... (Accessed pages / Total pages: %u / %u)\r",
					(unsigned int)i, (unsigned int)Accessed, (unsigned int)Total);
				fflush(stdout);
            }
			continue;
		}

		// Get the data!
		// TODO: Think about acquireing larger amounts of data
		//       like... 1 MB at a time sounds good
		DWORD PageCount = MemInfo.RegionSize / 0x1000;
		DWORD j;
		for(j = 0; j < PageCount; j++)
		{         
            // A static buffer
            static BYTE PageBuffer[0x1000];
            SIZE_T BytesRead = 0;
			
            // Read (and ignore the errors)
			LPVOID Addr = (LPVOID)(i + j * 0x1000);
            if(ReadProcessMemory(hProcess, (LPCVOID)(i + j * 0x1000), PageBuffer, sizeof(PageBuffer), &BytesRead) &&
				BytesRead != 0)
            {
				// Counter!
				Accessed++;
				Total++;
				
	
				// write the address, and the page...
				fwrite((void *)&Addr, 1, sizeof(DWORD_PTR), fd);
				fwrite((void *)&PageBuffer, 1, BytesRead, fd);

				// Write the page to disk
				//HandleDataWrite(WorkDescriptor, i + j * 0x1000, PageBuffer, BytesRead);
            }
			
            // Let's print out something
            if((Total & 0xff) == 0)
				printf("Reading memory at %.8x... (Accessed pages / Total pages: %u / %u)\r",
				(unsigned int)i, (unsigned int)Accessed, (unsigned int)Total);
		}
		
		// Iterate
		i += 0x1000 * PageCount;
	}
	
	// Done!
	printf("Done reading memory. Final statistics: Accessed pages / Total pages: %u / %u\n", 
		(unsigned int)Accessed, (unsigned int)Total);

	return 1;
}

// each thread has to be stepped out of any windows DLLs or other DLLs...
// so we can hook and redirect those to API proxy or a simulation..
int StepThread(HANDLE hThread) {
	// get threads EBP
	CONTEXT ctx;
	GetThreadContext(hThread, &ctx);
	ctx.ContextFlags = CONTEXT_FULL;
	if (GetThreadContext(hThread, &ctx) == 0) {
		printf("Couldnt get thread context.. %X\n", hThread);
		return -1;
	}

	int done = 0;
	while (!done) {
		DWORD_PTR frame_ret_addr = DWORD_PTR(ctx.Ebp + 4);
		DWORD_PTR ret_addr;
		
		DWORD read = 0;
		ReadProcessMemory(hProcess,(const void *) frame_ret_addr, &ret_addr, sizeof(DWORD_PTR), &read);

		char original_bytes[16];
		// grab original bytes
		ReadProcessMemory(hProcess,(const void *) ret_addr, &original_bytes, sizeof(DWORD_PTR), &read);

		char int3[] = "\xCC";
		DWORD wrote = 0;
		WriteProcessMemory(hProcess, (void *) ret_addr, &int3, 1, &wrote);

		// now lets connect a debugger and step until a breakpoint
	}

	return 1;
}


Modification *ModificationAdd(DWORD_PTR Address, char *replace, int size);

// pause all threads in the current process loading this DLL except the current
BOOL PauseThreads(unsigned long pid, bool bResumeThread, FILE *fd, DWORD_PTR EIP) {
    HANDLE        hThreadSnap = NULL; 
    BOOL          bRet        = FALSE; 
    THREADENTRY32 te32        = {0}; 
	DWORD CurrentProcID = GetCurrentProcessId();
	DWORD CurrentThreadID = GetCurrentThreadId();
	
	if (pid == 0) pid = CurrentProcID;
	
    // Take a snapshot of all threads currently in the system. 
    hThreadSnap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0); 
    if (hThreadSnap == INVALID_HANDLE_VALUE) 
        return (FALSE); 
	
    // Fill in the size of the structure before using it. 
    te32.dwSize = sizeof(THREADENTRY32); 
	DWORD_PTR count = 0;
	if (Thread32First(hThreadSnap, &te32)) { 
		
		do {
			
			if (te32.th32OwnerProcessID == pid)  {
				HANDLE hThread = OpenThread(THREAD_ALL_ACCESS, FALSE, te32.th32ThreadID);
				CONTEXT ctx;
				ctx.ContextFlags = CONTEXT_FULL;
				if (GetThreadContext(hThread, &ctx) == 0) {
					printf("Couldnt get thread context.. %X\n", hThread);
					return -1;
				}
				
				if (AddrInExecutable(pid, ctx.Eip)) {
					count++;
				}

				CloseHandle(hThread);
			}
			
		} while (Thread32Next(hThreadSnap, &te32));
	}
	CloseHandle (hThreadSnap); 

	if (!thread_count_location) {
		thread_count_location = ftell(fd);
		G_thread_count = count;
		fwrite((void *)&G_thread_count, 1, sizeof(DWORD_PTR), fd);
	}

	fwrite((void *)&count, 1, sizeof(DWORD_PTR), fd);

	hThreadSnap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0); 
	printf("Thread Count: %ld\n", count);
    // Walk the thread snapshot to find all threads of the process. 
    // If the thread belongs to the process, add its information 
    // to the display list.
    if (Thread32First(hThreadSnap, &te32)) { 
        do { 
            if (te32.th32OwnerProcessID == pid)  {
				if (te32.th32ThreadID != CurrentThreadID) {
					HANDLE hThread = OpenThread(THREAD_ALL_ACCESS, FALSE, te32.th32ThreadID);
					if (bResumeThread) {
						ResumeThread(hThread);
					} else {
						SuspendThread(hThread);
						//StepUpFrame(pid, hThread, te32.th32ThreadID);
						//printf("add\n");
						//ThreadAdd(te32.th32ThreadID, fd, EIP);
					}
					CloseHandle(hThread);
				}
            } 
        } while (Thread32Next(hThreadSnap, &te32)); 
        bRet = TRUE; 
    } 
    else 
        bRet = FALSE;          // could not walk the list of threads 
	
    // Do not forget to clean up the snapshot object. 
    CloseHandle (hThreadSnap); 
	
    return (bRet); 
} 

int DebugTillReady(DWORD_PTR);

int main(int argc, char *argv[]) {

	HMODULE mod_ws = (HMODULE)LoadLibrary("ws2_32");
	void *proc = (void *)GetProcAddress(mod_ws, "recv");
	DWORD_PTR rva = (DWORD_PTR)((DWORD_PTR)proc - (DWORD_PTR)mod_ws) + 145;
	printf("winsock %X recv %X RVA %X\n", mod_ws, proc, (DWORD_PTR)((DWORD_PTR)proc - (DWORD_PTR)mod_ws));
	AddDebugPrivilege();

	if (argc != 2) {
		printf("usage: %s pid\n", argv[0]);
		exit(-1);
	}

	int pid = atoi(argv[1]);
	if ((hProcess = OpenProcess(PROCESS_ALL_ACCESS, 0, pid)) == NULL) {
		printf("cannot open process %d\n", pid);
		exit(-1);	
	}

	DWORD_PTR remote_winsock = FindModuleBase(pid, "ws2_32");
	if (!remote_winsock) {
		printf("error? load a web site first\n");
	}
	printf("putting a bp at data reading\n");
	char int3[] = "\xCC";
	DWORD_PTR hook = (DWORD_PTR)(remote_winsock + rva);
	ModificationAdd((DWORD_PTR)(remote_winsock + rva), (char *)&int3, 1);
	DWORD wrote = 0;
	WriteProcessMemory(hProcess, (LPVOID)(remote_winsock + rva), (LPVOID) &int3, 1, &wrote);


	// attach to process once for this.. (so it doesnt keep recreating the DbgBreak thread
	DebugActiveProcess(pid);

	char fname[1024];
	wsprintf(fname, "%d_snapshot.dat", pid);

	printf("Attached to %d [HANDLE %X]\n", pid, hProcess);

	FILE *fd = fopen(fname, "wb");
	if (fd == NULL) {
		printf("couldnt open output file [%s]\n", fname);
		exit(-1);
	}

	// debug till we reach our breakpoint.. and dump that threads information..
	if (DebugTillReady(pid, hProcess, 0, fd)) {

		printf("Pausing all other processes\n");
		// now lets dump all other threads in case multi-threading is a necessity to trigger the bug
		PauseThreads(pid, 0, fd, hook);

		printf("Dump module information to snapshot\n");
		DumpModules(pid, fd);

		printf("Dump memory to snapshot\n");
		DumpMemory(fd);

		printf("Resume original process..\n");
		PauseThreads(pid, 1, fd, hook);
	}

	DebugActiveProcessStop(pid);

	ExitProcess(0);

	return 0;
}