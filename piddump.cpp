/*
one of the five subsystems for distributed fuzzing @ https://github.com/mikeguidry/dfuzz
PID Dump -
Dumps all memory inside of a process for insertion into the fuzzer..

NOTICE: A lot of this code has been grabbed from other places...
*/
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <shlwapi.h>
#include <Tlhelp32.h>
#include <dbghelp.h>
#pragma comment(lib, "dbghelp.lib")
#pragma comment(lib, "shlwapi.lib")

// ugly global variable.. i pulled this together from other code
HANDLE hProcess;


int ThreadAdd(DWORD_PTR ThreadID, HANDLE hThread, FILE *fd) {
	printf("ThreadAdd ID %X hThread %X FD %X\n", ThreadID, hThread, fd);
	// first save the current context
	CONTEXT ctx;
	GetThreadContext(hThread, &ctx);
	ctx.ContextFlags = CONTEXT_FULL;
	if (GetThreadContext(hThread, &ctx) == 0) {
		//CloseHandle(thread_handle);
		printf("coudlnt get thread context\n");
		return -1;
	}
	
	LDT_ENTRY ldtSel;
	if (!GetThreadSelectorEntry(hThread, ctx.SegFs, &ldtSel)) {
		printf("Couldnt get thread selector entry for FS for thread %d\n", ThreadID);
		exit(-1);
		return -1;
	}
	
	// this isnt FS BASE.. its TIB base!
	DWORD_PTR fs_base = (ldtSel.HighWord.Bits.BaseHi << 24 ) | ( ldtSel.HighWord.Bits.BaseMid << 16 ) | ( ldtSel.BaseLow );
	fwprintf(stdout, L"[i] FS:[0] (TIB) is @ 0x%08X\n", fs_base);

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
	fwrite((void *)&ctx, 1, sizeof(CONTEXT), fd);

	return 1;
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
int StepThread(DWORD_PTR ThreadID) {
	return 1;
}


// pause all threads in the current process loading this DLL except the current
BOOL PauseThreads(unsigned long pid, bool bResumeThread, FILE *fd) {
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
			count++;
			}
		} while (Thread32Next(hThreadSnap, &te32));
	}
	CloseHandle (hThreadSnap); 

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
						StepThread(te32.th32ThreadID);
						ThreadAdd(te32.th32ThreadID, hThread, fd);
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


int main(int argc, char *argv[]) {
	if (argc != 2) {
		printf("usage: %s pid\n", argv[0]);
		exit(-1);
	}

	int pid = atoi(argv[1]);
	if ((hProcess = OpenProcess(PROCESS_ALL_ACCESS, 0, pid)) == NULL) {
		printf("cannot open process %d\n", pid);
		exit(-1);	
	}

	char fname[1024];
	wsprintf(fname, "%d_snapshot.dat", pid);

	printf("Attached to %d [HANDLE %X]\n", pid, hProcess);

	FILE *fd = fopen(fname, "wb");
	if (fd == NULL) {
		printf("couldnt open output file [%s]\n", fname);
		exit(-1);
	}

	PauseThreads(pid, 0, fd);
	DumpModules(pid, fd);
	DumpMemory(fd);
	PauseThreads(pid, 1, fd);

	ExitProcess(0);

	return 0;
}