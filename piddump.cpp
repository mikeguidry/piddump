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
#include "structures.h"
#include "debug.h"

#pragma comment(lib, "dbghelp.lib")
#pragma comment(lib, "shlwapi.lib")

DWORD_PTR hdr = 0xFFFFEEEE;
DWORD_PTR version = 0x01000502;
DWORD_PTR _pid = 0;

char *dll = NULL;
long snapshot_count = 0;

BOOL  AddDebugPrivilege();
int StepUpFrame(int PID, HANDLE hThread, DWORD_PTR TID);
int AddrInExecutable(DWORD_PTR pid, DWORD_PTR Address);
DWORD_PTR RemoteDerefDWORD(DWORD_PTR Address);
int DebugTillReady(DWORD_PTR);
int FindModuleBase(DWORD_PTR pid, char *module);


// ugly global variable.. i pulled this together from other code
HANDLE hProcess = NULL;


ThreadInfo *thread_list = NULL;
FuzzFunction *funcs = NULL;



int FuzzFunctionAdd(char *module, char *function) {
	HMODULE module_handle = LoadLibrary(module);
	if (module == NULL) return 0;

	DWORD_PTR addr = (DWORD_PTR)GetProcAddress(module_handle, function);
	if (addr == 0) return 0;

	FuzzFunction *fptr = (FuzzFunction *)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(FuzzFunction));
	if (fptr == NULL) return -1;
	
	fptr->module_name = StrDupA(module);
	fptr->function_name = StrDupA(function);
	fptr->handle = module_handle;
	fptr->function_addr = (DWORD_PTR)addr;
	fptr->rva = (DWORD_PTR)((DWORD_PTR)fptr->function_addr - (DWORD_PTR)fptr->handle);
	
	fptr->next = funcs;
	funcs = fptr;
	
	return 1;
}

FuzzFunction *FuzzFunctionFind(DWORD_PTR addr) {
	FuzzFunction *fptr = funcs;
	while (fptr != NULL) {
		if ((addr == fptr->function_addr) || (addr == fptr->remote_addr)) {
			return fptr;
		}
		fptr = fptr->next;
	}
	return NULL;
}

struct _fuzzy_list {
	char *module_name;
	char *function_name;
} fuzzy_list[] = {
	// list all functions which return data to the application that we would like to fuzz
	//{ "ws2_32",		"recv"},
	//{ "ws2_32",		"recvfrom"},
	{ "kernel32",	"ReadFile" },
	//{ "kernel32",	"GetMessageA" },
	//{ "kernel32",	"GetMessageW" },
	//{ "kernel32",	"DeviceIoControl" },
	{ NULL, NULL }
	
};

int FuzzySetup() {
	int i = 0;
	
	while (fuzzy_list[i].module_name != NULL) {
		FuzzFunctionAdd(fuzzy_list[i].module_name, fuzzy_list[i].function_name);
		i++;
	}
	
	return i;
}

int FuzzyBreakpointsAdd(int pid) {
	int count = 0;
	
	for (FuzzFunction *fptr = funcs; fptr != NULL; fptr = fptr->next) {
		
		DWORD_PTR remote_module_handle = FindModuleBase(pid, fptr->module_name);
		if (!remote_module_handle) {
			printf("Couldnt find the module in the remote process: %s\n", fptr->module_name);
			continue;
		}
		
		printf("Adding a breakpoint at %s [%s]\n", fptr->function_name, fptr->module_name);
		
		char int3[] = "\xCC";
		
		Modification *modptr = ModificationAdd((DWORD_PTR)(remote_module_handle + fptr->rva), (char *)&int3, 1);
		if (modptr != NULL) {
			modptr->reason = fptr;
			count++;
		}
	}
	
	return count;
}


// converts segment registers to linear segment addresses for use in the emulator/fuzzer..
void ResolveSegs(HANDLE hThread, CONTEXT *ctx) {
	LDT_ENTRY ldtSel;

	int i = 0;
	DWORD_PTR *SegsToGrab[] = { &ctx->SegGs, &ctx->SegFs, &ctx->SegEs, &ctx->SegDs, &ctx->SegCs, &ctx->SegSs, NULL };
	printf("ResolveSegs GS %X FS %X ES %X DS %X CS %X SS %x\n", &ctx->SegGs, &ctx->SegFs, ctx->SegEs, ctx->SegDs, ctx->SegCs, ctx->SegSs);
	while (SegsToGrab[i] != NULL) {
		// deref the pointer of the list of segments..
		DWORD_PTR *_Seg = (DWORD_PTR *)SegsToGrab[i];
		DWORD_PTR Seg = *_Seg;
		
		// grab the real segment linear address...
		if (GetThreadSelectorEntry(hThread, Seg, &ldtSel)) {
			DWORD_PTR Addr = (ldtSel.HighWord.Bits.BaseHi << 24 ) | ( ldtSel.HighWord.Bits.BaseMid << 16 ) | ( ldtSel.BaseLow );

			*_Seg = Addr;

			
		}
		
		i++;
	}
	
}



ThreadInfo *ThreadFind(DWORD_PTR ThreadID) {
	ThreadInfo *tinfo = thread_list;

	while (tinfo != NULL) {
		if (tinfo->ThreadID == ThreadID)
			return tinfo;

		tinfo = tinfo->next;
	}

	return NULL;
}



int ThreadAdd(DWORD_PTR ThreadID) {
	int ret = 0;

	HANDLE hThread = OpenThread(THREAD_ALL_ACCESS, FALSE, ThreadID);
	CONTEXT ctx;
	ctx.ContextFlags = CONTEXT_FULL;
	if (GetThreadContext(hThread, &ctx) == 0) {
		CloseHandle(hThread);
		return -1;
	}
	if (!AddrInExecutable(_pid, ctx.Eip)) {
			CloseHandle(hThread);
			return 0;
	}
	
	printf("ThreadAdd ID %X hThread %X\n", ThreadID);
	
	if (hThread != NULL) {
		ThreadInfo *tinfo = ThreadFind(ThreadID);
			
		if (tinfo != NULL) return 1;

		tinfo = (ThreadInfo *)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(ThreadInfo));

		if (tinfo != NULL) {
			tinfo->ThreadID = ThreadID;
			CONTEXT ctx;
			ctx.ContextFlags = CONTEXT_FULL;

			if (GetThreadContext(hThread, &ctx) != 0) {	
				LDT_ENTRY ldtSel;

				CopyMemory(&tinfo->ctx, &ctx, sizeof(CONTEXT));

				if (GetThreadSelectorEntry(hThread, ctx.SegFs, &ldtSel)) {
					// Thread information Blocks address from the SegFS selector
					tinfo->TIB = (DWORD_PTR)(ldtSel.HighWord.Bits.BaseHi << 24 ) | ( ldtSel.HighWord.Bits.BaseMid << 16 ) | ( ldtSel.BaseLow );
					// Various thread information block locations for addresses that we need..
					DWORD_PTR stacklow_addr = tinfo->TIB + 0x04;
					DWORD_PTR stackhigh_addr = tinfo->TIB + 0x08;
					DWORD_PTR peb_addr = tinfo->TIB + 0x30;
					DWORD_PTR tls_addr = tinfo->TIB + 0x2C;

					// counter for how many bytes read..
					DWORD read = 0;
					ReadProcessMemory(hProcess, (const void *)stacklow_addr, &tinfo->StackLow, sizeof(DWORD_PTR), &read);
					ReadProcessMemory(hProcess, (const void *)stackhigh_addr, &tinfo->StackHigh, sizeof(DWORD_PTR), &read);
					ReadProcessMemory(hProcess, (const void *)peb_addr, &tinfo->PEB, sizeof(DWORD_PTR), &read);
					ReadProcessMemory(hProcess, (const void *)tls_addr, &tinfo->TLS, sizeof(DWORD_PTR), &read);

					// copy the CONTEXT to another CONTEXT (this one will have the segment selectors resolved to linear addresses..
					CopyMemory(&tinfo->ctx_segments, &tinfo->ctx, sizeof(CONTEXT));
					ResolveSegs(hThread, &tinfo->ctx_segments);
				
					Modification *modptr = ModificationSearch(ctx.Eip);
					if (modptr != NULL) {
						tinfo->fuzz = 1;
						
						strcpy(tinfo->module_name, modptr->reason->module_name);
						strcpy(tinfo->function_name, modptr->reason->function_name);
						printf("found modification! %s %s\n", tinfo->module_name, tinfo->function_name);
					}

					//printf("thread id: %X\n", tinfo->ThreadID);
					ret = 1;

				} else {
					printf("error\n");
					ret = 0;
				}
			} else {
				printf("error 2\n");
				ret = 0;

			}

			printf("Added %X EIP %X\n", tinfo->ThreadID, tinfo->ctx.Eip);

			tinfo->next = thread_list;
			thread_list = tinfo;
		}

		CloseHandle(hThread);
	} else
		ret = -1;
	
	return ret;
}


char *ModuleData(int pid, DWORD_PTR *size, DWORD *module_count) {
	char *ret = NULL;
	HANDLE hTH;
	DWORD_PTR count = 0;
	if ((hTH = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, pid)) != INVALID_HANDLE_VALUE) {
		DWORD_PTR start_count = 32;
		char *ptr = (char *)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, (start_count * sizeof(MODULEENTRY32)));
		if (ptr != NULL) {
			int done = 0;
			while (!done) {
				MODULEENTRY32 *me = NULL;

				if (count >= start_count) {
					start_count += 16;
					char *newbuf = (char *)HeapReAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, ptr, (start_count * sizeof(MODULEENTRY32)));
					if (newbuf == NULL) {
						printf("fatal error allocating memory for module data (realloc) %X [%d %d]\n", ptr, start_count, start_count * sizeof(MODULEENTRY32));
						exit(-1);
					}
					ptr = newbuf;
				}

				me = (MODULEENTRY32 *)(ptr + (count * sizeof(MODULEENTRY32)));
				me->dwSize = sizeof(MODULEENTRY32);
				int tret = 0;
				if (count == 0)
					tret = Module32First(hTH, me);
				else
					tret = Module32Next(hTH, me);

				if (tret) {
					count++;
					*size = (count * sizeof(MODULEENTRY32));
					ret = ptr;
				} else {
					done = 1;
					break;
				}
			}
		}
		CloseHandle(hTH);
	}

	*module_count = count;

	return ret;
}


int FindModuleBase(DWORD_PTR pid, char *module) {
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


char *MemoryData(DWORD_PTR *size, DWORD_PTR *page_count) {
	char *ret = NULL;
	DWORD_PTR mem_size_pages = 0x10000; // start with 16 megabytes of space for pages (roughly with the 4 byte address)
	DWORD_PTR mem_sizes_total = mem_size_pages * 0x1000;

	char *_ptr = (char *)HeapAlloc(GetProcessHeap(), 0, mem_sizes_total);
	if (_ptr == NULL) {
		printf("fatal error couldnt allocate space for memory data (16megs of pages)\n");
		exit(-1);
	}

	char *ptr = (char *)_ptr;

	MEMORYSTATUSEX MemStatEx;
	
	MemStatEx.dwLength = sizeof(MemStatEx);
	GlobalMemoryStatusEx(&MemStatEx);
	
	//if(MemStatEx.ullTotalVirtual == 0xC0000000)
	DWORD_PTR limit = (DWORD_PTR)MemStatEx.ullTotalVirtual;

	DWORD Total = 0;
	DWORD Wrote = 0;
	DWORD Accessed = 0;

	// For each page in memory
	for(DWORD_PTR i = 0; i < limit;) {
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
		DWORD j = 0;
		for(; j < PageCount; j++)
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
				
				DWORD_PTR cur_size = (ptr - _ptr);
				// if the next page goes over the size.. we need a bigger buffer
				if ((DWORD_PTR)(cur_size + 0x1000) > mem_sizes_total) {
					printf("increasing memory total %d need %X\n", mem_sizes_total, cur_size + 0x1000);
					mem_size_pages += 0x1000; // allocate another 16megs..
					mem_sizes_total = 0x1000 * mem_size_pages;
					char *newbuf = (char *)HeapReAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, _ptr, mem_sizes_total);
					if (newbuf == NULL) {
						printf("fatal error allocating more space for memory! cur_size %d needed %d\n", cur_size, mem_sizes_total);
						exit(-1);
					}
					_ptr = newbuf;
					ptr = (_ptr + cur_size);
				}
	
				DWORD_PTR *DataAddr = (DWORD_PTR *)ptr;
				*DataAddr = (DWORD_PTR)Addr;
				ptr += sizeof(DWORD_PTR);
				

				CopyMemory(ptr, PageBuffer, BytesRead);
				if (BytesRead < 0x1000) {
					BytesRead = 0x1000;
				}
				ptr += BytesRead;
				
				*size = (DWORD_PTR)(ptr - _ptr);
				ret = _ptr;
				Wrote++;
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

	*page_count = Wrote;

	return ret;
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




// pause all threads in the current process loading this DLL except the current
BOOL PauseThreads(unsigned long pid, bool bResumeThread) {
    HANDLE        hThreadSnap = NULL; 
    BOOL          bRet        = FALSE; 
    THREADENTRY32 te32        = {0}; 
	DWORD CurrentProcID = GetCurrentProcessId();
	DWORD CurrentThreadID = GetCurrentThreadId();
	
	if (pid == 0) pid = CurrentProcID;
		
    // Fill in the size of the structure before using it. 
    te32.dwSize = sizeof(THREADENTRY32); 
	// Take a snapshot of all threads currently in the system. 
	hThreadSnap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, pid); 
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

// pause all threads in the current process loading this DLL except the current
BOOL IndexThreads(unsigned long pid) {
    HANDLE        hThreadSnap = NULL; 
    BOOL          bRet        = FALSE; 
    THREADENTRY32 te32        = {0}; 
	DWORD CurrentProcID = GetCurrentProcessId();
	DWORD CurrentThreadID = GetCurrentThreadId();
	
	if (pid == 0) pid = CurrentProcID;
	
    // Fill in the size of the structure before using it. 
    te32.dwSize = sizeof(THREADENTRY32); 
	// Take a snapshot of all threads currently in the system. 
	hThreadSnap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, pid); 
    // Walk the thread snapshot to find all threads of the process. 
    // If the thread belongs to the process, add its information 
    // to the display list.
    if (Thread32First(hThreadSnap, &te32)) { 
        do { 
            if (te32.th32OwnerProcessID == pid)  {
				if (te32.th32ThreadID != CurrentThreadID) {
					//HANDLE hThread = OpenThread(THREAD_ALL_ACCESS, FALSE, te32.th32ThreadID);
					
					ThreadAdd(te32.th32ThreadID);

					//CloseHandle(hThread);
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



char *ThreadData(DWORD_PTR *size, DWORD *thread_count) {
	char *ret = NULL;
	ThreadInfo *tinfo = NULL;
	DWORD_PTR count = 0;

	// get count of threads..
	for (tinfo = thread_list; tinfo != NULL; tinfo = tinfo->next) {
		count++;
	}

	*thread_count = 0;

	*size = 0;
	// allocate space for them..
	ret = (char *)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(ThreadInfo) * count);
	if (ret == NULL) {
		printf("fatal error allocating space to hold thread information\n");
		exit(-1);
	}

	// write to our data pointer as array skipping *next element
	char *ptr = (char *)ret;
	for (tinfo = thread_list; tinfo != NULL; tinfo = tinfo->next) {

		ThreadInfo *tptr = (ThreadInfo *)(ptr);
		CopyMemory(ptr, (char *)((char *)tinfo), sizeof(ThreadInfo));

		printf("id: %X %X EIP %X\n", tptr->ThreadID, tinfo->ThreadID, tptr->ctx.Eip);

		tptr->next = 0x00000000;

		ptr += sizeof(ThreadInfo);
		*size += sizeof(ThreadInfo);

		*thread_count++;
	}

	//*size = (ptr - ret);

	return ret;
}

BOOL RemoteLibraryFunction( HANDLE hProcess, LPCSTR lpModuleName, LPCSTR lpProcName, LPVOID lpParameters, SIZE_T dwParamSize, PVOID *ppReturn )
{
	HANDLE hThread ;
    LPVOID lpRemoteParams = NULL;
	DWORD dwOut = 0;
	
    LPVOID lpFunctionAddress = GetProcAddress(GetModuleHandleA(lpModuleName), lpProcName);
    if( !lpFunctionAddress ) {
		printf("Couldnt find func address\n");
		lpFunctionAddress = GetProcAddress(LoadLibraryA(lpModuleName), lpProcName);
	}
    if( !lpFunctionAddress ) {
		printf("error\n");
		goto ErrorHandler;
	}
	
    if( lpParameters )
    {
        lpRemoteParams = VirtualAllocEx( hProcess, NULL, dwParamSize, MEM_RESERVE|MEM_COMMIT, PAGE_EXECUTE_READWRITE );
        if( !lpRemoteParams ) goto ErrorHandler;
		
        SIZE_T dwBytesWritten = 0;
        BOOL result = WriteProcessMemory( hProcess, lpRemoteParams, lpParameters, dwParamSize, &dwBytesWritten);
        if( !result || dwBytesWritten < 1 ) goto ErrorHandler;
    } else {
		printf("error with lpparams\n");
	}
	
    hThread = CreateRemoteThread( hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)lpFunctionAddress, lpRemoteParams, NULL, NULL );
    if( !hThread ) {
		printf("couldnt start thread\n");
		goto ErrorHandler;
	}
	
   
    while(GetExitCodeThread(hThread, &dwOut)) {
        if(dwOut != STILL_ACTIVE) {
            *ppReturn = (PVOID)dwOut;
            break;
        }
    }
	
    return TRUE;
	
ErrorHandler:
    if( lpRemoteParams ) VirtualFreeEx( hProcess, lpRemoteParams, dwParamSize, MEM_RELEASE );
    return FALSE;
}

int main(int argc, char *argv[]) {
	AddDebugPrivilege();
	
	// create our structures for the functions that respond with data to the applications we are fuzzing...
	FuzzySetup();
	
	if (argc < 2) {
		printf("usage: %s pid\n", argv[0]);
		exit(-1);
	}

	int pid = atoi(argv[1]);
	if (argc == 3) {
		dll = (char *)argv[2];
	}

	_pid = pid;
	if ((hProcess = OpenProcess(PROCESS_ALL_ACCESS, 0, pid)) == NULL) {
		printf("cannot open process %d\n", pid);
		exit(-1);	
	}


	//printf("Pausing all threads (to add breakpoints)\n");
	//PauseThreads(pid, 0);

	printf("Inserting the breakpoints\n");
	FuzzyBreakpointsAdd(pid);


	printf("Attached to %d [HANDLE %X]\n", pid, hProcess);


	printf("Resuming all threads and debugging until we reach a fuzzy function\n");
	//PauseThreads(pid, 1);
	// debug till we reach our breakpoint.. and dump that threads information..
	printf("Attaching debugger to %d\n", pid);
	int done = 0;
	while (!done) {
	if (DebugTillReady(pid)) {

		printf("Pausing all other threads\n");
		// now lets dump all other threads in case multi-threading is a necessity to trigger the bug
		PauseThreads(pid, 0);
		printf("Dumping thread context to snapshot\n");
		DWORD thread_data_size = 0;
		DWORD thread_count = 0;
		char *thread_data = ThreadData(&thread_data_size, &thread_count);
		
		printf("Thread Data Size %d PTR %X\n", thread_data_size, thread_data);



		printf("Dump module information to snapshot\n");
		DWORD module_data_size = 0;
		DWORD module_count = 0;
		char *module_data = ModuleData(pid, &module_data_size, &module_count);
		printf("Module Data Size %d PTR %X count %d\n", module_data_size, module_data, module_count);

		printf("Dump memory to snapshot\n");
		DWORD memory_data_size = 0;
		DWORD memory_page_count = 0;
		char *memory_data = MemoryData(&memory_data_size, &memory_page_count);
		printf("Memory Dump Size %d PTR %X\n", memory_data_size, memory_data);

		char fname[1024];
		wsprintf(fname, "%d_%d_snapshot.dat", pid, snapshot_count);
		
		printf("Writing data to disk as '%s'\n", fname);		

		
		
		printf("Opening output file: %s\n", fname);
		FILE *fd = fopen(fname, "wb");
		if (fd == NULL) {
			printf("couldnt open output file [%s]\n", fname);
			exit(-1);
		}


		FuzzSnapshotInfo snapinfo;
		snapinfo.hdr = 0xFFFFEEEE;
		snapinfo.version = 0x01000203;
		snapinfo.memory_data_size = memory_data_size;
		snapinfo.page_count = memory_page_count;
		snapinfo.module_count = module_count;
		snapinfo.thread_count = thread_count;
		snapinfo.module_data_size = module_data_size;
		snapinfo.thread_data_size = thread_data_size;

		fwrite((const void *)&snapinfo, 1, sizeof(FuzzSnapshotInfo), fd);
		fwrite((const void *)thread_data, 1, thread_data_size, fd);
		fwrite((const void *)module_data, 1, module_data_size, fd);
		fwrite((const void *)memory_data, 1, memory_data_size, fd);

		
		fclose(fd);

		HeapFree(GetProcessHeap(), 0, thread_data);
		HeapFree(GetProcessHeap(), 0, module_data);
		HeapFree(GetProcessHeap(), 0, memory_data);

		printf("Finished dumping snapshot\n");


		


		// we're closing FD after resume so the buffering of writing data to disk wont hold anything up...
		if (dll == NULL) {

			printf("Re-implementing breakpoints for next function!\n");
			Modifications_Redo();

			printf("Resume original process..\n");
			PauseThreads(pid, 1);
		
		} else {
			done = 1;
			printf("Injecting PROXY DLL for emulation help\n");
			/*
			DWORD old_prot = 0;
			char *remote_dll_addr = (char *)VirtualAllocEx(hProcess, 0, 4096, MEM_COMMIT|MEM_RESERVE, PAGE_EXECUTE_READWRITE);
			int inserted = 0;
			if (remote_dll_addr) {
				char *dll_name = StrRChr(dll, 0, '\\');
				dll_name++;
				inserted = (FindModuleBase(pid, dll_name) != NULL);
			}
			// get rva of loadlibrary...
			printf("Inserted DLL successfully? %d\n", inserted);
			if (remote_dll_addr == NULL || !inserted) {
				printf("error allocating space in the remote process.. resuming normally\n");
				PauseThreads(pid, 1);
			}*/
			PVOID lpReturn = NULL;
			RemoteLibraryFunction( hProcess, "kernel32.dll", "LoadLibraryA", dll, lstrlenA(dll), &lpReturn );
			HMODULE hInjected = reinterpret_cast<HMODULE>( lpReturn );
			if (!hInjected) {
				printf("Couldnt inject..resuming normally\n");
			} else printf("Successfully injected.. handle %X\n", hInjected);

			// resume all threads...
			PauseThreads(pid, 1);
			
			
		}
	}

		

	}

	DebugActiveProcessStop(pid);

	ExitProcess(0);

	return 0;
}
