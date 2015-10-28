#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <shlwapi.h>
#include <Tlhelp32.h>
#include <dbghelp.h>
#include <windows.h>
#include "structures.h"
#include "debug.h"

#pragma comment(lib, "dbghelp.lib")
#pragma comment(lib, "shlwapi.lib")

// hProcess global from other C file.. we'll remove globals later.. oh well
extern HANDLE hProcess;

// list of our functions being fuzzed (where we set breakpoints, original code, etc...)
Modification *mod_list = NULL;

// index threads inside of a PID
BOOL IndexThreads(unsigned long pid);




DWORD_PTR WINAPI GetThreadStartAddress(HANDLE hProcess, HANDLE hThread) {
    NTSTATUS ntStatus;
    HANDLE hDupHandle;
    DWORD dwStartAddress;
	
    tNtQueryInformationThread NtQueryInformationThread = (tNtQueryInformationThread)GetProcAddress(GetModuleHandle("ntdll.dll"), "NtQueryInformationThread");
	
    if(NtQueryInformationThread == NULL) 
        return 0;
	
	HANDLE hCurrentProcess = GetCurrentProcess();
    if(!DuplicateHandle(hProcess, hThread, hCurrentProcess, &hDupHandle, THREAD_QUERY_INFORMATION, FALSE, 0)){
        SetLastError(ERROR_ACCESS_DENIED);
		
        return 0;
    }
	
    ntStatus = NtQueryInformationThread(hDupHandle, (PVOID)ThreadQuerySetWin32StartAddress, &dwStartAddress, sizeof(DWORD), NULL);
    CloseHandle(hDupHandle);
    if(ntStatus != STATUS_SUCCESS) 
		return 0;
	
    return dwStartAddress;
	
}




Modification *ModificationAdd(DWORD_PTR Address, char *replace, int size) {
	Modification *mptr = (Modification *)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(Modification));
	if (mptr == NULL) return NULL;

	printf("Mod add addr %X\n", Address);

	mptr->Address = Address;
	mptr->original_data = (char *)HeapAlloc(GetProcessHeap(), 0, size);
	mptr->replace_data = (char *)HeapAlloc(GetProcessHeap(), 0, size);
	mptr->original_size = mptr->replace_size = size;

	CopyMemory(mptr->replace_data, replace, size);

	DWORD rw_count = 0;
	ReadProcessMemory(hProcess,(const void *) Address, mptr->original_data, size, &rw_count);

	DWORD old_prot = 0;
	VirtualProtectEx(hProcess, (LPVOID) Address, size, PAGE_EXECUTE_READWRITE, &old_prot);

	// we need to pause the process at this moment!
	WriteProcessMemory(hProcess, ( void *) Address, mptr->replace_data, 1, &rw_count);

	FlushInstructionCache(hProcess, (const void *)Address, size);

	VirtualProtectEx(hProcess, (LPVOID) Address, size, old_prot, &old_prot);

	mptr->next = mod_list;
	mod_list = mptr;

	return mptr;
}





Modification *ModificationSearch(DWORD_PTR Address) {
	Modification *mptr = mod_list;

	while (mptr != NULL) {
		if (mptr->Address == Address) return mptr;
		mptr = mptr->next;
	}

	return NULL;
}




int Modification_Undo(DWORD_PTR Address) {
	Modification *mptr = ModificationSearch(Address);

	if (mptr != NULL) {
		DWORD old_prot = 0;

		printf("replacing original\n");
		VirtualProtectEx(hProcess, (LPVOID) Address, mptr->original_size, PAGE_EXECUTE_READWRITE, &old_prot);

		DWORD rw_count = 0;
		// we need to pause the process at this moment..
		WriteProcessMemory(hProcess, (void *) Address, mptr->original_data, 1, &rw_count);
		printf("wrote %d bytes to %X\n", rw_count, Address);
		FlushInstructionCache(hProcess, (const void *)Address, mptr->original_size);
		VirtualProtectEx(hProcess, (LPVOID) Address, mptr->original_size, old_prot, &old_prot);

		return 1;
	}

	return 0;
}


BOOL  AddDebugPrivilege() { 
	HANDLE Token; 
    TOKEN_PRIVILEGES TokenPrivileges, PreviousState; 
    DWORD ReturnLength = 0; 
    if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY | TOKEN_ADJUST_PRIVILEGES, &Token))
	{
		if(LookupPrivilegeValueA(NULL, "SeDebugPrivilege", &TokenPrivileges.Privileges[0].Luid)) 
		{
			TokenPrivileges.PrivilegeCount = 1; 
            TokenPrivileges.Privileges[0].Attributes =SE_PRIVILEGE_ENABLED; 
            return (AdjustTokenPrivileges(Token, FALSE, &TokenPrivileges, 
				sizeof (TOKEN_PRIVILEGES), &PreviousState, &ReturnLength)); 
		} 
	}
    return FALSE; 
} // AddDebugPrivilege 





DWORD_PTR RemoteDerefDWORD(DWORD_PTR Address) {
	DWORD rw_count = 0;
	DWORD_PTR ret = 0;

	ReadProcessMemory(hProcess,(const void *)Address, &ret, sizeof(DWORD_PTR), &rw_count);

	return ret;
}





int WithinStack(HANDLE hProcess, HANDLE hThread, DWORD_PTR Address, CONTEXT *ctx) {
	LDT_ENTRY ldtSel;

	
	if (!GetThreadSelectorEntry(hThread, ctx->SegFs, &ldtSel)) {
		printf("Couldnt get thread selector entry for FS for thread %d\n", hThread);
		exit(-1);
		return -1;
	}
	
	// this isnt FS BASE.. its TIB base!
	DWORD_PTR fs_base = (ldtSel.HighWord.Bits.BaseHi << 24 ) | ( ldtSel.HighWord.Bits.BaseMid << 16 ) | ( ldtSel.BaseLow );

	DWORD_PTR stackhigh = RemoteDerefDWORD(fs_base + 4);
	DWORD_PTR stacklow = RemoteDerefDWORD(fs_base + 8);

	printf("Thread %X stack low %X high %X\n", stacklow, stackhigh);
	if (Address >= stacklow && Address < stackhigh) {
		printf("IN STACK\n");
		return 1;
	}

	return 1;
}




int AddrInExecutable(DWORD_PTR pid, DWORD_PTR Address) {
	int ret = 0;
    BOOL          bRet        = FALSE; 
    MODULEENTRY32 me        = {0}; 
	DWORD CurrentProcID = GetCurrentProcessId();
	DWORD CurrentThreadID = GetCurrentThreadId();
	HANDLE hTH;
	
	if (pid == 0) pid = CurrentProcID;
	
	if ((hTH = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, pid)) != INVALID_HANDLE_VALUE) {
		me.dwSize = sizeof(me);
		
		int tret = 0;
		for (tret = Module32First(hTH, &me); tret; tret = Module32Next(hTH, &me)) {
			if ((Address >= (DWORD_PTR)me.modBaseAddr) && (Address <= (DWORD_PTR)(me.modBaseAddr + me.modBaseSize))) {
				printf("EIP %X Found in module %s\n", Address, me.szModule);

				if (StrStrI(me.szModule, "ws2_32") != NULL) {
					ret = 1;
				}
				break;
			}
		}
	}

	CloseHandle(hTH);

	return ret;
}




// each thread has to be stepped out of any windows DLLs or other DLLs...
// so we can hook and redirect those to API proxy or a simulation..
//int StepUpFrame(int PID, HANDLE hThread, DWORD_PTR TID) {
int DebugTillReady(DWORD_PTR PID) {
	Modification *mptr = NULL;
	printf("\n----\nDebug Till Ready\n");	
	// get threads context..
	DEBUG_EVENT DebugEv;
	int ret = 0;
	CONTEXT ctx;
	DWORD dwContinueStatus = DBG_CONTINUE;

	HANDLE hThread2;

	
	DebugActiveProcess(PID);

	
	BOOL DoneOnce = FALSE;
	int done = 0;
	int count = 0;
	while (!done) {
		
		// now lets connect a debugger and step until a breakpoint
		if (WaitForDebugEvent(&DebugEv, INFINITE) == 0) {
			//if (count++ > 4) break;
			//DebugBreakProcess(hProcess);
			//continue;
			//break;
			//return -1;
		}

		//printf("LOOP\n");

		char ebuf[1024];
		//printf("debug event code %d proc %X thread %X [%X]\n", DebugEv.dwDebugEventCode, DebugEv.dwDebugEventCode, DebugEv.dwProcessId, TID);
		if (DebugEv.dwDebugEventCode == EXIT_THREAD_DEBUG_EVENT) {
			printf("exit thread debug %X\n", DebugEv.u.ExitThread.dwExitCode);
		}
		switch (DebugEv.dwDebugEventCode) {
			case EXCEPTION_DEBUG_EVENT: 
				wsprintf(ebuf, "2 Exception[%X %X] %X %X\n",DebugEv.dwProcessId, DebugEv.dwThreadId,
					DebugEv.u.Exception.ExceptionRecord.ExceptionCode, DebugEv.u.Exception.ExceptionRecord.ExceptionAddress); 
				printf(ebuf);
				OutputDebugString(ebuf); 

				switch (DebugEv.u.Exception.ExceptionRecord.ExceptionCode) {
					case EXCEPTION_BREAKPOINT:

						wsprintf(ebuf, "BP Debug exception event - Code: %x  Address: %x  Info: [%u] %x %x %x %x\n", 
							DebugEv.u.Exception.ExceptionRecord.ExceptionCode,  
							DebugEv.u.Exception.ExceptionRecord.ExceptionAddress,
							DebugEv.u.Exception.ExceptionRecord.NumberParameters,
							DebugEv.u.Exception.ExceptionRecord.ExceptionInformation[ 0 ],
							DebugEv.u.Exception.ExceptionRecord.ExceptionInformation[ 1 ],
							DebugEv.u.Exception.ExceptionRecord.ExceptionInformation[ 2 ],
							DebugEv.u.Exception.ExceptionRecord.ExceptionInformation[ 3 ]);  

						printf(ebuf);
						OutputDebugStr(ebuf);

						if (DoneOnce == FALSE) {
							dwContinueStatus = DBG_CONTINUE;
							DoneOnce = TRUE;
							break;
						}


						
						if ((mptr = ModificationSearch((DWORD_PTR)DebugEv.u.Exception.ExceptionRecord.ExceptionAddress)) != NULL) {
							
							
							hThread2 = OpenThread(THREAD_ALL_ACCESS, FALSE, DebugEv.dwThreadId);
							SuspendThread(hThread2);

							ctx.ContextFlags = CONTEXT_FULL;
							if (GetThreadContext(hThread2, &ctx) == 0) {
								printf("Couldnt get thread context.. %X\n", hThread2);
								return -1;
							}
							
							// since we had the breakpoint.. we have to reverse the EIP
							ctx.Eip--;
							SetThreadContext(hThread2, &ctx);
							printf("BP @ EIP %X [Function %s <%s>]\n", ctx.Eip, mptr->reason->module_name, mptr->reason->function_name);
							printf("ESP: %X EBP: %X\n", ctx.Esp, ctx.Ebp);


							Modification_Undo((DWORD_PTR)DebugEv.u.Exception.ExceptionRecord.ExceptionAddress);
							// *** We have to redo the breakpoint after we dump!!! I suggest breakpointing the next instruction..
							// continuing the thread and then setting the original... and then move forward... 
							// one step at a time.. lets fuzz the first hit of the first time first :)

							CloseHandle(hThread2);

							// take all thread information before execution resumes
							IndexThreads(PID);

							printf("We hit a fuzzed function breakpoint.  Returning so we can dump the data...\n");
							ret = 1;
							done = 1;
							
							break;
						}
						break;

					default:
						dwContinueStatus = DBG_EXCEPTION_NOT_HANDLED;
						break;
				}
				break;

				
				
				case CREATE_PROCESS_DEBUG_EVENT: 
					//DebugProcessCreate(pi,&DebugEv);
					dwContinueStatus = DBG_CONTINUE;
					break;
					
				case EXIT_PROCESS_DEBUG_EVENT: 
					dwContinueStatus = DBG_CONTINUE;
					//goto Done;
					break;
					
					
				case CREATE_THREAD_DEBUG_EVENT:
					//DebugThreadCreate(pi,&DebugEv);
					dwContinueStatus = DBG_CONTINUE;
					break;
					
				case EXIT_THREAD_DEBUG_EVENT:
					dwContinueStatus = DBG_CONTINUE;
					break;
					
					
				case LOAD_DLL_DEBUG_EVENT:
					dwContinueStatus = DBG_CONTINUE;
					break;
					
				case UNLOAD_DLL_DEBUG_EVENT:
					dwContinueStatus = DBG_CONTINUE;
					break;
					
					
				case OUTPUT_DEBUG_STRING_EVENT:				
					dwContinueStatus = DBG_CONTINUE;
					break;
					
		
				default:
					dwContinueStatus = DBG_EXCEPTION_NOT_HANDLED;
					break;
		}

		ContinueDebugEvent(DebugEv.dwProcessId, DebugEv.dwThreadId, dwContinueStatus);

	}

	
	DebugActiveProcessStop(PID);

	printf("Detached debugger from PID %X\n", PID);	

	
	return ret;
}



