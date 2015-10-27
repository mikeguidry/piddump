#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <shlwapi.h>
#include <Tlhelp32.h>
#include <dbghelp.h>
#pragma comment(lib, "dbghelp.lib")
#pragma comment(lib, "shlwapi.lib")

extern HANDLE hProcess;
#include <windows.h>
#include "debug.h"

extern int thread_count_location;
extern DWORD_PTR G_thread_count;


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



Modification *mod_list = NULL;



Modification *ModificationAdd(DWORD_PTR Address, char *replace, int size) {
	Modification *mptr = (Modification *)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(Modification));
	if (mptr == NULL) return NULL;

	mptr->Address = Address;
	mptr->original_data = (char *)HeapAlloc(GetProcessHeap(), 0, size);
	mptr->replace_data = (char *)HeapAlloc(GetProcessHeap(), 0, size);
	mptr->original_size = mptr->replace_size = size;

	CopyMemory(mptr->replace_data, replace, size);

	DWORD rw_count = 0;
	ReadProcessMemory(hProcess,(const void *) Address, mptr->original_data, size, &rw_count);

	DWORD old_prot = 0;
	VirtualProtectEx(hProcess, (LPVOID) Address, size, PAGE_EXECUTE_READWRITE, &old_prot);

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
		WriteProcessMemory(hProcess, (void *) Address, mptr->original_data, 1, &rw_count);
		printf("wrote %d bytes to %X\n", rw_count, Address);
		FlushInstructionCache(hProcess, (const void *)Address, mptr->original_size);
		VirtualProtectEx(hProcess, (LPVOID) Address, mptr->original_size, old_prot, &old_prot);

		HeapFree(GetProcessHeap(), 0, mptr->original_data);
		HeapFree(GetProcessHeap(), 0, mptr->replace_data);

		Modification *mptr2 = mod_list;
		if (mod_list == mptr) {
			mod_list = mptr->next;
		} else {
			while (mptr2->next != mptr) {
				mptr2 = mptr2->next;
			}
			mptr2->next = mptr2->next;
		}

		HeapFree(GetProcessHeap(), 0, mptr);
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

DWORD_PTR CaptureSegValue(HANDLE hThread, DWORD_PTR Seg) {
	LDT_ENTRY ldtSel;
	
	if (!GetThreadSelectorEntry(hThread, Seg, &ldtSel)) {
		printf("Couldnt get thread selector entry for FS for thread %d\n", hThread);
		exit(-1);
		return -1;
	}
	
	DWORD_PTR fs_base = (ldtSel.HighWord.Bits.BaseHi << 24 ) | ( ldtSel.HighWord.Bits.BaseMid << 16 ) | ( ldtSel.BaseLow );

	printf("CaptureSegValue(%X) = %X\n", Seg, fs_base);
	
	return fs_base;
}

void CaptureSegs(HANDLE hThread, CONTEXT *ctx) {
	int i = 0;
	DWORD_PTR *SegsToGrab[] = { &ctx->SegGs, &ctx->SegFs, &ctx->SegEs, &ctx->SegDs, &ctx->SegCs, &ctx->SegSs, NULL };
printf("%X %X %X %X %X %x %x\n",
&ctx->SegGs, &ctx->SegFs, ctx->SegEs, ctx->SegDs, ctx->SegCs, ctx->SegSs
	  );
	while (SegsToGrab[i] != NULL) {
		// deref the pointer of the list of segments..
		DWORD_PTR *_Seg = (DWORD_PTR *)SegsToGrab[i];
		DWORD_PTR Seg = *_Seg;

		// grab the real segment linear address..
		DWORD_PTR Addr = CaptureSegValue(hThread, Seg);

		// replace with the returned
		*_Seg = Addr;

		i++;
	}



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

				if (StrStrI(me.szModule, ".exe") != NULL) {
					ret = 1;
				}
				break;
			}
		}
	}

	CloseHandle(hTH);

	return ret;
}

int ThreadAdd(DWORD_PTR ThreadID, FILE *fd, DWORD_PTR EIP);
// each thread has to be stepped out of any windows DLLs or other DLLs...
// so we can hook and redirect those to API proxy or a simulation..
//int StepUpFrame(int PID, HANDLE hThread, DWORD_PTR TID) {
int DebugTillReady(DWORD_PTR PID, HANDLE hThread, DWORD_PTR TID, FILE *fd) {
	printf("\n----\nDebug Till Ready\n");	
	// get threads context..
	DEBUG_EVENT DebugEv;
	int ret = 0;
	CONTEXT ctx;
	DWORD dwContinueStatus = DBG_CONTINUE;

	HANDLE hThread2;

	/*printf("hThread %X TID %X\n", hThread, TID);
	
	// find the threads start address... so we can get back to a frame inside of it..
	DWORD_PTR StartAddress = GetThreadStartAddress(hProcess, hThread);
	if (!AddrInExecutable(PID, StartAddress) && 1==0) {
		return 0;
	}

	printf("1\n");

	SuspendThread(hThread);

	ctx.ContextFlags = CONTEXT_FULL;
	if (GetThreadContext(hThread, &ctx) == 0) {
		printf("Couldnt get thread context.. %X\n", hThread);
		return -1;
	}

	printf("2\n");

	int FoundFrame = 0;
	DWORD_PTR ret_bp_addr = 0;
	DWORD_PTR CurEbp = ctx.Ebp;
	int retry = 5;
	while (!FoundFrame && retry--) {
		printf("%X loop %X\n", hThread, CurEbp);
		DWORD_PTR frame_ret_addr = RemoteDerefDWORD(CurEbp + 4);

		if (frame_ret_addr == 0) break;
		printf("Frame Ret Addr %X\n", frame_ret_addr);
		if (AddrInExecutable(PID, frame_ret_addr)) {
			ret_bp_addr = frame_ret_addr;
			FoundFrame = 1;
			break;
		}

		DWORD_PTR NextEbp = RemoteDerefDWORD(CurEbp);

		if (NextEbp == 0) break;

		// ensure the next EBP frame is inside of the stack (some functions wont work like this)
		if (WithinStack(hProcess, hThread, NextEbp, &ctx)) {
			printf("next ebp %X is within stack\n", NextEbp);
			CurEbp = NextEbp;
			continue;
		}

		printf("breaking out of loop\n");
		break;
	}

	printf("Found EIP to BP %X CUR EBP [%X] Start EBP %X\n", ret_bp_addr, CurEbp, ctx.Ebp);

	

	printf("after loop\n");
	// if we couldnt find any frames inside of the target executable.. lets just do nothing on this thread
	if (!FoundFrame) {
		printf("Couldnt find next EIP for this thread\n");
		return 0;
	}

	printf("before mod %X\n", ret_bp_addr);

	char int3[] = "\xCC";
	Modification *mptr = ModificationAdd(ret_bp_addr, (char *)&int3, 1);
	printf("after mod\n");

	//ResumeThread(hThread);
	//ResumeThread(hThread);
	ResumeThread(hThread);
	// connect debugger to process... all threads have already been resumed..
	
	printf("debugging\n");
	
	printf("debug\n");
	*/
	
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
			if (DebugEv.dwThreadId == TID && 0==1) {
				printf("our tid!\n");
				done = 1;
				//break;
			}
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


						if (ModificationSearch((DWORD_PTR)DebugEv.u.Exception.ExceptionRecord.ExceptionAddress) != NULL) {
							
							hThread2 = OpenThread(THREAD_ALL_ACCESS, FALSE, DebugEv.dwThreadId);

							CONTEXT ctx;
							ctx.ContextFlags = CONTEXT_FULL;
							if (GetThreadContext(hThread2, &ctx) == 0) {
								printf("Couldnt get thread context.. %X\n", hThread);
								return -1;
							}
							ctx.Eip--;
							SetThreadContext(hThread2, &ctx);
							printf("EIP %X\n", ctx.Eip);

							if (!thread_count_location) {
								thread_count_location = ftell(fd);
								G_thread_count++;
								fwrite((void *)&G_thread_count, 1, sizeof(DWORD_PTR), fd);
							}
							
							ThreadAdd(DebugEv.dwThreadId, fd, ctx.Eip);
							
							SuspendThread(hThread2);

							Modification_Undo((DWORD_PTR)DebugEv.u.Exception.ExceptionRecord.ExceptionAddress);

							CloseHandle(hThread2);

							printf("FOUND BP!");
							ret = 1;
							done = 1;

							return 1;
							
							break;
						}

						/*if (DebugEv.u.Exception.ExceptionRecord.ExceptionAddress == (void *)ret_bp_addr) {
							printf("Reached the point we wanted.. EIP %X\n", DebugEv.u.Exception.ExceptionRecord.ExceptionAddress);

							
							ctx.ContextFlags = CONTEXT_FULL;
							if (GetThreadContext(hThread, &ctx) == 0) {
								printf("Couldnt get thread context.. %X\n", hThread);
								return -1;
							}
							printf("EIP %X\n", ctx.Eip);

							ctx.Eip--;

							SetThreadContext(hThread, &ctx);

							printf("finished debug\n");

							done = 1;

							dwContinueStatus = DBG_CONTINUE;
						} */
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

	
	printf("finished\n");

	//Modification_Undo(ret_bp_addr);
	printf("after undo\n");

	
	return ret;
}



