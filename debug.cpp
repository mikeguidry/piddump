#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <shlwapi.h>
#include <Tlhelp32.h>
#include <dbghelp.h>
#include <windows.h>
#include "structures.h"
#include "debug.h"

// *** FIX: remove udis86 (add as library so we dont have to share with the licensing)
#include "udis86/udis86.h"

#pragma comment(lib, "dbghelp.lib")
#pragma comment(lib, "shlwapi.lib")


extern long injected;

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


// how many bytes do we disassemble per loop?
#define BYTES_PER_DISASM_LOOP 13

// get the size of a function by disassembling it until the return
int Disasm(DWORD_PTR FuncAddr, char *asmbuf) {
	int size = 0;
	
	// initialize disassembler
	ud_t ud_obj;
	ud_init(&ud_obj);
	unsigned char data[BYTES_PER_DISASM_LOOP];
	
#ifndef _WIN64
	ud_set_mode(&ud_obj, 32);
#else
	ud_set_mode(&ud_obj, 64);
#endif
	ud_set_syntax(&ud_obj, UD_SYN_INTEL);
	
	unsigned char *Data = (unsigned char *)FuncAddr;
	
	DWORD_PTR Addr = (DWORD_PTR)FuncAddr;
	int len = 0;
	int bytes_to_disasm = BYTES_PER_DISASM_LOOP;
	
	while (1) {
		bytes_to_disasm = 13;
		//if (Addr >= ModuleEnd || bytes_to_disasm+Addr >= ModuleEnd) { size = 0; break; }
		
		ud_set_pc(&ud_obj, (unsigned __int64)Addr);
		
		// copy the instruction at Data (13 bytes max.. found this constant somewhere.. maybe up to ~21 on some 64bit, or vm-capable code)
		memcpy(&data, Data, BYTES_PER_DISASM_LOOP);
		ud_set_input_buffer(&ud_obj, (uint8_t*)data, BYTES_PER_DISASM_LOOP);
		
		// disassemble and turn into ascii
		if ((len = ud_disassemble(&ud_obj)) <= 0) { size = 0; break; }
		char *asm_text = (char *)ud_insn_asm(&ud_obj);
		
		if(asmbuf != NULL) {
			lstrcpy(asmbuf, asm_text);
		}
		size += len;
		
		printf("%s\n", asm_text);
		//if (StrStrI(asm_text, "ret") != NULL) break;
		
		Data += size;
		Addr += size;
		
		break;
	}
	
	return size;
}


Modification *ModificationAdd(DWORD_PTR Address, char *replace, int size) {
	Modification *mptr = (Modification *)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(Modification));
	if (mptr == NULL) return NULL;

	printf("Mod add addr %X\n", Address);

	mptr->Address = Address;
	mptr->original_data = (char *)HeapAlloc(GetProcessHeap(), 0, size);
	mptr->replace_data = (char *)HeapAlloc(GetProcessHeap(), 0, size);
	mptr->original_size = mptr->replace_size = size;

	mptr->next_original_data = (char *)HeapAlloc(GetProcessHeap(), 0, size);
	mptr->next_replace_data  = (char *)HeapAlloc(GetProcessHeap(), 0, size);
	mptr->next_original_size = mptr->next_replace_size = size;

	// now we need the address of the NEXT function (so we can continously hook & dump the software being fuzzed)
	int instruction_len = Disasm(Address, NULL);
	if (instruction_len != 0) {
		mptr->InstructionSize = instruction_len;
		mptr->NextAddress = (Address + instruction_len);
	} else {
		printf("couldnt disassemble instruction!\n");
	}

	CopyMemory(mptr->replace_data, replace, size);
	CopyMemory(mptr->next_replace_data, replace, size);

	DWORD rw_count = 0;
	ReadProcessMemory(hProcess,(const void *) Address, mptr->original_data, size, &rw_count);
	ReadProcessMemory(hProcess,(const void *) (Address + mptr->InstructionSize), mptr->next_original_data, size, &rw_count);

	DWORD old_prot = 0;
	VirtualProtectEx(hProcess, (LPVOID) Address, size, PAGE_EXECUTE_READWRITE, &old_prot);

	// we need to pause the process at this moment!
	WriteProcessMemory(hProcess, ( void *) Address, mptr->replace_data, size, &rw_count);

	FlushInstructionCache(hProcess, (const void *)Address, size);

	VirtualProtectEx(hProcess, (LPVOID) Address, size, old_prot, &old_prot);

	mptr->next = mod_list;
	mod_list = mptr;

	return mptr;
}





Modification *ModificationSearch(DWORD_PTR Address, int *was_next) {
	Modification *mptr = mod_list;

	while (mptr != NULL) {
		if (mptr->NextAddress == Address) {
			if (was_next != NULL)
				*was_next = 1;
			return mptr;
		} else {
			if (mptr->Address == Address) {
				return mptr;
			}
		}
		mptr = mptr->next;
	}

	return NULL;
}


int Modification_Redo(DWORD_PTR Address, int next) {
	int was_next = 0;
	Modification *mptr = ModificationSearch(Address, next ? &was_next : NULL);
	
	printf("Modification Redo: %X next: %d\n", Address, next);
	if (mptr != NULL) {
		printf("not found!\n");
		DWORD old_prot = 0;		
		DWORD rw_count = 0;

		int prot_size = mptr->InstructionSize + mptr->next_replace_size;
		printf("Setting BP: %X [next? %d]\n",
			Address, next);

		VirtualProtectEx(hProcess, (LPVOID) Address, prot_size, PAGE_EXECUTE_READWRITE, &old_prot);

		if (!next) {
			WriteProcessMemory(hProcess, (void *) mptr->Address, mptr->replace_data, mptr->replace_size, &rw_count);
			mptr->undo = 0;
		} else {
			printf("BP at NEXT: %X\n", mptr->NextAddress);
			WriteProcessMemory(hProcess, (void *) mptr->NextAddress, mptr->next_replace_data, mptr->next_replace_size, &rw_count);
			mptr->next_undo = 0;
		}

		VirtualProtectEx(hProcess, (LPVOID) Address, prot_size, old_prot, &old_prot);

		FlushInstructionCache(hProcess, (const void *)Address, prot_size);
		
		
		return 1;
	}
	
	return 0;

}



// for now.. we work with having the instruction size..
// we need to single step otherwise but i wasnt having much success with this new engine
int Modification_Undo(DWORD_PTR Address, int hook_next) {
	Modification *mptr = ModificationSearch(Address, NULL);

	if (mptr != NULL && !mptr->undo) {
		DWORD old_prot = 0;
		DWORD rw_count = 0;

		printf("Remove BP @ %X [next? %d]\n", Address, hook_next);
		VirtualProtectEx(hProcess, (LPVOID) Address, mptr->InstructionSize + mptr->next_replace_size, PAGE_EXECUTE_READWRITE, &old_prot);
		if (!hook_next) {
			// we need to pause the process at this moment..
			WriteProcessMemory(hProcess, (void *) Address, mptr->original_data, mptr->original_size, &rw_count);
			mptr->undo = 1;
		} else {
			// we need to pause the process at this moment..
			WriteProcessMemory(hProcess, (void *) mptr->NextAddress, mptr->next_original_data, mptr->next_original_size, &rw_count);
			mptr->next_undo = 1;
		}
		
		VirtualProtectEx(hProcess, (LPVOID) Address, mptr->InstructionSize + mptr->next_replace_size, old_prot, &old_prot);

		FlushInstructionCache(hProcess, (const void *)mptr->Address, mptr->InstructionSize + mptr->next_replace_size);

		return 1;
	}

	return 0;
}



// redo all
void Modifications_Redo() {
	Modification *mptr = mod_list;
	while (mptr != NULL) {
		Modification_Redo(mptr->Address, 0);

		mptr = mptr->next;
	}
}

// undo all
void Modifications_Undo() {
	Modification *mptr = mod_list;
	while (mptr != NULL) {
		Modification_Undo(mptr->Address, 0);
		Modification_Undo(mptr->Address, 1);

		mptr = mptr->next;
	}
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

BOOL DoneOnce = FALSE;
void InjDLL();
extern long inject_dll;

// each thread has to be stepped out of any windows DLLs or other DLLs...
// so we can hook and redirect those to API proxy or a simulation..
//int StepUpFrame(int PID, HANDLE hThread, DWORD_PTR TID) {
int DebugTillReady(DWORD_PTR PID, int next, int *do_we_dump) {
	Modification *mptr = NULL;
	printf("\n----\nDebug Till Ready\n");	
	// get threads context..
	DEBUG_EVENT DebugEv;
	int ret = 0;
	CONTEXT ctx;
	DWORD dwContinueStatus = DBG_CONTINUE;
	HANDLE hThread2;
	int was_next = 0;
	DWORD_PTR BreakAddr = 0;

	
	DebugActiveProcess(PID);

	
	
	int done = 0;
	int count = 0;
	while (!done && !InterlockedExchangeAdd(&injected, 0)) {

		int wf = WaitForDebugEvent(&DebugEv, 5000);
		if (InterlockedExchangeAdd(&inject_dll, 0)) {
			ContinueDebugEvent(DebugEv.dwProcessId, DebugEv.dwThreadId, dwContinueStatus);
			return 0;
		}
		if (wf == 0) continue;


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

						BreakAddr = (DWORD_PTR)DebugEv.u.Exception.ExceptionRecord.ExceptionAddress;

						if (next) {
							// first lets see if this is the next instruction after a fuzzy function (in which case we remove it and re-breakpoint the original)
							// until i get single stepping working properly with this debugger (it might be CONTEXT flags.. shrug)
							mptr = ModificationSearch((DWORD_PTR)BreakAddr, &was_next);

							printf("first next search for %X -> mptr %X was_next %d\n", BreakAddr, mptr, was_next);
						}

						// now lets see if this address is a hooked function..
						if (mptr == NULL) {
							mptr = ModificationSearch((DWORD_PTR)BreakAddr, NULL);

							printf("second search for %X -> mptr %X was_next %d\n", BreakAddr, mptr, was_next);
						}
						
						
						if (mptr != NULL) {	
							printf("MPTR FOUND %X : Mptr Addy %X Next %X\n", 
								BreakAddr, mptr->Address, mptr->NextAddress);

							hThread2 = OpenThread(THREAD_ALL_ACCESS, FALSE, DebugEv.dwThreadId);
							SuspendThread(hThread2);

							// we want debug registers just in case we begin using hardware breakpoints rather than
							// byte replacing.. (it would be faster.... but limits to 4 functions )
							ctx.ContextFlags = CONTEXT_ALL;
							if (GetThreadContext(hThread2, &ctx) == 0) {
								printf("Couldnt get thread context.. %X\n", hThread2);
								return -1;
							}
							
							printf("BP @ EIP %X [Function %s <%s>]\n", ctx.Eip, mptr->reason->module_name, mptr->reason->function_name);
							printf("ESP: %X EBP: %X\n", ctx.Esp, ctx.Ebp);

							ctx.Eip = (was_next) ? mptr->NextAddress : mptr->Address;
							// since we had the breakpoint.. we have to reverse the EIP
							//ctx.Eip--;
							SetThreadContext(hThread2, &ctx);
							

							printf("Undo %X was_next %d\n", BreakAddr, was_next);
							// undo the breakpoint (whether it was next, or original)..
							Modification_Undo((DWORD_PTR)BreakAddr, was_next);

							printf("Redo %X was_next %d\n", BreakAddr, was_next == 0);

							if (next) {
								// now if we want to continue to process (next variable) we want to set that breakpoint at the next instruction, or the original...
								Modification_Redo((DWORD_PTR)BreakAddr, was_next == 0);

								ResumeThread(hThread2);
							}

							
							CloseHandle(hThread2);
							

							if (!was_next) {
								printf("We hit a fuzzed function breakpoint.  Returning so we can dump the data...\n");

								// take all thread information before execution resumes
								IndexThreads(PID);
								*do_we_dump = 1;
							} else {
								*do_we_dump = 0;
							}

							// so we know the process is ready to return to calling function...
							ret = 1;
							done = 1;

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

	

	
	return ret;
}



