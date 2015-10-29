typedef long NTSTATUS;
typedef NTSTATUS (WINAPI *tNtQueryInformationThread)(HANDLE, PVOID, PVOID, ULONG, PULONG);

// undocumented information for NtQueryInformationThread that we use
//#define THREAD_QUERY_INFORMATION 0x0040
#define ThreadQuerySetWin32StartAddress 9
#define STATUS_SUCCESS ((NTSTATUS)0x00000000L)
// modifications should be placed here...
typedef struct _modification {
	struct _modification *next;
	FuzzFunction *reason;
	DWORD_PTR Address;
	char *original_data;
	int original_size;
	
	char *replace_data;
	int replace_size;
	int undo;
	int next_undo;

	DWORD_PTR InstructionSize;
	// just so we calculate this once at start
	DWORD_PTR NextAddress;
	char *next_original_data;
	int next_original_size;
	char *next_replace_data;
	int next_replace_size;
} Modification;

Modification *ModificationAdd(DWORD_PTR Address, char *replace, int size);
Modification *ModificationSearch(DWORD_PTR Address, int *was_next);
int Modification_Redo(DWORD_PTR Address);
void Modifications_Redo();
void Modifications_Undo();