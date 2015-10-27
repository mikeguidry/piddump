typedef struct _fuzz_functions {
	struct _fuzz_functions *next;
	char *module_name;
	char *function_name;
	HMODULE handle;
	DWORD_PTR function_addr;
	DWORD_PTR rva;
	DWORD_PTR remote_addr;
} FuzzFunction;



typedef struct _thread_info {
	struct _thread_info *next;

	DWORD_PTR ThreadID;
	DWORD_PTR StackLow;
	DWORD_PTR StackHigh;
	DWORD_PTR TIB;
	DWORD_PTR PEB;
	DWORD_PTR TLS;
	
	CONTEXT ctx;
	CONTEXT ctx_segments;

	// is this the thread to fuzz? (calling a function we wanna fuzz data)
	DWORD_PTR fuzz;

	// which function caused this BP?
	char module_name[32];
	char function_name[32];
} ThreadInfo;


typedef struct _fuzz_instruction_snapshot {
	DWORD_PTR hdr;
	DWORD_PTR version;
	DWORD_PTR thread_data_size;
	DWORD_PTR thread_count;
	DWORD_PTR module_data_size;
	DWORD_PTR module_count;
	DWORD_PTR memory_data_size;
	DWORD_PTR page_count;
} FuzzSnapshotInfo;