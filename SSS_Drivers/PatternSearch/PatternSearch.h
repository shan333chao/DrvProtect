#include "../Memmory/MiMemory.h"
#define VM_MODULE_FULL 1
#define VM_MODULE_CODESECTIONSONLY 2
#define VM_MODULE_RAW 3
 
namespace patternSearch {

	UCHAR read_i8(PEPROCESS process, ULONGLONG address);
	USHORT read_i16(PEPROCESS process, ULONGLONG address);
	ULONG read_i32(PEPROCESS process, ULONGLONG address);
	ULONGLONG read_i64(PEPROCESS process, ULONGLONG address);
	//float read_float(PEPROCESS process, ULONGLONG address);


	BOOLEAN write_i8(PEPROCESS process, ULONGLONG address, UCHAR value);
	BOOLEAN write_i16(PEPROCESS process, ULONGLONG address, USHORT value);
	BOOLEAN write_i32(PEPROCESS process, ULONGLONG address, ULONG value);
	BOOLEAN write_i64(PEPROCESS process, ULONGLONG address, ULONGLONG value);
	//BOOLEAN write_float(PEPROCESS process, ULONGLONG address, float value);

	ULONGLONG  get_relative_address(PEPROCESS process, ULONGLONG instruction, ULONG offset, ULONG instruction_size);
	ULONGLONG get_module(PEPROCESS process, PCSTR dll_name, PULONG moduleSize);
	ULONGLONG get_module_export(PEPROCESS process, ULONGLONG base, PCSTR export_name);
	ULONGLONG scan_pattern(PVOID dumped_module, char* pattern, char* mask, ULONGLONG length);
	PVOID  dump_module(PEPROCESS process, ULONGLONG base, UCHAR module_type);
	void  free_module(PVOID dumped_module);
	ULONGLONG  scan_pattern_direct(PEPROCESS process, ULONGLONG base, char* pattern, char* mask, ULONG moduleSize);
 
	BOOLEAN  IsAddressInModule(PEPROCESS process, ULONGLONG base, UCHAR module_type, ULONG64 exportAddr);
	PEPROCESS GetProcessByDllName(PCHAR dllName);
	ULONGLONG search_process_pattern(HANDLE pid, PCSTR export_name, char* pattern, char* mask);

	VOID test();
}