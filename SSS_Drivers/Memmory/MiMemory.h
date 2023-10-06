#include "../includes.h"
#include "../SSDT/Functions.h"



namespace MiMemory {
	ULONGLONG read_i64(ULONGLONG address);
	ULONGLONG  translate(ULONGLONG dir, ULONGLONG va);
	BOOLEAN read(ULONGLONG address, PVOID buffer, ULONGLONG length, ULONGLONG* ret);
	BOOLEAN  write(ULONGLONG address, PVOID buffer, ULONGLONG length);
	NTSTATUS MiReadSystemMemory(IN PVOID Source, OUT PVOID Destination, IN SIZE_T NumberOfBytes);
	NTSTATUS MiWriteSystemMemory(IN PVOID Destination, OUT PVOID Source, IN SIZE_T NumberOfBytes);
	NTSTATUS MiReadProcessMemory(IN PEPROCESS process, IN PVOID address, OUT PVOID buffer, IN SIZE_T readSize);
	NTSTATUS  MiWriteProcessMemory(PEPROCESS process, PVOID address, PVOID buffer, SIZE_T length);
}