#include "../includes.h"
#include "../SSDT/Functions.h"
typedef unsigned __int8  BYTE;
typedef unsigned __int16 WORD;
typedef unsigned long DWORD;
typedef unsigned __int64 QWORD;
typedef int BOOL;


namespace MiMemory {
	QWORD read_i64(QWORD address);
	QWORD  translate(QWORD dir, QWORD va);
	BOOL read(QWORD address, PVOID buffer, QWORD length, QWORD* ret);
	BOOL  write(QWORD address, PVOID buffer, QWORD length);
	NTSTATUS MiReadSystemMemory(IN PVOID Source, OUT PVOID Destination, IN SIZE_T NumberOfBytes);
	NTSTATUS MiWriteSystemMemory(IN PVOID Destination, OUT PVOID Source, IN SIZE_T NumberOfBytes);
	NTSTATUS MiReadProcessMemory(IN PEPROCESS process, IN PVOID address, OUT PVOID buffer, IN SIZE_T readSize);
	NTSTATUS  MiWriteProcessMemory(PEPROCESS process, PVOID address, PVOID buffer, SIZE_T length);
}