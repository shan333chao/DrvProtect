#include "../includes.h"
#include "../SSDT/Functions.h"
namespace MiMemory {
	NTSTATUS MiReadSystemMemory(IN PVOID Source, OUT PVOID Destination, IN SIZE_T NumberOfBytes);
	NTSTATUS MiWriteSystemMemory(IN PVOID Destination, OUT PVOID Source, IN SIZE_T NumberOfBytes);
	NTSTATUS MiReadProcessMemory(IN PEPROCESS Process, IN PVOID Source, OUT PVOID Destination, IN SIZE_T NumberOfBytes);
	NTSTATUS MiWriteProcessMemory(IN PEPROCESS Process, IN PVOID Destination, OUT PVOID Source, IN SIZE_T NumberOfBytes);
}