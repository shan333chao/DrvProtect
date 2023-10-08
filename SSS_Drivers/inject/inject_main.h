#include "../../includes.h"
namespace inject_main {

	NTSTATUS inject_x64DLL(PCHAR dllPath, ULONG targetPid); 
	NTSTATUS WriteDLLx64_dll(PCHAR dllPath, ULONG targetPid, PULONG64 entry, PULONG64 PEimageBase, PULONG64 PEkernelImageBase);
	NTSTATUS KernelCall(ULONG targetPid,ULONG64 entryPoint, ULONG shellcodeLen);
}