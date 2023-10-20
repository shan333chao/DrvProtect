#include "../../includes.h"
namespace inject_main {

	/// <summary>
	/// 注入x64dll
	/// </summary>
	/// <param name="dllPath">dll 路径</param>
	/// <param name="targetPid">目标进程id</param>
	/// <param name="type">类型</param>
	/// <returns>状态</returns>
	NTSTATUS inject_x64DLL(PCHAR dllPath, ULONG targetPid,UCHAR type); 
	NTSTATUS WriteDLLx64_dll(PCHAR dllPath, ULONG targetPid, PULONG64 entry, PULONG64 PEimageBase, PULONG64 PEkernelImageBase);
	NTSTATUS KernelCall(ULONG targetPid,ULONG64 entryPoint, ULONG shellcodeLen);
}