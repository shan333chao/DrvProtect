#include "../../includes.h"
namespace inject_main {

	/// <summary>
	/// ע��x64dll
	/// </summary>
	/// <param name="dllPath">dll ·��</param>
	/// <param name="targetPid">Ŀ�����id</param>
	/// <param name="type">����</param>
	/// <returns>״̬</returns>
	NTSTATUS inject_x64DLL(PCHAR dllPath, ULONG targetPid,UCHAR type); 
	NTSTATUS WriteDLLx64_dll(PCHAR dllPath, ULONG targetPid, PULONG64 entry, PULONG64 PEimageBase, PULONG64 PEkernelImageBase);
	NTSTATUS KernelCall(ULONG targetPid,ULONG64 entryPoint, ULONG shellcodeLen);
}