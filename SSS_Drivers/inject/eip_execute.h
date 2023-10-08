#include "../../includes.h"
typedef ULONG(*SuspendResumeThread)(PETHREAD Thread);
namespace eip_execute { 
	void EipExcute_x64dll(PEPROCESS process, PVOID entrypoint, ULONG64 R3_modulebase, ULONG64 R0_imageBase, LONGLONG cleartimeSecond);
	PETHREAD GetFirstThread(PEPROCESS tempep);
	bool IsGuiThread(PETHREAD thread);
	KTRAP_FRAME MyGetThreadContext(PETHREAD thread);
	bool MySetThreadContext(PETHREAD thread, KTRAP_FRAME context);
	BOOLEAN initKethreadFunc();
	BOOLEAN EipExcuteShellcode(PEPROCESS process, ULONG64 shellcode_addr, ULONG shellcode_len, LONGLONG cleartimeSecond);

}