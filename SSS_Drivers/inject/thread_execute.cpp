#include "thread_execute.h"
#include "../SSDT/Functions.h"

NTSTATUS   CreateInjectThread(PEPROCESS pEprocess,ULONG64 moduleBase,ULONG64 entryPoint,ULONG64 kernelModuleBase  ) {
 
	NTSTATUS status = STATUS_UNSUCCESSFUL;
	if (!moduleBase||!entryPoint)
	{
		return status;
			
	}
	PVOID peb32 = imports::ps_get_process_wow64_process(pEprocess);
	if (!peb32)
	{
		UCHAR shellcode[] = {
		0x51,	//push rcx
		0x50,	//push rax
		0x48,0xB9,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00 ,//mov rcx,modulebase
		0x48,0xBA,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00 ,//mov rdx,DLL_PROCESS_ATTACH
		0x48,0xB8,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00 ,//mov rax,entryaddr
		0x48,0x83,0xEC,0x28,								//sub rsp,28
		0xFF,0xD0,											//call rax
		0x48,0x83,0xC4,0x28,								//add rsp,28
		0x58,												//pop rax
		0x59,												//pop rcx 
		};
		*(PULONG64)(shellcode + 4) = moduleBase;
		*(PULONG64)(shellcode + 14) = 1;
		*(PULONG64)(shellcode + 24) = entryPoint;
		Utils::kmemcpy((PVOID)kernelModuleBase, shellcode, sizeof(shellcode));
	}
	else
	{
		uint8_t shellcode[]
		{
			0x9C,                           // pushfd   push flags
			0x60,                           // pushad   push registers
			0x68, 0x00, 0x00, 0x00, 0x00,   // push     nullptr (0x0)
			0x68, 0x01, 0x00, 0x00, 0x00,   // push     DLL_PROCESS_ATTACH (0x1)
			0x68, 0x00, 0x00, 0x00, 0x00,   // push     0x00000000
			0xB8, 0x00, 0x00, 0x00, 0x00,   // mov      eax 0x00000000
			0xFF, 0xD0,	                    // call     eax
			0x61,                           // popad    pop registers	
			0x9D,                           // popfd    pop flags
			0xC3                            // ret
		};

		*(uintptr_t*)(shellcode + 13) = moduleBase;
		*(uintptr_t*)(shellcode + 18) = entryPoint;
		Utils::kmemcpy((PVOID)kernelModuleBase, shellcode, sizeof(shellcode));
	}






	KAPC_STATE apcState = { 0 };

	HANDLE hThread = NULL;
	PNtCreateThreadEx pNtCrteateThread = functions::GetNtCreateThreadEx();
	if (!pNtCrteateThread)
	{
		return STATUS_UNSUCCESSFUL;
	}
 
	Utils::AttachProcess(pEprocess);
	//imports::ke_stack_attach_process(pEprocess, &apcState);
	MODE oldMode = functions::SetThreadPrevious(KeGetCurrentThread(), KernelMode);
	status = pNtCrteateThread(&hThread, THREAD_ALL_ACCESS, NULL, NtCurrentProcess(), (PVOID)moduleBase, NULL, NULL, NULL, NULL, NULL, NULL);
	functions::SetThreadPrevious(KeGetCurrentThread(), oldMode);
	//imports::ke_unstack_detach_process(&apcState);
	Utils::DetachProcess();
	return status;



}