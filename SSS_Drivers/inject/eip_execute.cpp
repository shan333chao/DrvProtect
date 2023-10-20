#include "eip_execute.h"
#include "../../SSDT/Functions.h"
#include "../../Memmory/Memory.h"
#define DLL_PROCESS_ATTACH   1  

namespace eip_execute {

	static SuspendResumeThread KeSuspendThread = NULL;
	static SuspendResumeThread KeResumeThread = NULL;


	BOOLEAN initKethreadFunc()
	{

		if (KeSuspendThread && KeResumeThread)
		{
			return TRUE;
		}
		PVOID NtSuspendThreadAddr = ssdt_serv::GetFunctionAddrInSSDT(functions::GetNtSuspendThreadServNo());
		PVOID NtResumeThreadAddr = ssdt_serv::GetFunctionAddrInSSDT(82);

		ULONGLONG PsSuspendThreadAddr = functions::GetFuncAddrInAddr((PUCHAR)NtSuspendThreadAddr, 0x78, 0xe8);
		ULONGLONG PsResumeThreadAddr = functions::GetFuncAddrInAddr((PUCHAR)NtResumeThreadAddr, 0x78, 0xe8);
		ULONG64 addr = Utils::find_pattern(PsSuspendThreadAddr,
			0x100,
			skCrypt("\xE8\x00\x00\x00\x00\x89\x44\x00\x00\x33\xDB\x89\x5C\x00\x00"),
			skCrypt("x????xx??xxxx??"),
			strlen_imp(skCrypt("x????xx??xxxx??")));
		if (!addr)
		{
			return FALSE;
		}
		LONG64 offset = *(PLONG32)(addr + 1);
		KeSuspendThread = (SuspendResumeThread)(addr + 5 + offset);
		Log("KeSuspendThread %p \r\n", KeSuspendThread);

		if (Utils::InitOsVersion().dwBuildNumber >= 22000)
		{
			ULONGLONG PsMultiResumeThreadAddr = functions::GetFuncAddrInAddr((PUCHAR)PsSuspendThreadAddr, 0x00, 0xe8);
			KeResumeThread = (SuspendResumeThread)functions::GetFuncAddrInAddr((PUCHAR)PsSuspendThreadAddr, 0xE9, 0xe8);
		}
		else
		{
			KeResumeThread = (SuspendResumeThread)functions::GetFuncAddrInAddr((PUCHAR)PsResumeThreadAddr, 0xF9, 0xe8);
		}

		Log("KeResumeThread %p \r\n", KeResumeThread);
		return TRUE;
	}
	//�ж��ǲ���GUI�߳�
	bool IsGuiThread(PETHREAD thread) {
		PUCHAR pteb64 = (PUCHAR)imports::ps_get_thread_teb(thread);
		if (!pteb64)
		{
			return false;
		}
		//_TEB64+ 0x78  = Win32ThreadInfo;  
		if (*(PULONG64)(pteb64 + 0x78) != 0) {
			return true;
		}

		return false;
	}

	PETHREAD GetFirstThread(PEPROCESS pEprocess) {
		//windows��ͳ���ڳ��������һ��������GUI�߳�



		PETHREAD pretthreadojb = NULL, ptempthreadobj = NULL;

		PLIST_ENTRY plisthead = NULL;

		PLIST_ENTRY plistflink = NULL;

		int i = 0;

		plisthead = (PLIST_ENTRY)((PUCHAR)pEprocess + 0x30);

		plistflink = plisthead->Flink;

		//����
		for (plistflink; plistflink != plisthead; plistflink = plistflink->Flink)
		{
			ptempthreadobj = (PETHREAD)((PUCHAR)plistflink - 0x2f8);

			HANDLE threadId = PsGetThreadId(ptempthreadobj);

			Logf("�߳�ID: %d", threadId);



			if (!MmIsAddressValid(ptempthreadobj)) {
				continue;
			}

			i++;

			if (imports::ps_get_thread_win_thread(ptempthreadobj)) {
				pretthreadojb = ptempthreadobj;
				break;
			}

		}



		return pretthreadojb;
	}

	KTRAP_FRAME MyGetThreadContext(PETHREAD thread)
	{
		//_ETHREAD-> _KTHREAD+0x90 TrapFrame;                                         
		PKTRAP_FRAME threadContext = (PKTRAP_FRAME) * (PULONG64)((ULONG64)thread + 0x90);
		return *threadContext;
	}

	bool MySetThreadContext(PETHREAD thread, KTRAP_FRAME context)
	{
		//_ETHREAD-> _KTHREAD+0x90 TrapFrame;     
		PKTRAP_FRAME threadContext = (PKTRAP_FRAME) * (PULONG64)((ULONG64)thread + 0x90);
		*threadContext = context;
		return true;
	}

	void EipExcute_x64dll(PEPROCESS process, PVOID entrypoint, ULONG64 R3_modulebase, ULONG64 R0_imageBase, LONGLONG cleartimeSecond)
	{

		if (!initKethreadFunc()) {
			return;
		}

		if (imports::ps_get_process_exit_process_called(process))
		{
			return;
		}

		if (!KeSuspendThread || !KeResumeThread) {
			Logf("KeSuspendThread �� KeResumeThread δ�ҵ�");
			return;
		}

		//��ѡ��һ���߳�
		PETHREAD thread = GetFirstThread(process);

		PVOID peb32 = imports::ps_get_process_wow64_process(process);
		MODE preMode = functions::SetThreadPrevious(imports::ke_get_current_thread(), KernelMode);

		//�����߳�
		KeSuspendThread(thread);
		functions::SetThreadPrevious(imports::ke_get_current_thread(), preMode);

		//��ȡ�Ĵ���������
		KTRAP_FRAME context = MyGetThreadContext(thread);
		ULONG shellcodeLength = 0;

		/*
			push rcx
			push rax
			mov rdx,00000001 //�ڶ�������DLL_PROCESS_ATTACH
			mov rax,entryaddr //��ַ
			sub rsp,28
			call rax
			add rsp,28
			pop rax
			pop rcx
			jmp rip  //rip�Ĵ�����ֵ

		*/
		//����shellcode
		//BYTE shellcode[] = {
		//	0x51, 0x50, 0x48 ,0xBA, 0x00 ,0x00 ,0x00, 0x00, 0x00, 0x00, 0x00 ,0x00 ,
		//	0x48 ,0xB8 ,0x00 ,0x00 ,0x00 ,0x00 ,0x00 ,0x00 ,0x00 ,0x00 ,0x48, 0x83 ,0xEC,
		//	0x28 ,0xFF ,0xD0 ,0x48 ,0x83 ,0xC4 ,0x28 ,0x58 ,0x59 ,0xFF ,0x25 ,0x00 ,0x00,
		//	0x00 ,0x00 ,0x00 ,0x00 ,0x00 ,0x00 ,0x00 ,0x00 ,0x00 ,0x00
		//};

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
			0xFF,0x25,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00//jmp Rip
		};

		//BOOL APIENTRY DllMain(HMODULE hModule,
		//	DWORD  ul_reason_for_call,
		//	LPVOID lpReserved
		//)
		shellcodeLength = sizeof(shellcode);
		//�������
		*(PULONG64)(shellcode + 4) = R3_modulebase;
		*(PULONG64)(shellcode + 14) = DLL_PROCESS_ATTACH;
		*(PULONG64)(shellcode + 24) = (ULONG64)entrypoint;
		*(PULONG64)(shellcode + shellcodeLength - 8) = context.Rip;
		Utils::kmemcpy((PVOID)R0_imageBase, shellcode, shellcodeLength);

		//����ripָ��shellcode ��ַ
		//�������Ǹ��� ֮ǰ���뵽��PEͷ�� �ռ�
		//����R3��R0 ָ����ͬ������ҳ  ����shellcode ֱ��ʹ��PEͷ��Ϊ��ʼ��ַ
		context.Rip = R3_modulebase;
		MySetThreadContext(thread, context);

		preMode = functions::SetThreadPrevious(imports::ke_get_current_thread(), KernelMode);
		//�ָ��߳� 
		KeResumeThread(thread);
		functions::SetThreadPrevious(imports::ke_get_current_thread(), preMode);

		//�ȴ�cleartimeSecond�룬���shellcode
		Utils::sleep(cleartimeSecond * 1000);
		//���shellcode r0 ��r3  ָ����ͬ������ҳ  
		Utils::kmemset((PVOID)R0_imageBase, 0x0, shellcodeLength);

		Log("shellcode ��գ�\r\n");
	}


	BOOLEAN EipExcuteShellcode(PEPROCESS process, ULONG64 shellcode_addr, ULONG shellcode_len, LONGLONG cleartimeSecond)
	{
		if (imports::ps_get_process_exit_process_called(process))
		{
			return FALSE;
		}
		if (!initKethreadFunc())
		{
			return FALSE;
		}

		if (!KeSuspendThread || !KeResumeThread) {
			Logf("KeSuspendThread �� KeResumeThread δ�ҵ�");
			return FALSE;
		}
		UCHAR ShellcodePacket[] = {
				0x48,0x83,0xEC,0x28,								//sub rsp,28
				0x50,
				0x48,0xB8,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,	//mov rax,0xffffffffffffffff
				0xFF,0xD0,											//call rax
				0x58,
				0x48,0x83,0xC4,0x28,								//add rsp,28

				0x50,												//push rax
				0x48,0xB8,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,	//mov rax, 0xffffffffffffffff
				0x48,0x87,0x04,0x24,								//xchg qword [rsp], rax
				0xC3												//ret
		};
		ULONG64 ShellcodeAddress;
	 
		SIZE_T AllocationSize;
 
		AllocationSize = shellcode_len + sizeof(ShellcodePacket)+0x10;
		ULONG64 r3Addr = 0;
		ULONG64 r0Addr = 0;
		MDL mdl = { 0 };
		NTSTATUS status = memory::CreateMemory(process, AllocationSize, &r3Addr, &r0Addr, &mdl);

		if (!NT_SUCCESS(status))
		{
 
			return FALSE;
		}

		//��ѡ��һ���߳�
		PETHREAD thread = GetFirstThread(process); 
		//�����߳�
		KeSuspendThread(thread);  
		//��ȡ�Ĵ���������
		KTRAP_FRAME context = MyGetThreadContext(thread); 
		ShellcodeAddress = (ULONG64)r3Addr + sizeof(ShellcodePacket);
		*(PULONG64)(ShellcodePacket + 7) = ShellcodeAddress;
		*(PULONG64)(ShellcodePacket + 25) = context.Rip;
		Utils::kmemcpy((PVOID)r0Addr, ShellcodePacket, sizeof(ShellcodePacket));
		Utils::kmemcpy((PVOID)(r0Addr + sizeof(ShellcodePacket)), (PVOID)shellcode_addr, shellcode_len); 
		context.Rip = r3Addr;
		MySetThreadContext(thread, context);

		//�ָ��߳�
		KeResumeThread(thread);

		//�ȴ�30�룬���shellcode
		Utils::sleep(cleartimeSecond * 1000);
		Log("shellcode ִ�����\r\n");
	}
}