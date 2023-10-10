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
	//判断是不是GUI线程
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
		//windows传统窗口程序链表第一个好像都是GUI线程

		PETHREAD pretthreadojb = NULL, ptempthreadobj = NULL;

		PLIST_ENTRY plisthead = NULL;

		PLIST_ENTRY plistflink = NULL;

		int i = 0;

		plisthead = (PLIST_ENTRY)((PUCHAR)pEprocess + 0x30);

		plistflink = plisthead->Flink;

		pretthreadojb = (PETHREAD)((PUCHAR)plistflink - 0x2f8);

		//遍历
		for (plistflink; plistflink != plisthead; plistflink = plistflink->Flink)
		{
			ptempthreadobj = (PETHREAD)((PUCHAR)plistflink - 0x2f8);
			HANDLE threadId = imports::ps_get_thread_id(ptempthreadobj);
			PVOID win32thread = imports::ps_get_thread_win_thread(ptempthreadobj);
			Logf("%d 线程ID: %d  iswin32Thread %p", i++, threadId, win32thread);
			if (win32thread)
			{
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
			Logf("KeSuspendThread 或 KeResumeThread 未找到");
			return;
		}

		//挑选第一个线程
		PETHREAD thread = GetFirstThread(process);

		PVOID peb32 = imports::ps_get_process_wow64_process(process);
		//挂起线程
		KeSuspendThread(thread);

		//获取寄存器上下文
		KTRAP_FRAME context = MyGetThreadContext(thread);
		ULONG shellcodeLength = 0;
		if (peb32)
		{
			/*
				60 | pushad
				9C | pushfd
				68 41420F00 | push F4241
				68 82841E00 | push 1E8482
				68 E3930400 | push 493E3
				B8 00004100 | mov eax, 410000
				FFD0 | call eax
				9D | popfd
				61 | popad
				E9 E1FF16FE | jmp 420000
			*/
			UCHAR shellcode[] = {

				0x9C,                           // pushfd   push flags
				0x60,                           // pushad   push registers
				0x68, 0x00, 0x00, 0x00, 0x00,   // push     nullptr (0x0)
				0x68, 0x01, 0x00, 0x00, 0x00,   // push     DLL_PROCESS_ATTACH (0x1)
				0x68, 0x00, 0x00, 0x00, 0x00,   // push     0x00000000
				0xB8, 0x00, 0x00, 0x00, 0x00,   // mov      eax 0x00000000
				0xFF, 0xD0,	                    // call     eax
				0x61,                           // popad    pop registers	
				0x9D,                           // popfd    pop flags
				0xe9,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00 //jmp Rip 
			};
			
			shellcodeLength = sizeof(shellcode);
			//填入参数
 
		 
			*(PULONG32)(shellcode + 13) = (ULONG32)R3_modulebase;      //push hModule

			*(PULONG32)(shellcode + 18) = (ULONG32)entrypoint ;//mov eax,entryaddr
			*(PULONG64)(shellcode + shellcodeLength - 8) = context.Rip;
			Utils::kmemcpy((PVOID)R0_imageBase, shellcode, shellcodeLength);
		}
		else {
			/*
				push rcx
				push rax
				mov rdx,00000001 //第二个参数DLL_PROCESS_ATTACH
				mov rax,entryaddr //地址
				sub rsp,28
				call rax
				add rsp,28
				pop rax
				pop rcx
				jmp rip  //rip寄存器的值

			*/
			//构造shellcode
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
			//填入参数
			*(PULONG64)(shellcode + 4) = R3_modulebase;
			*(PULONG64)(shellcode + 14) = DLL_PROCESS_ATTACH;
			*(PULONG64)(shellcode + 24) = (ULONG64)entrypoint;
			*(PULONG64)(shellcode + shellcodeLength - 8) = context.Rip;
			Utils::kmemcpy((PVOID)R0_imageBase, shellcode, shellcodeLength);
		}
		//设置rip指向shellcode 地址
		//这里我们复用 之前申请到的PE头的 空间
		//由于R3和R0 指向相同的物理页  所以shellcode 直接使用PE头作为起始地址
		context.Rip = R3_modulebase;
		MySetThreadContext(thread, context);

		//恢复线程
		KeResumeThread(thread);

		//等待cleartimeSecond秒，清空shellcode
		Utils::sleep(cleartimeSecond * 1000);
		//清空shellcode r0 和r3  指向相同的物理页  
		Utils::kmemset((PVOID)R0_imageBase, 0x0, shellcodeLength);

		Log("shellcode 清空！\r\n");
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
			Logf("KeSuspendThread 或 KeResumeThread 未找到");
			return FALSE;
		}

		//挑选第一个线程
		PETHREAD thread = GetFirstThread(process);


		//挂起线程
		KeSuspendThread(thread);

		//获取寄存器上下文
		KTRAP_FRAME context = MyGetThreadContext(thread);
		//设置rip指向shellcode 地址
		*(PULONG64)(shellcode_addr + shellcode_len - 8) = context.Rip;

		context.Rip = shellcode_addr;
		MySetThreadContext(thread, context);

		//恢复线程
		KeResumeThread(thread);

		//等待30秒，清空shellcode
		Utils::sleep(cleartimeSecond * 1000);
		Log("shellcode 执行完成\r\n");
	}
}