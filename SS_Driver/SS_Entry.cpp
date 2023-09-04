
#include "ProtectWindow/Protect.hpp"
#include "ProtectWindow/ProtectWindow.hpp"





EXTERN_C NTSTATUS NTAPI Dispatch(PCOMM_DATA pCommData) {
	NTSTATUS status = STATUS_SUCCESS;

	switch (pCommData->Type)
	{
	case TEST_COMM: {
		PTEST_TATA td = (PTEST_TATA)pCommData->InData;
		td->uTest = 0x100000;
		Log("[SSS]TEST %08x \r\n", td->uTest);
		status = STATUS_SUCCESS;
		break;
	}
	case INJECT_DLL: {

		break;
	}
	case PROTECT_PROCESS: {
		Protect::Initialize();
		ProtectWindow::SetProtectWindow();
		PFAKE_PROCESS_DATA  FUCK_PROCESS = (PFAKE_PROCESS_DATA)pCommData->InData;
		status = FakeProcess(FUCK_PROCESS->PID, FUCK_PROCESS->FakePID);
		if (NT_SUCCESS(status))
		{
			Log("FAKE success\n");
			status = Protect::AddProtectPid(FUCK_PROCESS->PID, FUCK_PROCESS->FakePID);
			if (FUCK_PROCESS->MainHWND)
			{
				auto threadId = ProtectWindow::GetWindowThread((HWND)FUCK_PROCESS->MainHWND);
				if (threadId)
				{
					Protect::AddProtectWND((HWND)FUCK_PROCESS->MainHWND, threadId);
					ProtectWindow::AntiSnapWindow(FUCK_PROCESS->MainHWND);
					Log("AntiSnapWindow success\n");
				}
			}
		}
		break;
	}
	case QUERY_MODULE: {
		PQUERY_MODULE_DATA  QUERY_MODULE = (PQUERY_MODULE_DATA)pCommData->InData;
		QUERY_MODULE->pModuleBase = GetProcessModuleInfo(QUERY_MODULE->PID, QUERY_MODULE->pcModuleName, QUERY_MODULE->pModuleSize);

		status = QUERY_MODULE->pModuleBase ? STATUS_SUCCESS : STATUS_UNSUCCESSFUL;
		break;
	}
	case PHY_READ_MEMORY: {
		PRW_MEM_DATA MM_DATA = (PRW_MEM_DATA)pCommData->InData;
		status = SS_ReadMemoryPhy(MM_DATA->PID, MM_DATA->Address, MM_DATA->uDataSize, MM_DATA->pValBuffer);
		break;
	}
	case PHY_WRITE_MEMORY: {
		PRW_MEM_DATA MM_DATA = (PRW_MEM_DATA)pCommData->InData;
		status = SS_WriteMemoryPhy(MM_DATA->PID, MM_DATA->Address, MM_DATA->uDataSize, MM_DATA->pValBuffer);
		break;
	}
	case FAKE_READ_MEMORY: {
		PRW_MEM_DATA MM_DATA = (PRW_MEM_DATA)pCommData->InData;
		status = SS_ReadMemory(MM_DATA->PID, MM_DATA->FakePID, MM_DATA->Address, MM_DATA->uDataSize, MM_DATA->pValBuffer);
		break;
	}
	case FAKE_WRITE_MEMORY: {
		PRW_MEM_DATA MM_DATA = (PRW_MEM_DATA)pCommData->InData;
		status = SS_WriteMemory(MM_DATA->PID, MM_DATA->FakePID, MM_DATA->Address, MM_DATA->uDataSize, MM_DATA->pValBuffer);
		break;
	}

	case WND_PROTECT: {
		Protect::Initialize();
		ProtectWindow::SetProtectWindow();
		PWND_PROTECT_DATA WND_PTDATA = (PWND_PROTECT_DATA)pCommData->InData;
		HANDLE threadId = ProtectWindow::GetWindowThread((HWND)WND_PTDATA->hwnds[0]);
		if (!threadId)
		{
			status = STATUS_UNSUCCESSFUL;
			break;
		}
		Log("GetWindowThread %d \r\n", threadId);
		status = Protect::AddProtectWNDBatch(WND_PTDATA->hwnds, WND_PTDATA->Length, threadId);
		if (!WND_PTDATA->Length)
		{
			status = STATUS_UNSUCCESSFUL;
			break;
		}
		status = ProtectWindow::AntiSnapWindow(WND_PTDATA->hwnds[0]);
		break;
	}
	case CREATE_MEMORY: {
		PCREATE_MEM_DATA MEM_DATA = (PCREATE_MEM_DATA)pCommData->InData;
		status = SS_CreateMemory(MEM_DATA->PID, MEM_DATA->uSize, MEM_DATA->pVAddress);
		break;
	}
	case CREATE_THREAD: {
		PCREATE_THREAD_DATA THREAD_FATA = (PCREATE_THREAD_DATA)pCommData->InData;
		status = MyNtCreateThreadEx(THREAD_FATA->PID, THREAD_FATA->ShellCode, THREAD_FATA->Argument);
		break;
	}

	}
	return status;
}



EXTERN_C NTSTATUS DriverEntry(SIZE_T key, ULONG size) {

	//todo 修改通讯hook NtUserGetPointerProprietaryId
	//添加从物理页表中获取进程信息
	//添加 窗口指定句柄保护 done
	//添加修改物理页属性 done
	//添加申请隐藏内存   done
	//添加内核注入
	//添加内核调用r3 call 
	//添加文件保护
	//添加通过进程名获取进程id
	//保护进程不被注入
	InitOsVersion();
	RegisterComm(Dispatch);

	//ProtectWindow::SetProtectWindow();
	//FakeProcess(6884, 3736);
 
	ProtectWindow::StartProtect();
 


	return  STATUS_SUCCESS;
}

