#include <ntifs.h>
#include "Comm/Comm.h"
#include "Process/Process.h"
#include "Process/FakeProcess.h"
#include "Memmory/Memory.h"
#include "Thread/SThread.h"
#include "ProtectWindow/Protect.h"
#include "ProtectRoute.h"

EXTERN_C NTSTATUS NTAPI Dispatch(PCOMM_DATA pCommData) {
	NTSTATUS status = STATUS_UNSUCCESSFUL;

	switch (pCommData->Type)
	{
	case TEST_COMM: {
		PTEST_TATA td = (PTEST_TATA)pCommData->InData;
		td->uTest = 0x100000;
		Log("[SSS]TEST %08x \r\n", td->uTest);
		status = STATUS_SUCCESS;
		break;
	}
				  //case INJECT_DLL: {

				  //	break;
				  //}
	case PROTECT_PROCESS: {
		Protect::Initialize();
		ProtectRoute::InitProtectWindow();

		PFAKE_PROCESS_DATA  FUCK_PROCESS = (PFAKE_PROCESS_DATA)pCommData->InData;
		status = fuck_process::FakeProcess(FUCK_PROCESS->PID, FUCK_PROCESS->FakePID);
		if (NT_SUCCESS(status))
		{
			Log("FAKE success\n");
			status = Protect::AddProtectPid(FUCK_PROCESS->PID, FUCK_PROCESS->FakePID);
			if (FUCK_PROCESS->MainHWND)
			{
				auto threadId = ProtectRoute::GetWindowThread((HANDLE)FUCK_PROCESS->MainHWND);
				if (threadId)
				{
					Protect::AddProtectWND((HANDLE)FUCK_PROCESS->MainHWND, threadId);
					ProtectRoute::AntiSnapWindow(FUCK_PROCESS->MainHWND);
					Log("AntiSnapWindow success\n");
				}
			}
		}
		break;
	}
	case QUERY_MODULE: {
		PQUERY_MODULE_DATA  QUERY_MODULE = (PQUERY_MODULE_DATA)pCommData->InData;
		QUERY_MODULE->pModuleBase = process_info::GetProcessModuleInfo(QUERY_MODULE->PID, QUERY_MODULE->pcModuleName, QUERY_MODULE->pModuleSize);

		status = QUERY_MODULE->pModuleBase ? STATUS_SUCCESS : STATUS_UNSUCCESSFUL;
		break;
	}
	case PHY_READ_MEMORY: {
		PRW_MEM_DATA MM_DATA = (PRW_MEM_DATA)pCommData->InData;
		status = memory::SS_ReadMemoryPhy(MM_DATA->PID, MM_DATA->Address, MM_DATA->uDataSize, MM_DATA->pValBuffer);
		break;
	}
	case PHY_WRITE_MEMORY: {
		PRW_MEM_DATA MM_DATA = (PRW_MEM_DATA)pCommData->InData;
		status = memory::SS_WriteMemoryPhy(MM_DATA->PID, MM_DATA->Address, MM_DATA->uDataSize, MM_DATA->pValBuffer);
		break;
	}
	case FAKE_READ_MEMORY: {
		PRW_MEM_DATA MM_DATA = (PRW_MEM_DATA)pCommData->InData;
		status = memory::SS_ReadMemory(MM_DATA->PID, MM_DATA->FakePID, MM_DATA->Address, MM_DATA->uDataSize, MM_DATA->pValBuffer);
		break;
	}
	case FAKE_WRITE_MEMORY: {
		PRW_MEM_DATA MM_DATA = (PRW_MEM_DATA)pCommData->InData;
		status = memory::SS_WriteMemory(MM_DATA->PID, MM_DATA->FakePID, MM_DATA->Address, MM_DATA->uDataSize, MM_DATA->pValBuffer);
		break;
	}

	case WND_PROTECT: {
		Protect::Initialize();
		ProtectRoute::InitProtectWindow();

		PWND_PROTECT_DATA WND_PTDATA = (PWND_PROTECT_DATA)pCommData->InData;
		HANDLE threadId = ProtectRoute::GetWindowThread((HANDLE)WND_PTDATA->hwnds[0]);
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
		status = ProtectRoute::AntiSnapWindow(WND_PTDATA->hwnds[0]);
		break;
	}
	case CREATE_MEMORY: {
		PCREATE_MEM_DATA MEM_DATA = (PCREATE_MEM_DATA)pCommData->InData;
		status = memory::SS_CreateMemory(MEM_DATA->PID, MEM_DATA->uSize, MEM_DATA->pVAddress);
		break;
	}
	case CREATE_THREAD: {
		PCREATE_THREAD_DATA THREAD_FATA = (PCREATE_THREAD_DATA)pCommData->InData;
		status = sthread::MyNtCreateThreadEx(THREAD_FATA->PID, THREAD_FATA->ShellCode, THREAD_FATA->Argument);
		break;
	}

	}
	return status;
}





#if 0
EXTERN_C VOID DriverUnload(PDRIVER_OBJECT pDriver) {
	UNREFERENCED_PARAMETER(pDriver);
	ProtectRoute::RemoveProtectWindow();

}
EXTERN_C ULONG_PTR GetNtoskrlImageBase(PDRIVER_OBJECT pdriver) {
	PLDR_DATA_TABLE_ENTRY current = (PLDR_DATA_TABLE_ENTRY)pdriver->DriverSection;
	ULONG_PTR imageBase = 0;
	while (1)
	{
		Log("%wZ   %p  %11x \r\n", current->BaseDllName, current->DllBase, current->SizeOfImage);
		if (!current->SizeOfImage)
		{
			current = (PLDR_DATA_TABLE_ENTRY)current->InLoadOrderLinks.Flink;
			Log("%wZ   %p  %11x \r\n", current->BaseDllName, current->DllBase, current->SizeOfImage);
			imageBase = current->DllBase;
			break;
		}
		current = (PLDR_DATA_TABLE_ENTRY)current->InLoadOrderLinks.Flink;
	}
	return imageBase;
}
EXTERN_C NTSTATUS DriverEntry(PDRIVER_OBJECT pdriver, PUNICODE_STRING reg) {
	pdriver->DriverUnload = DriverUnload;
	ULONG_PTR imageBase = GetNtoskrlImageBase(pdriver);
	Utils::SetKernelBase(imageBase);
	Utils::InitApis();
	if (Utils::InitOsVersion().dwBuildNumber > 7601)
	{
		ProtectRoute::SetCommHook(Dispatch);
	}
	else {
		communicate::RegisterComm(Dispatch);
	}
	ProtectRoute::StartProtect();
	return  STATUS_SUCCESS;
}
#else

EXTERN_C NTSTATUS DriverEntry(ULONG_PTR NtoskrlImageBase, PUNICODE_STRING reg) { 
	Utils::SetKernelBase(NtoskrlImageBase);
	Utils::InitApis();
	if (Utils::InitOsVersion().dwBuildNumber > 7601)
	{
		ProtectRoute::SetCommHook(Dispatch);
	}
	else {
		communicate::RegisterComm(Dispatch);
	}
	ProtectRoute::StartProtect();
	Log("start success %p \r\n", NtoskrlImageBase);
	return  STATUS_SUCCESS;
}
#endif // 0

