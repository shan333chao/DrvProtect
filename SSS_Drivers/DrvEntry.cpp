#include <ntifs.h>
#include "Comm/Comm.h"
#include "Process/Process.h"
#include "Process/FakeProcess.h"
#include "Memmory/Memory.h"
#include "Thread/SThread.h"
#include "ProtectWindow/Protect.h"
#include "ProtectRoute.h"
constexpr unsigned int max_unloader_driver = 50;
typedef struct _unloader_information
{
	UNICODE_STRING name;
	PVOID module_start;
	PVOID module_end;
	ULONG64 unload_time;
} unloader_information, * punloader_information;

EXTERN_C void clear_unloaded_driver()
{
	unsigned long long ntoskrnl_address = 0;
	ntoskrnl_address = (ULONGLONG)Utils::GetKernelBase();
	Log("[%s] ntoskrnl address 0x%llx\n", __FUNCTION__, ntoskrnl_address);
	if (ntoskrnl_address == 0) return;

	/*
	 * MmLocateUnloadedDriver proc near
	 * 4C 8B 15 ? ? ? ? 4C 8B C9
	 * mov     r10, cs:MmUnloadedDrivers
	 * mov     r9, rcx
	 * test    r10, r10
	 * jz      short loc_1402C4573
	 */
	unsigned long long MmUnloadedDrivers = Utils::find_pattern_image(ntoskrnl_address,
		"\x4C\x8B\x15\x00\x00\x00\x00\x4C\x8B\xC9",
		skCrypt("xxx????xxx"));
	if (MmUnloadedDrivers == 0) return;
	MmUnloadedDrivers = reinterpret_cast<unsigned long long>(reinterpret_cast<char*>(MmUnloadedDrivers) + 7 + *reinterpret_cast<int*>(reinterpret_cast<char*>(MmUnloadedDrivers) + 3));
	Log("[%s] MmUnloadedDrivers address 0x%llx\n", __FUNCTION__, MmUnloadedDrivers);

	/*
	 * MiRememberUnloadedDriver proc near
	 * 8B 05 ? ? ? ? 83 F8 32
	 * mov     eax, cs:MmLastUnloadedDriver
	 * cmp     eax, 32h
	 * jnb     loc_140741D32
	 */
	unsigned long long MmLastUnloadedDriver = Utils::find_pattern_image(ntoskrnl_address,
		"\x8B\x05\x00\x00\x00\x00\x83\xF8\x32",
		skCrypt("xx????xxx"));
	if (MmLastUnloadedDriver == 0) return;
	MmLastUnloadedDriver = reinterpret_cast<unsigned long long>(reinterpret_cast<char*>(MmLastUnloadedDriver) + 6 + *reinterpret_cast<int*>(reinterpret_cast<char*>(MmLastUnloadedDriver) + 2));
	Log("[%s] MmLastUnloadedDriver address 0x%llx \n", __FUNCTION__, MmLastUnloadedDriver);

	punloader_information unloaders = *(punloader_information*)MmUnloadedDrivers;
	unsigned long* unloaders_count = (unsigned long*)MmLastUnloadedDriver;
	if (imports::mm_is_address_valid(unloaders) == FALSE || imports::mm_is_address_valid(unloaders_count) == FALSE) return;

	static ERESOURCE PsLoadedModuleResource;
	if (imports::ex_acquire_resource_exclusive_lite(&PsLoadedModuleResource, TRUE))
	{
		int index = 0;
		unsigned long i = 0;
		for (; i < *unloaders_count && i < max_unloader_driver; i++)
		{
			unloader_information& t = unloaders[i];
			Log("[%s] %.2d %wZ \n", __FUNCTION__, i, t.name);
			index = i;
		}
		unloader_information& pret = unloaders[index - 1];
		unloader_information& endt = unloaders[index];

		Log("change [%s] %.2d %wZ \n", __FUNCTION__, index - 1, pret.name);
		Log("change [%s] %.2d %wZ \n", __FUNCTION__, index, endt.name);
		endt.module_start = pret.module_start;
		endt.module_end = pret.module_end;
		endt.unload_time = pret.unload_time;
		endt.name.Buffer = pret.name.Buffer;
		endt.name.Length = pret.name.Length;
		endt.name.MaximumLength = pret.name.MaximumLength;
		imports::ex_release_resource_lite(&PsLoadedModuleResource);
	}


}
EXTERN_C NTSTATUS NTAPI Dispatch(PCOMM_DATA pCommData) {
	NTSTATUS status = STATUS_UNSUCCESSFUL;
	if (pCommData->Type > 0)
	{
		if (!ProtectRoute::ValidateReg())
		{
			pCommData->status = status;
			return status;
		}
	}
	switch (pCommData->Type)
	{
	case TEST_COMM: {

		PTEST_TATA td = (PTEST_TATA)pCommData->InData;
		td->uTest = ProtectRoute::SetValidate(td->regCode, td->size, td->time);
		Log("[SSS]TEST %08x \r\n", td->uTest);
		clear_unloaded_driver();
		status = STATUS_SUCCESS;
		break;
	}
				  //case INJECT_DLL: {

				  //	break;
				  //}
	case PROTECT_PROCESS: {
		PFAKE_PROCESS_DATA  FUCK_PROCESS = (PFAKE_PROCESS_DATA)pCommData->InData;
		status = fuck_process::FakeProcess(FUCK_PROCESS->PID, FUCK_PROCESS->FakePID);
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

