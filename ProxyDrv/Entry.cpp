#include "LoadDriver/LoadDriver.h"
#include "ClearTrace/trace.hpp"

EXTERN_C VOID ClearDriverTrace(PDRIVER_OBJECT pDriver) {
	ULONG64 uDriverImageBase = (ULONG64)pDriver->DriverStart;
	PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)pDriver->DriverStart;
	PIMAGE_NT_HEADERS64 pNts = (PIMAGE_NT_HEADERS64)(uDriverImageBase + pDos->e_lfanew);
	ULONG driverTimeDateStamp = pNts->FileHeader.TimeDateStamp;
	WCHAR fileExt[] = L".sys";

	WCHAR driverFullName[50] = { 0 };
	memcpy(driverFullName, pDriver->DriverExtension->ServiceKeyName.Buffer, pDriver->DriverExtension->ServiceKeyName.Length);
	memcpy(driverFullName + pDriver->DriverExtension->ServiceKeyName.Length / sizeof(wchar_t), fileExt, sizeof(fileExt));
	trace::clear_cache(driverFullName, driverTimeDateStamp);
	trace::clear_unloaded_driver(driverFullName);
	trace::clear_hash_bucket_list(driverFullName);
	trace::clear_ci_ea_cache_lookaside_list();
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

EXTERN_C NTSTATUS DriverEntry(PDRIVER_OBJECT pDriver, PUNICODE_STRING pReg) {
	ULONG_PTR NtoskrlImageBase = GetNtoskrlImageBase(pDriver);
	Utils::SetKernelBase(NtoskrlImageBase);
	Utils::InitApis();

	LoadDrv::DestroyDriverFile(&((PLDR_DATA_TABLE_ENTRY)pDriver->DriverSection)->FullDllName);
	//É¾³ý×¢²á±í
	LoadDrv::DeleteRegeditEntry(pReg);
	PUCHAR drvImageBase = LoadDrv::LoadDriver(pDriver, pReg);
	ClearDriverTrace(pDriver);
	LoadDrv::ClearPeSection(drvImageBase);
	return  STATUS_DATA_ERROR;
}