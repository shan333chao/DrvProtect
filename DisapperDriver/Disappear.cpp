#pragma once
#include <ntifs.h>
EXTERN_C_START
#include "LoadDriver/LoadDriver.h"
EXTERN_C_END
#include "ClearTrace/utils.hpp"
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

EXTERN_C NTSTATUS DriverEntry(PDRIVER_OBJECT pDriver, PUNICODE_STRING pReg) {
 
	PUCHAR imageBase=LoadDriver(pDriver, pReg);
	ClearDriverTrace(pDriver);
	ClearPeSection(imageBase);
	return  STATUS_DATA_ERROR;
}