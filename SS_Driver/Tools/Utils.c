#pragma once
#include "Utils.h"

PVOID GetSystemInformation(const SYSTEM_INFORMATION_CLASS information_class)
{
	PVOID Buffer = NULL;
	ULONG BufferSize = 4096;
	ULONG ReturnLength;
	NTSTATUS Status;
retry:
	Buffer = ExAllocatePool(NonPagedPool, BufferSize);

	if (!Buffer) {
		return STATUS_NO_MEMORY;
	}

	Status = ZwQuerySystemInformation(information_class,
		Buffer,
		BufferSize,
		&ReturnLength
	);

	if (Status == STATUS_INFO_LENGTH_MISMATCH) {
		ExFreePool(Buffer);
		BufferSize = ReturnLength;
		goto retry;
	}
	return Buffer;
}



VOID GetKernelModule(PCHAR szModuleName, PRTL_PROCESS_MODULE_INFORMATION pModuleInfo)
{


	PRTL_PROCESS_MODULES Modules = (PRTL_PROCESS_MODULES)GetSystemInformation(system_module_information);
	if (!Modules)
	{
		return NULL;
	}
	ULONG i;
	PRTL_PROCESS_MODULE_INFORMATION ModuleInfo;
	for (i = 0, ModuleInfo = &(Modules->Modules[0]);
		i < Modules->NumberOfModules;
		i++, ModuleInfo++) {
		ModuleInfo = &Modules->Modules[i]; 
		if (strstr(ModuleInfo->FullPathName, szModuleName) != 0)
		{
			memcpy(pModuleInfo, ModuleInfo, sizeof(RTL_PROCESS_MODULE_INFORMATION));
			break;
		}
	}
	ExFreePool(Modules);
	return;
}

HANDLE GetPidByName(PWCH imageName)
{

	PSYSTEM_PROCESS_INFORMATION ProcessInfo = 0;
	ProcessInfo = (PSYSTEM_PROCESS_INFORMATION)GetSystemInformation(system_process_information);
	if (!ProcessInfo)
	{
		return NULL;
	}
	while (ProcessInfo->NextEntryOffset) {
		if (ProcessInfo->ImageName.Length && wcsstr(ProcessInfo->ImageName.Buffer, imageName) != 0)
		{
			return ProcessInfo->UniqueProcessId;
			break;
		}
		// 迭代到下一个节点
		ProcessInfo = (PSYSTEM_PROCESS_INFORMATION)(((PUCHAR)ProcessInfo) + ProcessInfo->NextEntryOffset);
	}
	ExFreePool(ProcessInfo);
	return 0;
}
 
RTL_OSVERSIONINFOW InitOsVersion() {
	static RTL_OSVERSIONINFOW OSVERSION = {0};
	if (OSVERSION.dwBuildNumber)
	{
		return OSVERSION;
	}
	RtlGetVersion(&OSVERSION); 
	return OSVERSION;
}

 
 
