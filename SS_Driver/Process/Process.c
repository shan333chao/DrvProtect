#pragma once
#include "Process.h"

ULONG_PTR GetProcessModuleInfo(ULONG pid, PCHAR pcModuleName, PULONG pModuleSize)
{
	PVOID									pIsx86Process;
	PEPROCESS								pTargetEprocess = NULL;
	NTSTATUS								status = NULL;
	ULONG_PTR								uImageBase = 0;
	if (strlen(pcModuleName)==0)
	{
		return 0;
	}
	status = PsLookupProcessByProcessId((HANDLE)pid, &pTargetEprocess);
	if (!NT_SUCCESS(status)) return status;
	//判断进程状态
	status = PsGetProcessExitStatus(pTargetEprocess);
	if (status != STATUS_PENDING) {
		ObDereferenceObject(pTargetEprocess);
		return status;
	}
	ANSI_STRING aName = { 0 };
	RtlInitAnsiString(&aName, pcModuleName);
 
	UNICODE_STRING moduleNameMem = { 0 };
	//moduleNameMem.Buffer = ExAllocatePool(NonPagedPool, aName.MaximumLength*2);
	RtlAnsiStringToUnicodeString(&moduleNameMem, &aName, TRUE);

	//memcpy(moduleNameMem.Buffer, moduleName.Buffer, moduleName.Length);
	//moduleNameMem.Length = moduleName.Length;
	//moduleNameMem.MaximumLength = moduleName.MaximumLength;
	pIsx86Process = PsGetProcessWow64Process(pTargetEprocess);
	ULONG moduleSize = 0;
	ULONG_PTR moduleBase = 0;
	if (pIsx86Process)
	{
		moduleBase = GetX86ProcessModule(pTargetEprocess, &moduleNameMem, &moduleSize);
	}
	else {
		moduleBase = GetX64ProcessModule(pTargetEprocess, &moduleNameMem, &moduleSize);
	}
	*pModuleSize = moduleSize;
	ObDereferenceObject(pTargetEprocess);
	RtlFreeUnicodeString(&moduleNameMem);
	return moduleBase;
}
ULONG_PTR GetX86ProcessModule(PEPROCESS	pTargetEprocess, PUNICODE_STRING szModuleName, PULONG pModuleSize) {

	NTSTATUS status;
	ULONG_PTR uImageBase = 0;
	PPEB32 peb32 = NULL;
	SIZE_T size = 0;
	KAPC_STATE kApcState = { 0 };
	peb32 = PsGetProcessWow64Process(pTargetEprocess);
	if (!peb32) return 0;
	//修复缺页异常
	status = MmCopyVirtualMemory(pTargetEprocess, peb32, pTargetEprocess, peb32, 4, UserMode, &size);
	if (!NT_SUCCESS(status))return 0;

	KeStackAttachProcess(pTargetEprocess, &kApcState);
	if (MmIsAddressValid(peb32))
	{
		status = MmCopyVirtualMemory(pTargetEprocess, peb32->Ldr, pTargetEprocess, peb32->Ldr, 4, UserMode, &size);
		if (!NT_SUCCESS(status)) {
			KeUnstackDetachProcess(&kApcState);
			return 0;
		}
		if (MmIsAddressValid(peb32->Ldr))
		{

			for (PLIST_ENTRY32 ListEntry = (PLIST_ENTRY32)
				((PPEB_LDR_DATA32)peb32->Ldr)->InLoadOrderModuleList.Flink; ListEntry != &
				((PPEB_LDR_DATA32)peb32->Ldr)->InLoadOrderModuleList; ListEntry =
				(PLIST_ENTRY32)ListEntry->Flink)
			{
				UNICODE_STRING UnicodeString = { 0 };
				PLDR_DATA_TABLE_ENTRY32 LdrDataTableEntry32 = CONTAINING_RECORD(ListEntry, LDR_DATA_TABLE_ENTRY32, InLoadOrderLinks);

				RtlInitUnicodeString(&UnicodeString, (PWCH)LdrDataTableEntry32->BaseDllName.Buffer);
				// 找到了返回模块基址
				if (RtlCompareUnicodeString(&UnicodeString, szModuleName, TRUE) == 0)
				{
					*pModuleSize = LdrDataTableEntry32->SizeOfImage;
					uImageBase = LdrDataTableEntry32->DllBase;
	 
					break;
				}
			}
		}
	}
	KeUnstackDetachProcess(&kApcState);
	return uImageBase;
}


ULONG_PTR GetX64ProcessModule(PEPROCESS	pTargetEprocess, PUNICODE_STRING szModuleName, PULONG pModuleSize) {

	NTSTATUS status;
	ULONG_PTR uImageBase = 0;
	PPEB64 peb64 = NULL;
	SIZE_T size = 0;
	KAPC_STATE kApcState = { 0 };
	peb64 = PsGetProcessPeb(pTargetEprocess);
	if (!peb64) return 0;
	//修复缺页异常
	status = MmCopyVirtualMemory(pTargetEprocess, peb64, pTargetEprocess, peb64, 4, UserMode, &size);
	if (!NT_SUCCESS(status))return 0;
	KeStackAttachProcess(pTargetEprocess, &kApcState);
	if (MmIsAddressValid(peb64))
	{

		status = MmCopyVirtualMemory(pTargetEprocess, peb64->Ldr, pTargetEprocess, peb64->Ldr, 4, UserMode, &size);
		if (!NT_SUCCESS(status)) {
			KeUnstackDetachProcess(&kApcState);
			return 0;
		}
		if (MmIsAddressValid(peb64->Ldr)) {
			// 遍历链表
			for (PLIST_ENTRY ListEntry = peb64->Ldr->InLoadOrderModuleList.Flink;
				ListEntry != &peb64->Ldr->InLoadOrderModuleList;
				ListEntry = ListEntry->Flink)
			{
				// 将特定链表转换为PLDR_DATA_TABLE_ENTRY格式
				PLDR_DATA_TABLE_ENTRY LdrDataTableEntry = CONTAINING_RECORD(ListEntry, LDR_DATA_TABLE_ENTRY, InLoadOrderLinks);
				// 找到了则返回地址
				if (RtlCompareUnicodeString(&LdrDataTableEntry->BaseDllName, szModuleName, TRUE) == 0)
				{
					*pModuleSize = LdrDataTableEntry->SizeOfImage;
					uImageBase = LdrDataTableEntry->DllBase;
			 
					break;
				}
			}
		}
	}
	KeUnstackDetachProcess(&kApcState);
	return uImageBase;
}

ULONG_PTR GetProcessModuleFromVad(PEPROCESS pTargetEprocess, PUNICODE_STRING szModuleName, PULONG pModuleSize)
{
	//PsGetProcessExitStatus
	return 0;
}
