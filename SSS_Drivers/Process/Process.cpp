#pragma once
#include "Process.h"
#include "../PatternSearch/PatternSearch.h"
#include "../ERROR_CODE.h"

namespace process_info {


	ULONG_PTR GetProcessModuleInfo(ULONG pid, PCHAR pcModuleName, PULONG pModuleSize)
	{
		PVOID									pIsx86Process = NULL;
		PEPROCESS								pTargetEprocess = NULL;
		NTSTATUS								status = STATUS_UNSUCCESSFUL;

		if (!pcModuleName)
		{
			return 0;
		}
		pTargetEprocess = Utils::lookup_process_by_id((HANDLE)pid);
		if (!pTargetEprocess) return status;
		ANSI_STRING aName = { 0 };
		imports::rtl_init_ansi_string(&aName, pcModuleName);
		UNICODE_STRING moduleNameMem = { 0 };
		imports::rtl_ansi_string_to_unicode_string(&moduleNameMem, &aName, TRUE);
		pIsx86Process = imports::ps_get_process_wow64_process(pTargetEprocess);
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
		imports::rtl_free_unicode_string(&moduleNameMem);
		status = STATUS_SUCCESS;
		return moduleBase;
	}
	ULONG_PTR GetProcessModuleExport(ULONG pid, PCHAR pcModuleName, PCHAR funcName)
	{
		ULONG pModuleSize = 0;
		ULONG64 moduleBase = 0;
		ULONG64 funcAddr = 0;
		PEPROCESS eprocess = Utils::lookup_process_by_id(ULongToHandle(pid));
		if (!eprocess)
		{
			return STATUS_COMMON_PARAM_1;
		}
		moduleBase = patternSearch::get_module(eprocess, pcModuleName, &pModuleSize);
		if (!moduleBase)
		{
			return STATUS_MODULE_EXPORT_MODULE_BASE_ERROR;
		}
		funcAddr = patternSearch::get_module_export(eprocess, moduleBase, funcName);
		return funcAddr;
	}

	ULONG_PTR GetProcessModuleExport2(ULONG pid, ULONGLONG moduleBase, PCHAR funcName)
	{
		if (!moduleBase)
		{
			return STATUS_MODULE_EXPORT_MODULE_BASE_ERROR;
		}
		PEPROCESS eprocess = Utils::lookup_process_by_id(ULongToHandle(pid));
		if (!eprocess)
		{
			return STATUS_COMMON_PARAM_1;
		}
		return   patternSearch::get_module_export(eprocess, moduleBase, funcName);;
	}
	ULONG_PTR GetX86ProcessModule(PEPROCESS	pTargetEprocess, PUNICODE_STRING szModuleName, PULONG pModuleSize) {

		NTSTATUS status;
		ULONG_PTR uImageBase = 0;
		PPEB32 peb32 = NULL;
		SIZE_T size = 0;
		KAPC_STATE kApcState = { 0 };
		peb32 = (PPEB32)imports::ps_get_process_wow64_process(pTargetEprocess);
		if (!peb32) return 0;
		//修复缺页异常
		status = imports::mm_copy_virtual_memory(pTargetEprocess, peb32, pTargetEprocess, peb32, 4, UserMode, &size);
		if (!NT_SUCCESS(status))return 0;

		imports::ke_stack_attach_process(pTargetEprocess, &kApcState);
		if (imports::mm_is_address_valid(peb32))
		{
			status = imports::mm_copy_virtual_memory(pTargetEprocess, (PVOID)peb32->Ldr, pTargetEprocess, (PVOID)peb32->Ldr, 4, UserMode, &size);
			if (!NT_SUCCESS(status)) {
				imports::ke_unstack_detach_process(&kApcState);
				return 0;
			}
			if (imports::mm_is_address_valid((PVOID)peb32->Ldr))
			{
				for (PLIST_ENTRY32 ListEntry = (PLIST_ENTRY32)
					((PPEB_LDR_DATA32)peb32->Ldr)->InLoadOrderModuleList.Flink; ListEntry != &
					((PPEB_LDR_DATA32)peb32->Ldr)->InLoadOrderModuleList; ListEntry =
					(PLIST_ENTRY32)ListEntry->Flink)
				{
					UNICODE_STRING UnicodeString = { 0 };
					PLDR_DATA_TABLE_ENTRY32 LdrDataTableEntry32 = CONTAINING_RECORD(ListEntry, LDR_DATA_TABLE_ENTRY32, InLoadOrderLinks);
					imports::rtl_init_unicode_string(&UnicodeString, (PWCH)LdrDataTableEntry32->BaseDllName.Buffer);
					// 找到了返回模块基址
					if (imports::rtl_compare_unicode_string(&UnicodeString, szModuleName, TRUE) == 0)
					{
						*pModuleSize = LdrDataTableEntry32->SizeOfImage;
						uImageBase = LdrDataTableEntry32->DllBase;

						break;
					}
				}
			}
		}
		imports::ke_unstack_detach_process(&kApcState);
		return uImageBase;
	}
	ULONG_PTR GetX64ProcessModule(PEPROCESS	pTargetEprocess, PUNICODE_STRING szModuleName, PULONG pModuleSize) {

		NTSTATUS status;
		ULONG_PTR uImageBase = 0;
		PPEB64 peb64 = NULL;
		SIZE_T size = 0;
		KAPC_STATE kApcState = { 0 };
		peb64 = (PPEB64)imports::ps_get_process_peb(pTargetEprocess);
		if (!peb64) return 0;
		//修复缺页异常
		status = imports::mm_copy_virtual_memory(pTargetEprocess, peb64, pTargetEprocess, peb64, 4, UserMode, &size);
		if (!NT_SUCCESS(status))return 0;
		imports::ke_stack_attach_process(pTargetEprocess, &kApcState);
		if (imports::mm_is_address_valid(peb64))
		{

			status = imports::mm_copy_virtual_memory(pTargetEprocess, peb64->Ldr, pTargetEprocess, peb64->Ldr, 4, UserMode, &size);
			if (!NT_SUCCESS(status)) {
				imports::ke_unstack_detach_process(&kApcState);
				return 0;
			}
			if (imports::mm_is_address_valid(peb64->Ldr)) {
				// 遍历链表
				for (PLIST_ENTRY ListEntry = (PLIST_ENTRY)peb64->Ldr->InLoadOrderModuleList.Flink;
					ListEntry != (PLIST_ENTRY)&peb64->Ldr->InLoadOrderModuleList;
					ListEntry = ListEntry->Flink)
				{
					// 将特定链表转换为PLDR_DATA_TABLE_ENTRY格式
					PLDR_DATA_TABLE_ENTRY LdrDataTableEntry = CONTAINING_RECORD(ListEntry, LDR_DATA_TABLE_ENTRY, InLoadOrderLinks);
					// 找到了则返回地址
					if (imports::rtl_compare_unicode_string(&LdrDataTableEntry->BaseDllName, szModuleName, TRUE) == 0)
					{
						*pModuleSize = LdrDataTableEntry->SizeOfImage;
						uImageBase = LdrDataTableEntry->DllBase;

						break;
					}
				}
			}
		}
		imports::ke_unstack_detach_process(&kApcState);
		return uImageBase;
	}




	ULONG_PTR GetProcessModuleInfoNoAttach(ULONG pid, PCHAR pcModuleName, PULONG pModuleSize)
	{
		PEPROCESS eprocess = Utils::lookup_process_by_id(ULongToHandle(pid));
		if (!eprocess)
		{
			return 0;
		}
		return patternSearch::get_module(eprocess, pcModuleName, pModuleSize);
	}


}
