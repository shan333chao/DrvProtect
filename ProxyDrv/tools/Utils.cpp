#pragma once
#include "Utils.h"
#include "imports.h"
#include "crt.h"
#include "Log.h"
#include "xor.h"


PVOID Utils::GetFuncExportName(_In_ PVOID ModuleBase, _In_ PCHAR FuncName) {
	PIMAGE_DOS_HEADER lpDosHeader = (PIMAGE_DOS_HEADER)ModuleBase;
	PIMAGE_NT_HEADERS64 lpNtHeader =
		(PIMAGE_NT_HEADERS64)(lpDosHeader->e_lfanew + (ULONG64)ModuleBase);

	PIMAGE_EXPORT_DIRECTORY lpExportDir =
		(PIMAGE_EXPORT_DIRECTORY)((ULONG64)ModuleBase +
			lpNtHeader->OptionalHeader
			.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT]
			.VirtualAddress);

	ULONG32* lpNameArr =
		(ULONG32*)(lpExportDir->AddressOfNames + (ULONG64)ModuleBase);

	ULONG32* lpFuncs =
		(ULONG32*)(lpExportDir->AddressOfFunctions + (ULONG64)ModuleBase);

	USHORT* lpOrdinals =
		(USHORT*)(lpExportDir->AddressOfNameOrdinals + (ULONG64)ModuleBase);

	for (auto nIdx = 0u; nIdx < lpExportDir->NumberOfFunctions; ++nIdx) {
		if (!lpNameArr[nIdx] || !lpOrdinals[nIdx])
			continue;

		if (crt::strcmp((PCHAR)((PUCHAR)ModuleBase + lpNameArr[nIdx]), FuncName) == 0) {
			Log("%s %p \r\n", FuncName, (PUCHAR)ModuleBase + lpFuncs[lpOrdinals[nIdx]]);
			return (PVOID)((PUCHAR)ModuleBase + lpFuncs[lpOrdinals[nIdx]]);
		}
	}
	Log("%s  not found \r\n", FuncName);
	return NULL;
}

USHORT Utils::GetServiceNoByName(_In_ PVOID ModuleBase, _In_ PCHAR FuncName) {
	if (!ModuleBase)
	{
		return 0;
	}
	PIMAGE_DOS_HEADER lpDosHeader = (PIMAGE_DOS_HEADER)ModuleBase;
	PIMAGE_NT_HEADERS64 lpNtHeader =
		(PIMAGE_NT_HEADERS64)(lpDosHeader->e_lfanew + (ULONG64)ModuleBase);

	PIMAGE_EXPORT_DIRECTORY lpExportDir =
		(PIMAGE_EXPORT_DIRECTORY)((ULONG64)ModuleBase +
			lpNtHeader->OptionalHeader
			.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT]
			.VirtualAddress);

	ULONG32* lpNameArr =
		(ULONG32*)(lpExportDir->AddressOfNames + (ULONG64)ModuleBase);

	ULONG32* lpFuncs =
		(ULONG32*)(lpExportDir->AddressOfFunctions + (ULONG64)ModuleBase);

	USHORT* lpOrdinals =
		(USHORT*)(lpExportDir->AddressOfNameOrdinals + (ULONG64)ModuleBase);

	for (auto nIdx = 0u; nIdx < lpExportDir->NumberOfFunctions; ++nIdx) {
		if (!lpNameArr[nIdx] || !lpOrdinals[nIdx])
			continue;

		if (crt::strcmp((PCHAR)((PUCHAR)ModuleBase + lpNameArr[nIdx]), FuncName) == 0) {
			return lpOrdinals[nIdx];
		}
	}
	return NULL;
}

static PVOID  KernelBase = 0;

VOID Utils::SetKernelBase(ULONG_PTR ntoskrnl_base) {
	KernelBase = (PVOID)ntoskrnl_base;
};
PVOID Utils::GetKernelBase() {
	return KernelBase;
}


uintptr_t Utils::GetNtFuncExportName(_In_ PCHAR FuncName) {
	return (uintptr_t)GetFuncExportName(GetKernelBase(), FuncName);
}

PVOID Utils::GetSystemInformation(const SYSTEM_INFORMATION_CLASS information_class)
{
	PVOID Buffer = NULL;
	ULONG BufferSize = 4096;
	ULONG ReturnLength;
	NTSTATUS Status;
retry:
	Buffer = imports::ex_allocate_pool(NonPagedPool, BufferSize);

	if (!Buffer) {
		return 0;
	}

	Status = imports::zw_query_system_information(information_class,
		Buffer,
		BufferSize,
		&ReturnLength
	);

	if (Status == STATUS_INFO_LENGTH_MISMATCH) {
		imports::ex_free_pool_with_tag(Buffer, 0);
		BufferSize = ReturnLength;
		goto retry;
	}
	return Buffer;
}

ULONG_PTR Utils::GetKernelModule(PCHAR szModuleName, PULONG imageSize)
{
	PUCHAR buffer = (PUCHAR)GetSystemInformation(system_module_information);
	if (!buffer)
	{
		return 0;
	}
	PCHAR lowerModuleName = to_lower_c(szModuleName);
	PRTL_PROCESS_MODULES Modules = (PRTL_PROCESS_MODULES)buffer;
	ULONG_PTR imageBase = 0;
	ULONG i;
	PRTL_PROCESS_MODULE_INFORMATION ModuleInfo;
	for (i = 0, ModuleInfo = &(Modules->Modules[0]);
		i < Modules->NumberOfModules;
		i++, ModuleInfo++) {
		ModuleInfo = &Modules->Modules[i];
		if (Utils::kstrstr(to_lower_c((PCHAR)ModuleInfo->FullPathName), lowerModuleName) != 0)
		{
			*imageSize = ModuleInfo->ImageSize;
			imageBase = (ULONG_PTR)ModuleInfo->ImageBase;
			break;
		}
	}
	imports::ex_free_pool_with_tag(Modules, 0);
	return imageBase;
}



HANDLE Utils::GetPidByName(PWCH imageName)
{

	PSYSTEM_PROCESS_INFORMATION ProcessInfo = 0;
	HANDLE pid = 0;
	PUCHAR buffer = (PUCHAR)GetSystemInformation(system_process_information);
	if (!buffer)
	{
		return NULL;
	}
	ProcessInfo = (PSYSTEM_PROCESS_INFORMATION)buffer;
	while (ProcessInfo->NextEntryOffset) {
		if (ProcessInfo->ImageName.Length && wcsstr(ProcessInfo->ImageName.Buffer, imageName) != 0)
		{
			pid = ProcessInfo->UniqueProcessId;
			break;
		}
		// 迭代到下一个节点
		ProcessInfo = (PSYSTEM_PROCESS_INFORMATION)(((PUCHAR)ProcessInfo) + ProcessInfo->NextEntryOffset);
	}
	imports::ex_free_pool_with_tag(buffer, 0);
	return pid;
}

VOID Utils::InitApis() {
	
 

	imports::imported.io_get_device_attachment_base_ref = GetNtFuncExportName(skCrypt("IoGetDeviceAttachmentBaseRef"));
	imports::imported.io_get_related_device_object = GetNtFuncExportName(skCrypt("IoGetRelatedDeviceObject"));
	imports::imported.ex_release_resource_lite = GetNtFuncExportName(skCrypt("ExReleaseResourceLite"));
	imports::imported.ex_acquire_resource_exclusive_lite = GetNtFuncExportName(skCrypt("ExAcquireResourceExclusiveLite"));


	imports::imported.ob_reference_object_by_handle_with_tag = GetNtFuncExportName(skCrypt("ObReferenceObjectByHandleWithTag"));
	imports::imported.rtl_random_ex = GetNtFuncExportName(skCrypt("RtlRandomEx"));
	imports::imported.ob_close_handle = GetNtFuncExportName(skCrypt("ObCloseHandle"));
	imports::imported.io_create_file_ex = GetNtFuncExportName(skCrypt("IoCreateFileEx"));

	imports::imported.rtl_lookup_element_generic_table_avl = GetNtFuncExportName(skCrypt("RtlLookupElementGenericTableAvl"));
	imports::imported.rtl_delete_element_generic_table_avl = GetNtFuncExportName(skCrypt("RtlDeleteElementGenericTableAvl"));

	imports::imported.ex_delete_lookaside_list_ex = GetNtFuncExportName(skCrypt("ExDeleteLookasideListEx"));
	imports::imported.ex_initialize_lookaside_list_ex = GetNtFuncExportName(skCrypt("ExInitializeLookasideListEx"));
	imports::imported.mm_flush_image_section = GetNtFuncExportName(skCrypt("MmFlushImageSection"));
	imports::imported.zw_delete_file = GetNtFuncExportName(skCrypt("ZwDeleteFile"));
	imports::imported.rtl_find_exported_routine_by_name = GetNtFuncExportName(skCrypt("RtlFindExportedRoutineByName"));

	imports::imported.rtl_delete_registry_value = GetNtFuncExportName(skCrypt("RtlDeleteRegistryValue"));
	imports::imported.zw_open_key = GetNtFuncExportName(skCrypt("ZwOpenKey"));
	imports::imported.zw_delete_key = GetNtFuncExportName(skCrypt("ZwDeleteKey"));


	imports::imported.mm_get_system_routine_address = GetNtFuncExportName(skCrypt("MmGetSystemRoutineAddress"));
	imports::imported.mm_map_io_space = GetNtFuncExportName(skCrypt("MmMapIoSpace"));
	imports::imported.io_get_device_object_pointer = GetNtFuncExportName(skCrypt("IoGetDeviceObjectPointer"));
	imports::imported.mm_get_physical_address = GetNtFuncExportName(skCrypt("MmGetPhysicalAddress"));
	imports::imported.mm_is_address_valid = GetNtFuncExportName(skCrypt("MmIsAddressValid"));
	imports::imported.ke_delay_execution_thread = GetNtFuncExportName(skCrypt("KeDelayExecutionThread"));
	imports::imported.ex_allocate_pool_with_tag = GetNtFuncExportName(skCrypt("ExAllocatePoolWithTag"));
	imports::imported.ex_get_previous_mode = GetNtFuncExportName(skCrypt("ExGetPreviousMode"));
	imports::imported.ps_create_system_thread = GetNtFuncExportName(skCrypt("PsCreateSystemThread"));
	imports::imported.zw_close = GetNtFuncExportName(skCrypt("ZwClose"));
	imports::imported.nt_trace_control = GetNtFuncExportName(skCrypt("NtTraceControl"));
	imports::imported.mm_build_mdl_for_non_paged_pool = GetNtFuncExportName(skCrypt("MmBuildMdlForNonPagedPool"));
	imports::imported.ps_get_process_exit_status = GetNtFuncExportName(skCrypt("PsGetProcessExitStatus"));
	imports::imported.ps_reference_primary_token = GetNtFuncExportName(skCrypt("PsReferencePrimaryToken"));
	imports::imported.ps_get_process_wow64_process = GetNtFuncExportName(skCrypt("PsGetProcessWow64Process"));
	imports::imported.ps_get_process_image_file_name = GetNtFuncExportName(skCrypt("PsGetProcessImageFileName"));

	imports::imported.ps_reference_process_file_pointer = GetNtFuncExportName(skCrypt("PsReferenceProcessFilePointer"));
	imports::imported.ke_initialize_guarded_mutex = GetNtFuncExportName(skCrypt("KeInitializeGuardedMutex"));
	imports::imported.ke_acquire_guarded_mutex = GetNtFuncExportName(skCrypt("KeAcquireGuardedMutex"));
	imports::imported.ke_release_guarded_mutex = GetNtFuncExportName(skCrypt("KeReleaseGuardedMutex"));
	imports::imported.ps_get_process_id = GetNtFuncExportName(skCrypt("PsGetProcessId"));
	imports::imported.ps_get_current_process_id = GetNtFuncExportName(skCrypt("PsGetCurrentProcessId"));
	imports::imported.ps_get_current_thread_id = GetNtFuncExportName(skCrypt("PsGetCurrentThreadId")); ;
	imports::imported.ps_get_process_session_id = GetNtFuncExportName(skCrypt("PsGetProcessSessionId"));
	imports::imported.zw_create_file = GetNtFuncExportName(skCrypt("ZwCreateFile")); ;
	imports::imported.zw_query_information_file = GetNtFuncExportName(skCrypt("ZwQueryInformationFile"));
	imports::imported.zw_read_file = GetNtFuncExportName(skCrypt("ZwReadFile")); ;
	imports::imported.rtl_compare_memory = GetNtFuncExportName(skCrypt("RtlCompareMemory"));
	imports::imported.rtl_image_nt_header = GetNtFuncExportName(skCrypt("RtlImageNtHeader"));


	imports::imported.ex_allocate_pool = GetNtFuncExportName(skCrypt("ExAllocatePool"));
	imports::imported.zw_query_system_information = GetNtFuncExportName(skCrypt("ZwQuerySystemInformation"));
	imports::imported.ex_free_pool_with_tag = GetNtFuncExportName(skCrypt("ExFreePoolWithTag"));
	imports::imported.rtl_init_ansi_string = GetNtFuncExportName(skCrypt("RtlInitAnsiString"));
	imports::imported.rtl_ansi_string_to_unicode_string = GetNtFuncExportName(skCrypt("RtlAnsiStringToUnicodeString"));
	imports::imported.mm_copy_virtual_memory = GetNtFuncExportName(skCrypt("MmCopyVirtualMemory"));
	imports::imported.io_get_current_process = GetNtFuncExportName(skCrypt("IoGetCurrentProcess"));
	imports::imported.ps_lookup_process_by_process_id = GetNtFuncExportName(skCrypt("PsLookupProcessByProcessId"));
	imports::imported.ps_get_process_peb = GetNtFuncExportName(skCrypt("PsGetProcessPeb"));
	imports::imported.ob_reference_object_safe = GetNtFuncExportName(skCrypt("ObReferenceObjectSafe"));
	imports::imported.zw_allocate_virtual_memory = GetNtFuncExportName(skCrypt("ZwAllocateVirtualMemory"));
	imports::imported.rtl_compare_unicode_string = GetNtFuncExportName(skCrypt("RtlCompareUnicodeString"));
	imports::imported.rtl_free_unicode_string = GetNtFuncExportName(skCrypt("RtlFreeUnicodeString"));
	imports::imported.obf_dereference_object = GetNtFuncExportName(skCrypt("ObfDereferenceObject"));
	imports::imported.mm_copy_memory = GetNtFuncExportName(skCrypt("MmCopyMemory"));
	imports::imported.ps_get_process_section_base_address = GetNtFuncExportName(skCrypt("PsGetProcessSectionBaseAddress"));
	imports::imported.zw_query_virtual_memory = GetNtFuncExportName(skCrypt("ZwQueryVirtualMemory"));
	imports::imported.zw_free_virtual_memory = GetNtFuncExportName(skCrypt("ZwFreeVirtualMemory"));
	imports::imported.io_create_driver = GetNtFuncExportName(skCrypt("IoCreateDriver"));
	imports::imported.io_allocate_mdl = GetNtFuncExportName(skCrypt("IoAllocateMdl"));
	imports::imported.mm_probe_and_lock_pages = GetNtFuncExportName(skCrypt("MmProbeAndLockPages"));
	imports::imported.mm_map_locked_pages_specify_cache = GetNtFuncExportName(skCrypt("MmMapLockedPagesSpecifyCache"));
	imports::imported.mm_protect_mdl_system_address = GetNtFuncExportName(skCrypt("MmProtectMdlSystemAddress"));
	imports::imported.mm_unmap_locked_pages = GetNtFuncExportName(skCrypt("MmUnmapLockedPages"));
	imports::imported.mm_unlock_pages = GetNtFuncExportName(skCrypt("MmUnlockPages"));
	imports::imported.io_free_mdl = GetNtFuncExportName(skCrypt("IoFreeMdl"));
	imports::imported.iof_complete_request = GetNtFuncExportName(skCrypt("IofCompleteRequest"));
	imports::imported.rtl_init_unicode_string = GetNtFuncExportName(skCrypt("RtlInitUnicodeString"));
	imports::imported.ex_raise_hard_error = GetNtFuncExportName(skCrypt("ExRaiseHardError"));

	imports::imported.io_delete_device = GetNtFuncExportName(skCrypt("IoDeleteDevice"));
	imports::imported.io_create_device = GetNtFuncExportName(skCrypt("IoCreateDevice"));
	imports::imported.rtl_get_version = GetNtFuncExportName(skCrypt("RtlGetVersion"));
	imports::imported.mm_map_io_space_ex = GetNtFuncExportName(skCrypt("MmMapIoSpaceEx"));
	imports::imported.mm_unmap_io_space = GetNtFuncExportName(skCrypt("MmUnmapIoSpace"));
	imports::imported.mm_get_virtual_for_physical = GetNtFuncExportName(skCrypt("MmGetVirtualForPhysical"));
	imports::imported.mm_get_physical_memory_ranges = GetNtFuncExportName(skCrypt("MmGetPhysicalMemoryRanges"));
	imports::imported.ke_stack_attach_process = GetNtFuncExportName(skCrypt("KeStackAttachProcess"));
	imports::imported.ke_unstack_detach_process = GetNtFuncExportName(skCrypt("KeUnstackDetachProcess"));
	imports::imported.io_query_file_dos_device_name = GetNtFuncExportName(skCrypt("IoQueryFileDosDeviceName"));
	imports::imported.ps_get_thread_process = GetNtFuncExportName(skCrypt("PsGetThreadProcess"));
	imports::imported.ke_get_current_thread = GetNtFuncExportName(skCrypt("KeGetCurrentThread"));
	imports::imported.mm_user_probe_address = *(PULONGLONG)GetNtFuncExportName(skCrypt("MmUserProbeAddress"));
}

RTL_OSVERSIONINFOW Utils::InitOsVersion() {
	static RTL_OSVERSIONINFOW OSVERSION = { 0 };
	if (OSVERSION.dwBuildNumber)
	{
		return OSVERSION;
	}
	imports::rtl_get_version(&OSVERSION);
	return OSVERSION;
}

INT Utils::kmemcmp(const void* s1, const void* s2, size_t n)
{
	const unsigned char* p1 = (const unsigned char*)s1;
	const unsigned char* end1 = p1 + n;
	const unsigned char* p2 = (const unsigned char*)s2;
	int                   d = 0;
	for (;;) {
		if (d || p1 >= end1) break;
		d = (int)*p1++ - (int)*p2++;
		if (d || p1 >= end1) break;
		d = (int)*p1++ - (int)*p2++;
		if (d || p1 >= end1) break;
		d = (int)*p1++ - (int)*p2++;
		if (d || p1 >= end1) break;
		d = (int)*p1++ - (int)*p2++;
	}
	return d;
}
PVOID Utils::kmemcpy(void* dest, const void* src, size_t len)
{
	char* d = (char*)dest;
	const char* s = (const char*)src;
	while (len--)
		*d++ = *s++;
	return dest;
}
PVOID Utils::kmemset(void* dest, UINT8 c, size_t count)
{
	size_t blockIdx;
	size_t blocks = count >> 3;
	size_t bytesLeft = count - (blocks << 3);
	UINT64 cUll =
		c
		| (((UINT64)c) << 8)
		| (((UINT64)c) << 16)
		| (((UINT64)c) << 24)
		| (((UINT64)c) << 32)
		| (((UINT64)c) << 40)
		| (((UINT64)c) << 48)
		| (((UINT64)c) << 56);

	UINT64* destPtr8 = (UINT64*)dest;
	for (blockIdx = 0; blockIdx < blocks; blockIdx++) destPtr8[blockIdx] = cUll;

	if (!bytesLeft) return dest;

	blocks = bytesLeft >> 2;
	bytesLeft = bytesLeft - (blocks << 2);

	UINT32* destPtr4 = (UINT32*)&destPtr8[blockIdx];
	for (blockIdx = 0; blockIdx < blocks; blockIdx++) destPtr4[blockIdx] = (UINT32)cUll;

	if (!bytesLeft) return dest;

	blocks = bytesLeft >> 1;
	bytesLeft = bytesLeft - (blocks << 1);

	UINT16* destPtr2 = (UINT16*)&destPtr4[blockIdx];
	for (blockIdx = 0; blockIdx < blocks; blockIdx++) destPtr2[blockIdx] = (UINT16)cUll;

	if (!bytesLeft) return dest;

	UINT8* destPtr1 = (UINT8*)&destPtr2[blockIdx];
	for (blockIdx = 0; blockIdx < bytesLeft; blockIdx++) destPtr1[blockIdx] = (UINT8)cUll;

	return dest;
}
char* Utils::kstrchr(const char* str, int character) {
	for (; *str != '\0'; ++str) {
		if (*str == (char)character)
			return (char*)str;
	}
	if (*str == '\0') {
		return NULL;
	}
	return NULL;
}
char* Utils::kstrstr(const char* haystack, const char* needle)
{
	if (!*needle) // Empty needle.
		return (char*)haystack;

	const char    needle_first = *needle;



	// Runs strchr() on the first section of the haystack as it has a lower
	// algorithmic complexity for discarding the first non-matching characters.
	haystack = Utils::kstrchr(haystack, needle_first);
	if (!haystack) // First character of needle is not in the haystack.
		return NULL;

	// First characters of haystack and needle are the same now. Both are
	// guaranteed to be at least one character long.
	// Now computes the sum of the first needle_len characters of haystack
	// minus the sum of characters values of needle.

	const char* i_haystack = haystack + 1
		, * i_needle = needle + 1;

	unsigned int  sums_diff = *haystack;
	bool          identical = true;

	while (*i_haystack && *i_needle) {
		sums_diff += *i_haystack;
		sums_diff -= *i_needle;
		identical &= *i_haystack++ == *i_needle++;
	}

	// i_haystack now references the (needle_len + 1)-th character.

	if (*i_needle) // haystack is smaller than needle.
		return NULL;
	else if (identical)
		return (char*)haystack;

	size_t        needle_len = i_needle - needle;
	size_t        needle_len_1 = needle_len - 1;

	// Loops for the remaining of the haystack, updating the sum iteratively.
	const char* sub_start;
	for (sub_start = haystack; *i_haystack; i_haystack++) {
		sums_diff -= *sub_start++;
		sums_diff += *i_haystack;

		// Since the sum of the characters is already known to be equal at that
		// point, it is enough to check just needle_len-1 characters for
		// equality.
		if (
			sums_diff == 0
			&& needle_first == *sub_start // Avoids some calls to memcmp.
			&& Utils::kmemcmp(sub_start, needle, needle_len_1) == 0
			)
			return (char*)sub_start;
	}

	return NULL;
}



