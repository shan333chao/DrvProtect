#pragma once
#include "Memory.h"

#include "PMemory.h"
#include "../SSDT/Functions.h"


namespace memory {
	BOOLEAN IsAddressValid(PVOID Address, ULONG_PTR uSize) {
		BOOLEAN result = FALSE;
		if (Address == NULL)
		{
			return result;
		}
		result = uSize == 0 || ((PUCHAR)Address + uSize) < Address || (ULONG64)Address >= imports::imported.mm_user_probe_address || (ULONG64)((PUCHAR)Address + uSize) > imports::imported.mm_user_probe_address;
		return result;
	}

	NTSTATUS mNtProtectVirtualMemory(HANDLE ProcessHandle, PVOID* BaseAddress, PSIZE_T RegionSize, ULONG NewProtect, PULONG OldProtect)
	{
		MODE oldMode = functions::SetThreadPrevious(imports::ke_get_current_thread(), KernelMode);
		NTSTATUS status;
		PNtProtectVirtualMemory MyNtProtectVirtualMemory = functions::GetNtProtectVirtualMemory();
		if (!MyNtProtectVirtualMemory)
		{
			return STATUS_UNSUCCESSFUL;

		}
		status = MyNtProtectVirtualMemory(ProcessHandle, BaseAddress, RegionSize, NewProtect, OldProtect);

		functions::SetThreadPrevious(imports::ke_get_current_thread(), oldMode);


		return  status;
	}

	NTSTATUS SS_ReadMemory(ULONG_PTR uPid, ULONG_PTR uFakePid, PVOID Address, ULONG_PTR uReadSize, PVOID ReadBuffer)
	{
		PEPROCESS								pTargetEprocess = NULL;
		NTSTATUS								status = STATUS_UNSUCCESSFUL;
		static PEPROCESS						pFakeEprocess = NULL;
		static PVOID							pFakeObject = NULL;
		PEPROCESS								pCopyFakeEprocess = NULL;
		SIZE_T									NumberOfBytesCopied = NULL;
		PVOID									pTempBuffer = NULL;
		ULONG_PTR								uProtectCr3 = NULL;
		if (IsAddressValid(Address, uReadSize))
		{
			return STATUS_INVALID_PARAMETER_2;
		}
		if (IsAddressValid(ReadBuffer, 1))
		{
			return STATUS_INVALID_PARAMETER_5;
		}
		if (uReadSize == 0)
		{
			return STATUS_INVALID_PARAMETER_4;
		}

		pTargetEprocess = Utils::lookup_process_by_id((HANDLE)uPid);
		if (!pTargetEprocess) return status;
		if (!pFakeObject)
		{
			pFakeEprocess = Utils::lookup_process_by_id((HANDLE)uFakePid);
			//获取傀儡进程 
			if (!pFakeEprocess) {
				return STATUS_INVALID_PARAMETER_2;
			}
			pFakeObject = imports::ex_allocate_pool(NonPagedPool, PAGE_SIZE);
			if (!pFakeObject)
			{
				return STATUS_COMMON_ALLOC_FAILED;
			}

			//复制傀儡进程
			Utils::kmemset(pFakeObject, 0, PAGE_SIZE);

			Utils::kmemcpy(pFakeObject, (PUCHAR)pFakeEprocess - 0x30, PAGE_SIZE);
		}
		pCopyFakeEprocess = (PEPROCESS)((PUCHAR)pFakeObject + 0x30);
		//替换页表地址 
		uProtectCr3 = *(PULONG_PTR)((PUCHAR)pTargetEprocess + 0x28);
		*(PULONG_PTR)((PUCHAR)pCopyFakeEprocess + 0x28) = uProtectCr3;
		ULONG64 GotSize = 0;
		//读取内存
		status = imports::mm_copy_virtual_memory(pCopyFakeEprocess, Address, imports::io_get_current_process(), ReadBuffer, uReadSize, KernelMode, &GotSize);
		if (!NT_SUCCESS(status))
		{
			//读取内存
			status = imports::mm_copy_virtual_memory(pTargetEprocess, Address, imports::io_get_current_process(), ReadBuffer, uReadSize, KernelMode, &GotSize);
		}
		return status;
	}
	NTSTATUS SS_WriteMemory(ULONG_PTR uPid, ULONG_PTR uFakePid, PVOID Address, ULONG_PTR uWriteSize, PVOID WriteBuffer)
	{
	 


		return STATUS_INVALID_ADDRESS;


	}

	NTSTATUS SS_ReadMemoryPhy(ULONG_PTR uPid, PVOID Address, ULONG_PTR uReadSize, PVOID ReadBuffer)
	{
		PEPROCESS								pTargetEprocess = NULL;
		NTSTATUS								status = STATUS_UNSUCCESSFUL;
		if (IsAddressValid(Address, uReadSize))
		{
			return STATUS_INVALID_PARAMETER_2;
		}
		if (IsAddressValid(ReadBuffer, 1))
		{
			return STATUS_INVALID_PARAMETER_4;
		}
		pTargetEprocess = Utils::lookup_process_by_id((HANDLE)uPid);
		if (!pTargetEprocess) return status;
		SIZE_T NumberOfReadSize = 0;
		status = p_memory::ReadProcessMemory(pTargetEprocess, Address, ReadBuffer, uReadSize, &NumberOfReadSize);
		return status;
	}

	NTSTATUS SS_WriteMemoryPhy(ULONG_PTR uPid, PVOID Address, ULONG_PTR uWriteSize, PVOID WriteBuffer)
	{
		PEPROCESS								pTargetEprocess = NULL;
		NTSTATUS								status = STATUS_UNSUCCESSFUL;
		if (IsAddressValid(Address, uWriteSize))
		{
			return STATUS_INVALID_PARAMETER_2;
		}
		if (IsAddressValid(WriteBuffer, 1))
		{
			return STATUS_INVALID_PARAMETER_4;
		}
		pTargetEprocess = Utils::lookup_process_by_id((HANDLE)uPid);
		if (!pTargetEprocess) return status;
		SIZE_T NumberOfWriteSize = 0;

		status = p_memory::WriteProcessMemory(pTargetEprocess, Address, WriteBuffer, uWriteSize, &NumberOfWriteSize);

		return status;
	}


	NTSTATUS SS_ReadMemoryPhy2(ULONG_PTR uPid, PVOID Address, ULONG_PTR uReadSize, PVOID ReadBuffer)
	{
		PEPROCESS								pTargetEprocess = NULL;
		NTSTATUS								status = STATUS_UNSUCCESSFUL;
		if (IsAddressValid(Address, uReadSize))
		{
			return STATUS_INVALID_PARAMETER_2;
		}
		if (IsAddressValid(ReadBuffer, 1))
		{
			return STATUS_INVALID_PARAMETER_4;
		}
		pTargetEprocess = Utils::lookup_process_by_id((HANDLE)uPid);
		if (!pTargetEprocess) return status;
		status = MiMemory::MiReadProcessMemory(pTargetEprocess, Address, ReadBuffer, uReadSize);
		return status;
	}

	NTSTATUS SS_WriteMemoryPhy2(ULONG_PTR uPid, PVOID Address, ULONG_PTR uWriteSize, PVOID WriteBuffer)
	{
		PEPROCESS								pTargetEprocess = NULL;
		NTSTATUS								status = STATUS_UNSUCCESSFUL;
		if (IsAddressValid(Address, uWriteSize))
		{
			return STATUS_INVALID_PARAMETER_2;
		}
		if (IsAddressValid(WriteBuffer, 1))
		{
			return STATUS_INVALID_PARAMETER_4;
		}
		pTargetEprocess = Utils::lookup_process_by_id((HANDLE)uPid);
		if (!pTargetEprocess) return status;

		status = MiMemory::MiWriteProcessMemory(pTargetEprocess, Address, WriteBuffer, uWriteSize);

		return status;
	}
	NTSTATUS  CreateMemory(PEPROCESS pTargetEprocess, ULONG_PTR uSize, PULONG64 retAddress, PULONG64 kernelAllocAddr, PMDL pmdl)
	{
		NTSTATUS								status = STATUS_UNSUCCESSFUL;
		KAPC_STATE								kapc_state = { 0 };
		PVOID									BaseAddr = NULL;
		PVOID									MappAddr = NULL;
		PMDL									pMdl = NULL;

		Utils::AttachProcess(pTargetEprocess);
		//挂靠目标进程
		//imports::ke_stack_attach_process(pTargetEprocess, &kapc_state);
		BaseAddr = imports::ex_allocate_pool(NonPagedPool, uSize);
		if (!BaseAddr)
		{
			Utils::DetachProcess();
			//imports::ke_unstack_detach_process(&kapc_state);
			return STATUS_UNSUCCESSFUL;
		}

		Utils::kmemset(BaseAddr, 0, uSize);
		*(PBOOLEAN)imports::imported.kd_entered_debugger = TRUE;
		///创建pMdl
		pMdl = imports::io_allocate_mdl(BaseAddr, uSize, FALSE, NULL, NULL);
		*(PBOOLEAN)imports::imported.kd_entered_debugger = FALSE;
		if (!pMdl) {
			imports::ex_free_pool_with_tag(BaseAddr, 0);
			Utils::DetachProcess();
			//imports::ke_unstack_detach_process(&kapc_state);
			return STATUS_UNSUCCESSFUL;
		}
		*(PBOOLEAN)imports::imported.kd_entered_debugger = TRUE;
		//构建非分页物理页
		imports::mm_build_mdl_for_non_paged_pool(pMdl);
		*(PBOOLEAN)imports::imported.kd_entered_debugger = FALSE;
		__try {

			//MDL指向的物理页映射值虚拟地址
			*(PBOOLEAN)imports::imported.kd_entered_debugger = TRUE;
			MappAddr = imports::mm_map_locked_pages_specify_cache(pMdl, UserMode, MmCached, NULL, NULL, NormalPagePriority);
			*(PBOOLEAN)imports::imported.kd_entered_debugger = FALSE;
			if (!MappAddr) {
				imports::io_free_mdl(pMdl);
				imports::ex_free_pool_with_tag(BaseAddr, 0);
				Utils::DetachProcess();
				//imports::ke_unstack_detach_process(&kapc_state);
				return STATUS_UNSUCCESSFUL;
			}
		}
		__except (EXCEPTION_EXECUTE_HANDLER) {
			imports::io_free_mdl(pMdl);
			imports::ex_free_pool_with_tag(BaseAddr, 0);
			Utils::DetachProcess();
			//imports::ke_unstack_detach_process(&kapc_state);
			return STATUS_UNSUCCESSFUL;
		}


		//写入内存
		Utils::kmemset(MappAddr, 0, uSize);
		ChangePageAttributeExecute((ULONG64)MappAddr, uSize);
		*retAddress = (ULONG64)MappAddr;
		*kernelAllocAddr = (ULONG64)BaseAddr;
		Utils::kmemcpy(pmdl, pMdl, sizeof(MDL));
		//取消进程挂靠
		//imports::ke_unstack_detach_process(&kapc_state);
		Utils::DetachProcess();

		ULONG64 uProtectCr3 = *(PULONG_PTR)((PUCHAR)pTargetEprocess + 0x28);

		status = *retAddress > 0 ? STATUS_SUCCESS : STATUS_UNSUCCESSFUL;
		return status;
	}


	void FreeMemory(PEPROCESS eprocess, ULONGLONG mapLockAddr, PVOID kernelAddr, PMDL pmdl) {
		//KAPC_STATE								kapc_state = { 0 };
		//if (imports::ps_get_process_exit_process_called(eprocess))
		//{
		//	return;
		//}
		//挂靠目标进程
		//imports::ke_stack_attach_process(eprocess, &kapc_state);
		//MmUnmapLockedPages((PVOID)mapLockAddr, pmdl);
		//imports::ex_free_pool_with_tag(kernelAddr, 0);
		//imports::io_free_mdl(pmdl);

		//取消进程挂靠
		//imports::ke_unstack_detach_process(&kapc_state);
	}

	NTSTATUS SS_CreateMemory(ULONG uPid, ULONG_PTR uSize, PULONG64 retAddress)
	{
		if (uSize == 0)
		{
			return STATUS_INVALID_PARAMETER_2;
		}
		if (!retAddress)
		{
			return STATUS_INVALID_PARAMETER_3;
		}
		PEPROCESS								pTargetEprocess = NULL;

		NTSTATUS								status = NULL;
		KAPC_STATE								kapc_state = { 0 };
		PVOID									BaseAddr = NULL;
		PVOID									MappAddr = NULL;
		MDL								Mdl = { 0 };
		ULONG64		kernelAllocateAddr = 0;
		ULONG64		r3_addr = 0;
		pTargetEprocess = Utils::lookup_process_by_id((HANDLE)uPid);
		if (!pTargetEprocess) return STATUS_INVALID_PARAMETER_1;
		status = CreateMemory(pTargetEprocess, uSize, &r3_addr, &kernelAllocateAddr, &Mdl);
		*retAddress = r3_addr;
		return status;
	}




	ULONG_PTR getPteBase() {
		NTSTATUS status;
		static ULONG_PTR PTE_BASE = 0;
		if (PTE_BASE)
		{
			return PTE_BASE;
		}
		ULONG64 versionNumber = Utils::InitOsVersion().dwBuildNumber;
		// win7或者1607以下
		if (versionNumber < WINDOWS_10_VERSION_REDSTONE1)
		{
			PTE_BASE = 0xFFFFF68000000000llu;
		}
		else {

			/*	// win10 1607以上
			//UNICODE_STRING MmGetVirtualForPhysicalStr = { 0 };
			//RtlInitUnicodeString(&MmGetVirtualForPhysicalStr, L"MmGetVirtualForPhysical");

			PUCHAR MmGetVirtualForPhysicalAddr = MmGetSystemRoutineAddress(&MmGetVirtualForPhysicalStr);*/
			PTE_BASE = *(PULONG64)(imports::imported.mm_get_virtual_for_physical + 0x22);
		}
		return PTE_BASE;
	}

	ULONG64 getPte(ULONG64 VirtualAddress)
	{
		ULONG_PTR PTE_BASE = getPteBase();
		return ((VirtualAddress >> 9) & 0x7FFFFFFFF8) + PTE_BASE;
	}

	ULONG64 getPde(ULONG64 VirtualAddress)
	{
		ULONG_PTR PTE_BASE = getPteBase();
		ULONG64 pte = getPte(VirtualAddress);
		return ((pte >> 9) & 0x7FFFFFFFF8) + PTE_BASE;
	}

	//ULONG64 getPdpte(ULONG64 VirtualAddress)
	//{
	//	ULONG_PTR PTE_BASE = getPteBase();
	//	ULONG64 pde = getPde(VirtualAddress);
	//	return ((pde >> 9) & 0x7FFFFFFFF8) + PTE_BASE;
	//}

	//ULONG64 getPml4e(ULONG64 VirtualAddress)
	//{
	//	ULONG_PTR PTE_BASE = getPteBase();
	//	ULONG64 ppe = getPdpte(VirtualAddress);
	//	return ((ppe >> 9) & 0x7FFFFFFFF8) + PTE_BASE;
	//}





	VOID ChangePageAttributeExecute(ULONG64 uAddress, ULONG64 uSize) {
		if (uAddress >> 47 == -1 || uAddress >> 47 == 0) {
			ULONG64 uStartAddress = uAddress & (~(PAGE_SIZE - 1));
			ULONG64 uEndAddress = (uStartAddress + uSize);
			while (uStartAddress <= uEndAddress)
			{
				PHARDWARE_PTE	pde = (PHARDWARE_PTE)getPde(uStartAddress);
				//判断P位
				if (pde && imports::mm_is_address_valid(pde) && pde->Valid == 1)
				{
					pde->NoExecute = 0;
					//判断PS位 是不是大页
					if (pde->Global == 1)
					{
						continue;
					}
				}
				PHARDWARE_PTE	pte = (PHARDWARE_PTE)getPte(uStartAddress);
				if (pte && imports::mm_is_address_valid(pte) && pte->Valid == 1)
				{

					//判断P位 
					pte->NoExecute = 0;
					//刷新TLB
					__invlpg((PVOID)uStartAddress);
				}
				uStartAddress += PAGE_SIZE;
			}
		}
	}
	NTSTATUS ChangeProcessPagtAddrExe(ULONG PID, ULONG64 Address, ULONG size)
	{

		NTSTATUS status = STATUS_UNSUCCESSFUL;
		PEPROCESS pTargetEprocess = Utils::lookup_process_by_id(ULongToHandle(PID));
		if (!pTargetEprocess)
		{
			return STATUS_INVALID_PARAMETER_1;
		}

		ULONG64 uProtectCr3 = *(PULONG_PTR)((PUCHAR)pTargetEprocess + 0x28);
		status = p_memory::ChangeProcessPageAttributeExecute(uProtectCr3, Address, size);

		return status;
	}
	//NTSTATUS map_physical_memory(uint64_t address, SIZE_T size, PVOID* mappedAddress)
	//{
	//	PHYSICAL_ADDRESS physicalAddress;
	//	physicalAddress.QuadPart = address;

	//	OBJECT_ATTRIBUTES objectAttributes;
	//	InitializeObjectAttributes(&objectAttributes, NULL, OBJ_KERNEL_HANDLE, NULL, NULL);

	//	HANDLE sectionHandle;
	//	NTSTATUS status = ZwCreateSection(&sectionHandle, SECTION_MAP_READ | SECTION_MAP_WRITE, &objectAttributes, NULL, PAGE_READWRITE, SEC_COMMIT, NULL);
	//	if (!NT_SUCCESS(status))
	//	{
	//		return status;
	//	}

	//	LARGE_INTEGER sectionOffset;
	//	sectionOffset.QuadPart = 0;

	//	SIZE_T viewSize = size;
	//	*mappedAddress = NULL;
	//	status = ZwMapViewOfSection(sectionHandle, ZwCurrentProcess(), mappedAddress, 0, viewSize, &sectionOffset, &viewSize, ViewShare, 0, PAGE_READWRITE);
	//	ZwClose(sectionHandle);

	//	return status;
	//}

	//NTSTATUS write_physical_address(uint64_t address, PVOID buffer, SIZE_T size, SIZE_T* written)
	//{
	//	if (!address)
	//		return STATUS_UNSUCCESSFUL;

	//	PVOID pmapped_mem = NULL;

	//	NTSTATUS status = map_physical_memory(address, size, &pmapped_mem);
	//	if (!NT_SUCCESS(status))
	//		return status;

	//	Log("mapped physical memory -> address 0x%x, size %zu", address, size);

	//	memcpy(pmapped_mem, buffer, size);

	//	*written = size;

	//	ZwUnmapViewOfSection(ZwCurrentProcess(), pmapped_mem);

	//	return STATUS_SUCCESS;
	//}
}
