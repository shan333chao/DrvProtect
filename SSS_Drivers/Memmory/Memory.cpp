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
			return STATUS_INVALID_PARAMETER_4;

		}
 
		status = imports::ps_lookup_process_by_process_id((HANDLE)uPid, &pTargetEprocess);
		if (!NT_SUCCESS(status)) return status;
		//判断进程状态

		status = imports::ps_get_process_exit_status(pTargetEprocess);
		if (status != STATUS_PENDING) {
			imports::obf_dereference_object(pTargetEprocess);
			return status;
		}
		//if (!pFakeObject)
		//{
		//	//获取傀儡进程
		//	status = imports::ps_lookup_process_by_process_id((HANDLE)uFakePid, &pFakeEprocess);
		//	if (!NT_SUCCESS(status)) {
		//		imports::obf_dereference_object(pTargetEprocess);
		//		return status;
		//	}
		//	pFakeObject = imports::ex_allocate_pool(NonPagedPool, PAGE_SIZE);
		//	if (!pFakeObject)
		//	{
		//		imports::obf_dereference_object(pTargetEprocess);
		//		imports::obf_dereference_object(pFakeEprocess);
		//		return status;
		//	}

		//	//复制傀儡进程
		//	Utils::kmemset(pFakeObject, 0, PAGE_SIZE);

		//	Utils::kmemcpy(pFakeObject, (PUCHAR)pFakeEprocess - 0x30, PAGE_SIZE);
		//}
		//pCopyFakeEprocess = (PEPROCESS)((PUCHAR)pFakeObject + 0x30);
		////替换页表地址 
		//uProtectCr3 = *(PULONG_PTR)((PUCHAR)pTargetEprocess + 0x28);
		//*(PULONG_PTR)((PUCHAR)pCopyFakeEprocess + 0x28) = uProtectCr3;
		ULONG64 GotSize = 0;

		////读取内存
		//status = imports::mm_copy_virtual_memory(pCopyFakeEprocess, Address, imports::io_get_current_process(), ReadBuffer, uReadSize, KernelMode, &GotSize);

		//读取内存
		status = imports::mm_copy_virtual_memory(pTargetEprocess, Address, imports::io_get_current_process(), ReadBuffer, uReadSize, KernelMode, &GotSize);
		imports::obf_dereference_object(pTargetEprocess);
		//imports::obf_dereference_object(pFakeEprocess);
		return status;
	}
	NTSTATUS SS_WriteMemory(ULONG_PTR uPid, ULONG_PTR uFakePid, PVOID Address, ULONG_PTR uWriteSize, PVOID WriteBuffer)
	{
		PEPROCESS								pTargetEprocess = NULL;
		NTSTATUS								status = STATUS_UNSUCCESSFUL;
		static PEPROCESS						pFakeEprocess = NULL;
		static PVOID							pFakeObject = NULL;
		PEPROCESS								pCopyFakeEprocess = NULL;
		SIZE_T									NumberOfBytesCopied = NULL;
		PVOID									pTempBuffer = NULL;
		ULONG_PTR								uProtectCr3 = NULL;
		KAPC_STATE								kapc_state = { 0 };
		if (IsAddressValid(Address, uWriteSize))
		{
			return STATUS_INVALID_PARAMETER_2;
		}
		if (IsAddressValid(WriteBuffer, 1))
		{
			return STATUS_INVALID_PARAMETER_4;
		}
 
		status = imports::ps_lookup_process_by_process_id((HANDLE)uPid, &pTargetEprocess);
		if (!NT_SUCCESS(status)) return status;
		//判断进程状态
		status = imports::ps_get_process_exit_status(pTargetEprocess);
		if (status != STATUS_PENDING) {
			imports::obf_dereference_object(pTargetEprocess);
			return status;
		}
		if (!pFakeObject)
		{
			//获取傀儡进程
			status = imports::ps_lookup_process_by_process_id((HANDLE)uFakePid, &pFakeEprocess);
			if (!NT_SUCCESS(status)) {
				imports::obf_dereference_object(pTargetEprocess);
				return status;
			}
			pFakeObject = imports::ex_allocate_pool(NonPagedPool, PAGE_SIZE);
			//复制傀儡进程
			Utils::kmemset(pFakeObject, 0, PAGE_SIZE);
			Utils::kmemcpy(pFakeObject, (PUCHAR)pFakeEprocess - 0x30, PAGE_SIZE);
		}
		pCopyFakeEprocess = (PEPROCESS)((PUCHAR)pFakeObject + 0x30);
		//替换页表地址 
		uProtectCr3 = *(PULONG_PTR)((PUCHAR)pTargetEprocess + 0x28);
		*(PULONG_PTR)((PUCHAR)pCopyFakeEprocess + 0x28) = uProtectCr3;
		ULONG64 GotSize = 0;


		//第一次写入内存
		status = imports::mm_copy_virtual_memory(imports::io_get_current_process(), WriteBuffer, pCopyFakeEprocess, Address, uWriteSize, KernelMode, &GotSize);

		if (!NT_SUCCESS(status)) {
			PVOID pTempAddress = Address;
			SIZE_T size_t = uWriteSize;
			ULONG uOldProtect = 0;
			//挂靠目标进程 会被ETW捕获 需要特征定位NTProtectVirtualMemory
			imports::ke_stack_attach_process(pCopyFakeEprocess, &kapc_state);
			status = mNtProtectVirtualMemory(NtCurrentProcess(), &pTempAddress, &size_t, PAGE_EXECUTE_WRITECOPY, &uOldProtect);

			//取消进程挂靠
			imports::ke_unstack_detach_process(&kapc_state);
			if (NT_SUCCESS(status))
			{
				status = imports::mm_copy_virtual_memory(imports::io_get_current_process(), WriteBuffer, pCopyFakeEprocess, Address, uWriteSize, KernelMode, &GotSize);
			}
			if (NT_SUCCESS(status)) {
				//挂靠目标进程
				imports::ke_stack_attach_process(pCopyFakeEprocess, &kapc_state);
				///恢复内存属性
				status = mNtProtectVirtualMemory(NtCurrentProcess(), &pTempAddress, &size_t, uOldProtect, &uOldProtect);
				//取消进程挂靠
				imports::ke_unstack_detach_process(&kapc_state);
				return status;
			}
		}
		if (!NT_SUCCESS(status)) {

			PVOID pTempInBuffer = imports::ex_allocate_pool(NonPagedPool, uWriteSize);
			if (!pTempInBuffer)
			{
				return 0;
			}
			Utils::kmemset(pTempInBuffer, 0, uWriteSize);
			Utils::kmemcpy(pTempInBuffer, WriteBuffer, uWriteSize);

			//挂靠目标进程
			imports::ke_stack_attach_process(pCopyFakeEprocess, &kapc_state);
			///创建pMdl
			PMDL pMdl = imports::io_allocate_mdl(Address, uWriteSize, FALSE, NULL, NULL);
			if (!pMdl) return 0;

			imports::mm_build_mdl_for_non_paged_pool(pMdl);

			PVOID pAddr = imports::mm_map_locked_pages_specify_cache(pMdl, KernelMode, MmCached, NULL, NULL, NormalPagePriority);
			if (!pAddr) {
				imports::io_free_mdl(pMdl);
	 
				imports::ke_unstack_detach_process(&kapc_state);
				imports::ex_free_pool_with_tag(pTempInBuffer, 0);
				return 0;
			}
			//写入内存
			Utils::kmemcpy(pAddr, pTempInBuffer, uWriteSize);
			imports::mm_unmap_locked_pages(pAddr, pMdl);
			imports::io_free_mdl(pMdl);
			//取消进程挂靠
			imports::ke_unstack_detach_process(&kapc_state);
			imports::ex_free_pool_with_tag(pTempInBuffer, 0);
			status = STATUS_SUCCESS;
		}

		imports::obf_dereference_object(pTargetEprocess);
		imports::obf_dereference_object(pFakeEprocess);
		return status;


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
		status = imports::ps_lookup_process_by_process_id((HANDLE)uPid, &pTargetEprocess);
		if (!NT_SUCCESS(status)) return status;
		SIZE_T NumberOfReadSize = 0;

		 
		status = p_memory::ReadProcessMemory(pTargetEprocess, Address, ReadBuffer, uReadSize, &NumberOfReadSize);



		imports::obf_dereference_object(pTargetEprocess);
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
		status = imports::ps_lookup_process_by_process_id((HANDLE)uPid, &pTargetEprocess);
		if (!NT_SUCCESS(status)) return status;
		SIZE_T NumberOfWriteSize = 0;
 
		status = p_memory::WriteProcessMemory(pTargetEprocess, Address, WriteBuffer, uWriteSize, &NumberOfWriteSize);
		imports::obf_dereference_object(pTargetEprocess);
		return status;
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
		PMDL									pMdl = NULL;

		status = imports::ps_lookup_process_by_process_id((HANDLE)uPid, &pTargetEprocess);
		if (!NT_SUCCESS(status)) return STATUS_INVALID_PARAMETER_1;
		//判断进程状态
		status = imports::ps_get_process_exit_status(pTargetEprocess);
		if (status != STATUS_PENDING) {
			imports::obf_dereference_object(pTargetEprocess);
			return status;
		}

		//挂靠目标进程
		imports::ke_stack_attach_process(pTargetEprocess, &kapc_state);
		BaseAddr = imports::ex_allocate_pool(NonPagedPool, uSize);
		if (!BaseAddr)
		{
			imports::ke_unstack_detach_process(&kapc_state);
			imports::obf_dereference_object(pTargetEprocess);
			return STATUS_UNSUCCESSFUL;
		}

		Utils::kmemset(BaseAddr, 0, uSize);
		///创建pMdl
		pMdl = imports::io_allocate_mdl(BaseAddr, uSize, FALSE, NULL, NULL);
		if (!pMdl) {
			imports::ex_free_pool_with_tag(BaseAddr, 0);
			imports::ke_unstack_detach_process(&kapc_state);
			imports::obf_dereference_object(pTargetEprocess);
			return STATUS_UNSUCCESSFUL;
		}
		//构建非分页物理页
		imports::mm_build_mdl_for_non_paged_pool(pMdl);
		//MDL指向的物理页映射值虚拟地址
		MappAddr = imports::mm_map_locked_pages_specify_cache(pMdl, UserMode, MmCached, NULL, NULL, NormalPagePriority);
		if (!MappAddr) {
			imports::io_free_mdl(pMdl);
			imports::ex_free_pool_with_tag(BaseAddr, 0);
			imports::ke_unstack_detach_process(&kapc_state);
			imports::obf_dereference_object(pTargetEprocess);
			return STATUS_UNSUCCESSFUL;
		}
		//写入内存
		Utils::kmemset(MappAddr, 0, uSize);
		ChangePageAttributeExecute((ULONG64)MappAddr, uSize);
		//取消进程挂靠
		imports::ke_unstack_detach_process(&kapc_state);
		imports::obf_dereference_object(pTargetEprocess);
		*retAddress = (ULONG64)MappAddr;

		return STATUS_SUCCESS;
	}







	/// <summary>
	/// 获取系统版本号
	/// </summary>
	/// <returns></returns>
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

	ULONG64 getPdpte(ULONG64 VirtualAddress)
	{
		ULONG_PTR PTE_BASE = getPteBase();
		ULONG64 pde = getPde(VirtualAddress);
		return ((pde >> 9) & 0x7FFFFFFFF8) + PTE_BASE;
	}

	ULONG64 getPml4e(ULONG64 VirtualAddress)
	{
		ULONG_PTR PTE_BASE = getPteBase();
		ULONG64 ppe = getPdpte(VirtualAddress);
		return ((ppe >> 9) & 0x7FFFFFFFF8) + PTE_BASE;
	}


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

}
