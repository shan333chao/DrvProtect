#pragma once
#include "Memory.h"
#include "PMemory.h"
#include  "../SSDT/Functions.h"



BOOLEAN IsAddressValid(PVOID Address, ULONG_PTR uSize) {
	BOOLEAN result = FALSE;
	if (Address == NULL)
	{
		return result;
	}
	result = uSize == 0 || ((PUCHAR)Address + uSize) < Address || Address >= MmUserProbeAddress || ((PUCHAR)Address + uSize) > MmUserProbeAddress;
	return result;
}

NTSTATUS mNtProtectVirtualMemory(HANDLE ProcessHandle, PVOID* BaseAddress, PSIZE_T RegionSize, ULONG NewProtect, PULONG OldProtect)
{
	MODE oldMode = SetThreadPrevious(KeGetCurrentThread(), KernelMode);
	NTSTATUS status;
	PNtProtectVirtualMemory MyNtProtectVirtualMemory = GetNtProtectVirtualMemory();
	if (!MyNtProtectVirtualMemory)
	{
		return STATUS_UNSUCCESSFUL;

	}
	status = MyNtProtectVirtualMemory(ProcessHandle, BaseAddress, RegionSize, NewProtect, OldProtect);
	SetThreadPrevious(KeGetCurrentThread(), oldMode);


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
	status = PsLookupProcessByProcessId((HANDLE)uPid, &pTargetEprocess);
	if (!NT_SUCCESS(status)) return status;
	//判断进程状态
	status = PsGetProcessExitStatus(pTargetEprocess);
	if (status != STATUS_PENDING) {
		ObDereferenceObject(pTargetEprocess);
		return status;
	}
	if (!pFakeObject)
	{
		//获取傀儡进程
		status = PsLookupProcessByProcessId((HANDLE)uFakePid, &pFakeEprocess);
		if (!NT_SUCCESS(status)) {
			ObDereferenceObject(pTargetEprocess);
			return status;
		}
		pFakeObject = ExAllocatePool(NonPagedPool, PAGE_SIZE);
		if (!pFakeObject)
		{
			ObDereferenceObject(pTargetEprocess);
			ObDereferenceObject(pFakeEprocess);
			return status;
		}
		//复制傀儡进程
		RtlZeroMemory(pFakeObject, PAGE_SIZE);
		memcpy(pFakeObject, (PUCHAR)pFakeEprocess - 0x30, PAGE_SIZE);
	}
	pCopyFakeEprocess = (PEPROCESS)((PUCHAR)pFakeObject + 0x30);
	//替换页表地址 
	uProtectCr3 = *(PULONG_PTR)((PUCHAR)pTargetEprocess + 0x28);
	*(PULONG_PTR)((PUCHAR)pCopyFakeEprocess + 0x28) = uProtectCr3;
	ULONG64 GotSize = 0;
	//读取内存
	status = MmCopyVirtualMemory(pCopyFakeEprocess, Address, IoGetCurrentProcess(), ReadBuffer, uReadSize, KernelMode, &GotSize);
	ObDereferenceObject(pTargetEprocess);
	ObDereferenceObject(pFakeEprocess);
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
	status = PsLookupProcessByProcessId((HANDLE)uPid, &pTargetEprocess);
	if (!NT_SUCCESS(status)) return status;
	//判断进程状态
	status = PsGetProcessExitStatus(pTargetEprocess);
	if (status != STATUS_PENDING) {
		ObDereferenceObject(pTargetEprocess);
		return status;
	}
	if (!pFakeObject)
	{
		//获取傀儡进程
		status = PsLookupProcessByProcessId((HANDLE)uFakePid, &pFakeEprocess);
		if (!NT_SUCCESS(status)) {
			ObDereferenceObject(pTargetEprocess);
			return status;
		}
		pFakeObject = ExAllocatePool(NonPagedPool, PAGE_SIZE);
		//复制傀儡进程
		RtlZeroMemory(pFakeObject, PAGE_SIZE);
		memcpy(pFakeObject, (PUCHAR)pFakeEprocess - 0x30, PAGE_SIZE);
	}
	pCopyFakeEprocess = (PEPROCESS)((PUCHAR)pFakeObject + 0x30);
	//替换页表地址 
	uProtectCr3 = *(PULONG_PTR)((PUCHAR)pTargetEprocess + 0x28);
	*(PULONG_PTR)((PUCHAR)pCopyFakeEprocess + 0x28) = uProtectCr3;
	ULONG64 GotSize = 0;


	//第一次写入内存
	status = MmCopyVirtualMemory(IoGetCurrentProcess(), WriteBuffer, pCopyFakeEprocess, Address, uWriteSize, KernelMode, &GotSize);

	if (!NT_SUCCESS(status)) {
		PVOID pTempAddress = Address;
		SIZE_T size_t = uWriteSize;
		ULONG uOldProtect = 0;
		//挂靠目标进程 会被ETW捕获 需要特征定位NTProtectVirtualMemory
		KeStackAttachProcess(pCopyFakeEprocess, &kapc_state);
		status = mNtProtectVirtualMemory(NtCurrentProcess(), &pTempAddress, &size_t, PAGE_EXECUTE_WRITECOPY, &uOldProtect);
		//取消进程挂靠
		KeUnstackDetachProcess(&kapc_state);
		if (NT_SUCCESS(status))
		{
			status = MmCopyVirtualMemory(IoGetCurrentProcess(), WriteBuffer, pCopyFakeEprocess, Address, uWriteSize, KernelMode, &GotSize);
		}
		if (NT_SUCCESS(status)) {
			//挂靠目标进程
			KeStackAttachProcess(pCopyFakeEprocess, &kapc_state);
			///恢复内存属性
			status = mNtProtectVirtualMemory(NtCurrentProcess(), &pTempAddress, &size_t, uOldProtect, &uOldProtect);
			//取消进程挂靠
			KeUnstackDetachProcess(&kapc_state);
			return status;
		}
	}
	if (!NT_SUCCESS(status)) {
		{
			PVOID pTempInBuffer = ExAllocatePool(NonPagedPool, uWriteSize);
			if (!pTempInBuffer)
			{
				return 0;
			}
			memset(pTempInBuffer, 0, uWriteSize);
			memcpy(pTempInBuffer, WriteBuffer, uWriteSize);

			//挂靠目标进程
			KeStackAttachProcess(pCopyFakeEprocess, &kapc_state);
			///创建pMdl
			PMDL pMdl = IoAllocateMdl(Address, uWriteSize, FALSE, NULL, NULL);
			if (!pMdl) return 0;

			MmBuildMdlForNonPagedPool(pMdl);

			PVOID pAddr = MmMapLockedPagesSpecifyCache(pMdl, KernelMode, MmCached, NULL, NULL, NormalPagePriority);
			if (!pAddr) {
				IoFreeMdl(pMdl);
				KeUnstackDetachProcess(&kapc_state);
				ExFreePool(pTempInBuffer);
				return 0;
			}
			//写入内存
			memcpy(pAddr, pTempInBuffer, uWriteSize);
			MmUnmapLockedPages(pAddr, pMdl);
			IoFreeMdl(pMdl);
			//取消进程挂靠
			KeUnstackDetachProcess(&kapc_state);
			ExFreePool(pTempInBuffer);
			status = STATUS_SUCCESS;
		}

		ObDereferenceObject(pTargetEprocess);
		ObDereferenceObject(pFakeEprocess);
		return status;
	}

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
	status = PsLookupProcessByProcessId((HANDLE)uPid, &pTargetEprocess);
	if (!NT_SUCCESS(status)) return status;
	SIZE_T NumberOfReadSize = 0;
 
	status = ReadProcessMemory(pTargetEprocess, Address, ReadBuffer, uReadSize, &NumberOfReadSize);
	ObDereferenceObject(pTargetEprocess);
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
	status = PsLookupProcessByProcessId((HANDLE)uPid, &pTargetEprocess);
	if (!NT_SUCCESS(status)) return status;
	SIZE_T NumberOfWriteSize = 0;

	status = WriteProcessMemory(pTargetEprocess, Address, WriteBuffer, uWriteSize, &NumberOfWriteSize);
	ObDereferenceObject(pTargetEprocess);
	return status;
}

NTSTATUS SS_CreateMemory(ULONG uPid,  ULONG_PTR uSize, PULONG64 retAddress)
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
 
	status = PsLookupProcessByProcessId((HANDLE)uPid, &pTargetEprocess);
	if (!NT_SUCCESS(status)) return STATUS_INVALID_PARAMETER_1;
	//判断进程状态
	status = PsGetProcessExitStatus(pTargetEprocess);
	if (status != STATUS_PENDING) {
		ObDereferenceObject(pTargetEprocess);
		return status;
	}
 
	//挂靠目标进程
	KeStackAttachProcess(pTargetEprocess, &kapc_state);
	BaseAddr = ExAllocatePool(NonPagedPool, uSize);
	if (!BaseAddr)
	{
		KeUnstackDetachProcess(&kapc_state);
		ObDereferenceObject(pTargetEprocess);
		return STATUS_UNSUCCESSFUL;
	}
	memset(BaseAddr, 0, uSize);
	///创建pMdl
	pMdl = IoAllocateMdl(BaseAddr, uSize, FALSE, NULL, NULL);
	if (!pMdl) {
		ExFreePool(BaseAddr);
		KeUnstackDetachProcess(&kapc_state);
		ObDereferenceObject(pTargetEprocess);
		return STATUS_UNSUCCESSFUL;
	}
	//构建非分页物理页
	MmBuildMdlForNonPagedPool(pMdl);
	//MDL指向的物理页映射值虚拟地址
	MappAddr = MmMapLockedPagesSpecifyCache(pMdl, UserMode, MmCached, NULL, NULL, NormalPagePriority);
	if (!MappAddr) {
		IoFreeMdl(pMdl);
		ExFreePool(BaseAddr);
		KeUnstackDetachProcess(&kapc_state);
		ObDereferenceObject(pTargetEprocess);
		return STATUS_UNSUCCESSFUL;
	}
	//写入内存
	memset(MappAddr, 0, uSize);
	ChangePageAttributeExecute(MappAddr, uSize);
	//取消进程挂靠
	KeUnstackDetachProcess(&kapc_state);
	ObDereferenceObject(pTargetEprocess);
	*retAddress = MappAddr;

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
	ULONG64 versionNumber = InitOsVersion().dwBuildNumber;
	// win7或者1607以下
	if (versionNumber < WINDOWS_10_VERSION_REDSTONE1)
	{
		PTE_BASE = 0xFFFFF68000000000llu;
	}
	else {
		// win10 1607以上
		UNICODE_STRING MmGetVirtualForPhysicalStr = { 0 };
		RtlInitUnicodeString(&MmGetVirtualForPhysicalStr, L"MmGetVirtualForPhysical");
		PUCHAR MmGetVirtualForPhysicalAddr = MmGetSystemRoutineAddress(&MmGetVirtualForPhysicalStr);
		PTE_BASE = *(PULONG64)(MmGetVirtualForPhysicalAddr + 0x22);
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
			PHARDWARE_PTE	pde = getPde(uStartAddress);
			//判断P位
			if (pde && MmIsAddressValid(pde) && pde->Valid == 1)
			{
				pde->NoExecute = 0;
				//判断PS位 是不是大页
				if (pde->Global == 1)
				{
					continue;
				}
			}
			PHARDWARE_PTE	pte = getPte(uStartAddress);
			if (pte && MmIsAddressValid(pte) && pte->Valid == 1)
			{

				//判断P位 
				pte->NoExecute = 0;
				//刷新TLB
				__invlpg(uStartAddress);
			}
			uStartAddress += PAGE_SIZE;
		}
	}
}
