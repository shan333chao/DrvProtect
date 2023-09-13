#pragma once
#include "PMemory.h"


namespace p_memory {




	PVOID split_memory(PVOID SearchBase, SIZE_T SearchSize, const void* Pattern, SIZE_T PatternSize)
	{
		PUCHAR searchBase = (PUCHAR)SearchBase;
		PUCHAR pattern = (PUCHAR)Pattern;

		for (SIZE_T i = 0; i <= SearchSize - PatternSize; ++i) {
			SIZE_T j = 0;
			for (; j < PatternSize; ++j) {
				if (searchBase[i + j] != pattern[j])
					break;
			}
			if (j == PatternSize)
				return (PUCHAR)&searchBase[i];
		}
		return NULL;
	}
	ULONG_PTR GetCr3FromSectionBase(PEPROCESS pTargetProcess) {

		PVOID sectionBase = imports::ps_get_process_section_base_address(pTargetProcess);
		if (sectionBase)
		{
			return Cr3FromSectionBaseAddress(sectionBase);
		}
		return 0;
	}


	PVOID InitializeMmPfnDatabase()
	{
		static PVOID g_mmonp_MmPfnDatabase = NULL;
		if (g_mmonp_MmPfnDatabase != NULL)
		{
			return g_mmonp_MmPfnDatabase;
		}
		MmPfnDatabaseSearchPattern patterns = { 0 };

		// Windows 10 x64 Build 14332+
		static const UCHAR kPatternWin10x64[] = {
			0x48, 0x8B, 0xC1,        // mov     rax, rcx
			0x48, 0xC1, 0xE8, 0x0C,  // shr     rax, 0Ch
			0x48, 0x8D, 0x14, 0x40,  // lea     rdx, [rax + rax * 2]
			0x48, 0x03, 0xD2,        // add     rdx, rdx
			0x48, 0xB8,              // mov     rax, 0FFFFFA8000000008h
		};

		patterns.bytes = (PUCHAR)kPatternWin10x64;
		patterns.bytes_size = sizeof(kPatternWin10x64);
		patterns.hard_coded = TRUE;


		PUCHAR found = (PUCHAR)split_memory((PVOID)imports::imported.mm_get_virtual_for_physical, 0x20, patterns.bytes, patterns.bytes_size);
		if (!found) {
			return NULL;
		}


		found += patterns.bytes_size;
		if (patterns.hard_coded) {
			g_mmonp_MmPfnDatabase = *(void**)(found);
		}
		else {
			ULONG_PTR mmpfn_address = *(ULONG_PTR*)(found);
			g_mmonp_MmPfnDatabase = *(void**)(mmpfn_address);
		}

		g_mmonp_MmPfnDatabase = PAGE_ALIGN(g_mmonp_MmPfnDatabase);

		return g_mmonp_MmPfnDatabase;
	}

	static ULONG_PTR g_last_cr3 = 0;
	ULONG_PTR Cr3FromSectionBaseAddress(PVOID SectionBase)
	{
		if (!SectionBase || (ULONG64)SectionBase >= imports::imported.mm_user_probe_address)
		{
			return 0;
		}
		PVOID MmPfnDatabase = InitializeMmPfnDatabase();
		if (!MmPfnDatabase)
			return 0;
		virt_addr_t virt_base = { 0 };
		virt_base.value = SectionBase;
		size_t read = 0;
		PPHYSICAL_MEMORY_RANGE ranges = imports::mm_get_physical_memory_ranges();

		for (int i = 0;; i++) {

			PPHYSICAL_MEMORY_RANGE elem = &ranges[i];

			if (!elem->BaseAddress.QuadPart || !elem->NumberOfBytes.QuadPart)
				break;

			uintptr_t current_phys_address = elem->BaseAddress.QuadPart;

			for (int j = 0; j < (elem->NumberOfBytes.QuadPart / 0x1000); j++, current_phys_address += 0x1000) {

				PMMPFN pnfinfo = (PMMPFN)((uintptr_t)MmPfnDatabase + (current_phys_address >> 12) * sizeof(MMPFN));

				if (pnfinfo->u4.PteFrame == (current_phys_address >> 12)) {
					MMPTE pml4e = { 0 };
					if (!NT_SUCCESS(PhysReadAddress((PVOID)(current_phys_address + 8 * virt_base.pml4_index), &pml4e, 8, &read)))
						continue;

					if (!pml4e.u.Hard.Valid)
						continue;

					MMPTE pdpte = { 0 };
					if (!NT_SUCCESS(PhysReadAddress((PVOID)((pml4e.u.Hard.PageFrameNumber << 12) + 8 * virt_base.pdpt_index), &pdpte, 8, &read)))
						continue;

					if (!pdpte.u.Hard.Valid)
						continue;

					MMPTE pde = { 0 };
					if (!NT_SUCCESS(PhysReadAddress((PVOID)((pdpte.u.Hard.PageFrameNumber << 12) + 8 * virt_base.pd_index), &pde, 8, &read)))
						continue;

					if (!pde.u.Hard.Valid)
						continue;

					MMPTE pte = { 0 };
					if (!NT_SUCCESS(PhysReadAddress((PVOID)((pde.u.Hard.PageFrameNumber << 12) + 8 * virt_base.pt_index), &pte, 8, &read)))
						continue;

					if (!pte.u.Hard.Valid)
						continue;

					return current_phys_address;
				}
			}
		}
		return 0;
	}



	//¹Ì¶¨Æ«ÒÆµÄcr3
	ULONG_PTR GetProcessCR3(PEPROCESS pTargetProcess)
	{
		if (!pTargetProcess)
			return 0;

		PUCHAR process = (PUCHAR)pTargetProcess;
		ULONG_PTR process_dirbase = *(PULONG_PTR)(process + 0x28);
		if (process_dirbase == 0)
		{
			ULONG userdiroffset = GetCR3Offsets();
			ULONG_PTR process_userdirbase = *(PULONG_PTR)(process + userdiroffset);
			return process_userdirbase;
		}
		return process_dirbase;
	}

	ULONG64 Convert2PhyAddress(ULONG64 CR3base, ULONG64 VirtualAddress)
	{
		CR3base &= ~0xf;

		ULONG64 pageoffset = VirtualAddress & ~(~0ul << PAGE_OFFSET_SIZE);
		ULONG64 pte = ((VirtualAddress >> 12) & (0x1ffll));
		ULONG64 pt = ((VirtualAddress >> 21) & (0x1ffll));
		ULONG64 pd = ((VirtualAddress >> 30) & (0x1ffll));
		ULONG64 pdp = ((VirtualAddress >> 39) & (0x1ffll));

		SIZE_T readsize = 0;
		ULONG64 pdpe = 0;
		PhysReadAddress((void*)(CR3base + 8 * pdp), &pdpe, sizeof(pdpe), &readsize);
		if (~pdpe & 1)
			return 0;

		ULONG64 pde = 0;
		PhysReadAddress((void*)((pdpe & mask) + 8 * pd), &pde, sizeof(pde), &readsize);
		if (~pde & 1)
			return 0;

		/* 1GB large page, use pde's 12-34 bits */
		if (pde & 0x80)
			return (pde & (~0ull << 42 >> 12)) + (VirtualAddress & ~(~0ull << 30));

		ULONG64 ptraddr = 0;
		PhysReadAddress((void*)((pde & mask) + 8 * pt), &ptraddr, sizeof(ptraddr), &readsize);
		if (~ptraddr & 1)
			return 0;

		/* 2MB large page */
		if (ptraddr & 0x80)
			return (ptraddr & mask) + (VirtualAddress & ~(~0ull << 21));

		VirtualAddress = 0;
		PhysReadAddress((void*)((ptraddr & mask) + 8 * pte), &VirtualAddress, sizeof(VirtualAddress), &readsize);
		VirtualAddress &= mask;

		if (!VirtualAddress)
			return 0;

		return VirtualAddress + pageoffset;
	}

	NTSTATUS PhysReadAddress(PVOID address, PVOID buffer, SIZE_T size, SIZE_T* read)
	{
		if (!address)
			return STATUS_UNSUCCESSFUL;
 
#if (NTDDI_VERSION >= NTDDI_WIN8)
		MM_COPY_ADDRESS addr = { 0 };
		addr.PhysicalAddress.QuadPart = (LONGLONG)address;
		return imports::mm_copy_memory(buffer, addr, size, MM_COPY_MEMORY_PHYSICAL, read);
#else
		return STATUS_UNSUCCESSFUL;
#endif
	}


	NTSTATUS PhysWriteAddress(PVOID address, PVOID buffer, SIZE_T size, SIZE_T* written)
	{
		if (!address)
			return STATUS_UNSUCCESSFUL;

		PHYSICAL_ADDRESS addr = { 0 };
		addr.QuadPart = (LONGLONG)address;

		PVOID mapped_mem = imports::mm_map_io_space_ex(addr, size, PAGE_READWRITE);

		if (!mapped_mem)
			return STATUS_UNSUCCESSFUL;

		Utils::kmemcpy(mapped_mem, buffer, size);

		*written = size;
		imports::mm_unmap_io_space(mapped_mem, size);
		return STATUS_SUCCESS;
	}
	BOOLEAN safe_copy(PVOID dst, PVOID src, size_t size)
	{
		SIZE_T bytes = 0;
		
		if (imports::mm_copy_virtual_memory(imports::io_get_current_process(), src, imports::io_get_current_process(), dst, size, KernelMode, &bytes) == STATUS_SUCCESS && bytes == size)
		{
			return TRUE;
		}
		return FALSE;
	}

	NTSTATUS ReadProcessMemory(PEPROCESS process, PVOID address, PVOID buffer, SIZE_T size, SIZE_T* read)
	{
		//static PEPROCESS lastReadProcess = 0;
		//static ULONG_PTR rProcess_dirbase = 0;

		//if (process != lastReadProcess)
		//{
		//	lastReadProcess = process;
		//	//rProcess_dirbase = GetCr3FromSectionBase(process);
		//	rProcess_dirbase = GetProcessCR3(process);
		//}

		//if (!rProcess_dirbase)
		//{
		//	lastReadProcess = 0;
		//	rProcess_dirbase = 0;
		//	return STATUS_UNSUCCESSFUL;
		//}
		ULONG_PTR rProcess_dirbase = GetProcessCR3(process);

		SIZE_T curoffset = 0;
		while (size)
		{
			ULONG64 addr = Convert2PhyAddress(rProcess_dirbase, (ULONG64)address + curoffset);
			if (!addr) return STATUS_UNSUCCESSFUL;

			ULONG64 readsize = min(PAGE_SIZE - (addr & 0xFFF), size);
			SIZE_T readreturn = 0;
			NTSTATUS readstatus = PhysReadAddress((void*)addr, (PVOID)((ULONG64)buffer + curoffset), readsize, &readreturn);
			size -= readreturn;
			curoffset += readreturn;
			if (readstatus != STATUS_SUCCESS) break;
			if (readreturn == 0) break;
		}

		*read = curoffset;
		return STATUS_SUCCESS;
	}

	NTSTATUS WriteProcessMemory(PEPROCESS process, PVOID address, PVOID buffer, SIZE_T size, SIZE_T* written)
	{

		//static PEPROCESS lastWriteProcess = 0;
		//static ULONG_PTR wProcess_dirbase = 0;

		//if (process != lastWriteProcess)
		//{
		//	lastWriteProcess = process;
		//	//wProcess_dirbase = GetCr3FromSectionBase(process);
		//	lastWriteProcess = GetProcessCR3(process);
		//}
		//if (!wProcess_dirbase)
		//{
		//	lastWriteProcess = 0;
		//	wProcess_dirbase = 0;
		//	return STATUS_UNSUCCESSFUL;
		//}
		ULONG_PTR wProcess_dirbase = GetProcessCR3(process);
		SIZE_T curoffset = 0;
		while (size)
		{
			ULONG64 addr = Convert2PhyAddress(wProcess_dirbase, (ULONG64)address + curoffset);
			if (!addr) return STATUS_UNSUCCESSFUL;

			ULONG64 writesize = min(PAGE_SIZE - (addr & 0xFFF), size);
			SIZE_T written = 0;
			NTSTATUS writestatus = PhysWriteAddress((void*)addr, (PVOID)((ULONG64)buffer + curoffset), writesize, &written);
			size -= written;
			curoffset += written;
			if (writestatus != STATUS_SUCCESS) break;
			if (written == 0) break;
		}

		*written = curoffset;
		return STATUS_SUCCESS;
	}


	ULONG GetCR3Offsets()
	{
		switch (Utils::InitOsVersion().dwBuildNumber)
		{
		case WINDOWS_1803:
			return 0x0278;
			break;
		case WINDOWS_1809:
			return 0x0278;
			break;
		case WINDOWS_1903:
			return 0x0280;
			break;
		case WINDOWS_1909:
			return 0x0280;
			break;
		case WINDOWS_2004:
			return 0x0388;
			break;
		case WINDOWS_20H2:
			return 0x0388;
			break;
		case WINDOWS_21H1:
			return 0x0388;
			break;
		default:
			return 0x0388;
		}
	}

}