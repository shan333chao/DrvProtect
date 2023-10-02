#include "MiMemory.h"

#pragma warning(disable : 4554)

// =====================================================================================================================
// Define macro to adjust the map threshold value.
// =====================================================================================================================
#define PHYSICAL_MAP_THRESHOLD(Address, TotalSize) ((PAGE_SIZE - ((ULONGLONG)PAGE_SIZE - (Address & 0xFFF) & 0xFFF) < (TotalSize)) ? (PAGE_SIZE - (Address & 0xFFF)) : (TotalSize))

#define PAGE_OFFSET_SIZE                           12
#define PMASK                                      (~0xfull << 8) & 0xfffffffffull

#define PHY_ADDRESS_MASK                           0x000ffffffffff000ull
#define PHY_ADDRESS_MASK_1GB_PAGES                 0x000fffffc0000000ull
#define PHY_ADDRESS_MASK_2MB_PAGES                 0x000fffffffe00000ull
#define VADDR_ADDRESS_MASK_1GB_PAGES               0x000000003fffffffull
#define VADDR_ADDRESS_MASK_2MB_PAGES               0x00000000001fffffull
#define VADDR_ADDRESS_MASK_4KB_PAGES               0x0000000000000fffull
#define ENTRY_PRESENT_BIT                          1
#define ENTRY_PAGE_SIZE_BIT                        0x0000000000000080ull

// =====================================================================================================================
// Define inline Function.
// =====================================================================================================================
namespace MiMemory {

	PVOID GetProcessRundownProtect(PEPROCESS pEprocess) {
		static ULONG rundown_offset = 0;
		if (!rundown_offset)
		{
			ULONGLONG address = Utils::find_pattern_image((ULONGLONG)Utils::GetKernelBase(),
				skCrypt("\x33\xD2\x48\x00\x00\x00\x00\x00\x00\xE8\x00\x00\x00\x00\x84\xC0\x74\x00\xBA\x00\x00\x00\x00"),
				skCrypt("xxx??????x????xxx?x????"),
				skCrypt("PAGE"));
			if (!address)
			{
				return 0;
			}
			rundown_offset = *(PULONG)(address + 5);
			Log("rundown_offset %08x \r\n", rundown_offset);
		}
		return (PVOID)((PUCHAR)pEprocess + rundown_offset);
	}

	FORCEINLINE BOOLEAN IsDirectoryBaseEncrypted(ULONGLONG DirectoryBase)
	{
		BOOLEAN Encrypted = (DirectoryBase >> 0x38) == 0x40;
		return Encrypted;
	}

	FORCEINLINE ULONGLONG DecryptDirectoryBaseEAC(ULONGLONG DirectoryBase)
	{
#define __ROR__(num, bits)    ((num >> bits) | (num << (64 - bits))) & 0xFFFFFFFFFFFFFFFF
#define DECRYPT_CR3(cr3, key) (cr3 & 0xBFFF000000000FFF) | ((_byteswap_uint64(__ROR__(-1i64 - key, 29)) & 0xFFFFFFFFF) << 12)

		ULONGLONG Destination = 0;
		ULONG size = 0;
		ULONGLONG eac_module = Utils::GetKernelModule(skCrypt("EasyAntiCheat_EOS.sys"), &size);


		if (eac_module)
		{
			LONGLONG offset = *(LONGLONG*)(eac_module + 0x14D9E0);

			if (offset)
			{
				ULONGLONG data_offset = (offset & 0xFFFFFFFFF) << 12;
				ULONGLONG data = ((0xFFFFULL << 48) + data_offset);
				ULONGLONG key = *(ULONGLONG*)(data + 0x14);
				Destination = DECRYPT_CR3(DirectoryBase, key);
			}
		}

		return Destination;
	}

	FORCEINLINE NTSTATUS MiCopyPhysicalMemory(ULONGLONG PhysicalAddress, PVOID Buffer, SIZE_T NumberOfBytes, BOOLEAN DoWrite)
	{
		NTSTATUS         Status;
		SIZE_T           TotalBytes, BytesCopied, BytesToCopy;
		PVOID            MapSection;
		PHYSICAL_ADDRESS Address;

		Status = STATUS_INFO_LENGTH_MISMATCH;
		TotalBytes = NumberOfBytes;
		BytesCopied = 0;
		BytesToCopy = 0;
		MapSection = NULL;

		while (TotalBytes)
		{
			Status = STATUS_INSUFFICIENT_RESOURCES;
			Address.QuadPart = PhysicalAddress + BytesCopied;
			BytesToCopy = PHYSICAL_MAP_THRESHOLD(Address.QuadPart, TotalBytes);
			MapSection = MmMapIoSpaceEx(Address, BytesToCopy, PAGE_READWRITE);

			if (MapSection)
			{
				switch (DoWrite)
				{
				case TRUE:
					RtlCopyMemory(MapSection, RtlOffsetToPointer(Buffer, BytesCopied), BytesToCopy);
					break;
				case FALSE:
					RtlCopyMemory(RtlOffsetToPointer(Buffer, BytesCopied), MapSection, BytesToCopy);
					break;
				}

				MmUnmapIoSpace(MapSection, BytesToCopy);
				Status = STATUS_SUCCESS;
				BytesCopied += BytesToCopy;
				TotalBytes -= BytesToCopy;
			}

			if (Status != STATUS_SUCCESS) break;
		}

		return Status;
	}

	FORCEINLINE ULONGLONG MiVirtualToPhysical(_In_ ULONGLONG DirectoryBase, _In_ ULONGLONG VirtualAddress)
	{
		ULONGLONG       table, PhysicalAddress = 0, selector, entry = 0;
		LONG            r, shift;
		SIZE_T          NumberOfBytesCopied;
		MM_COPY_ADDRESS MmAddress;

		table = DirectoryBase & PHY_ADDRESS_MASK;

		for (r = 0; r < 4; r++)
		{
			shift = 39 - (r * 9);
			selector = (VirtualAddress >> shift) & 0x1ff;
			NumberOfBytesCopied = 0;
			MmAddress.PhysicalAddress.QuadPart = table + selector * 8;

			if (!NT_SUCCESS(MmCopyMemory(&entry, MmAddress, sizeof(ULONGLONG), MM_COPY_MEMORY_PHYSICAL, &NumberOfBytesCopied)))
			{
				return PhysicalAddress;
			}

			if (!(entry & ENTRY_PRESENT_BIT))
			{
				return PhysicalAddress;
			}

			table = entry & PHY_ADDRESS_MASK;
			if (entry & ENTRY_PAGE_SIZE_BIT)
			{
				if (r == 1)
				{
					table &= PHY_ADDRESS_MASK_1GB_PAGES;
					table += VirtualAddress & VADDR_ADDRESS_MASK_1GB_PAGES;
					PhysicalAddress = table;
					return PhysicalAddress;
				}

				if (r == 2)
				{
					table &= PHY_ADDRESS_MASK_2MB_PAGES;
					table += VirtualAddress & VADDR_ADDRESS_MASK_2MB_PAGES;
					PhysicalAddress = table;
					return PhysicalAddress;
				}
			}
		}

		table += VirtualAddress & VADDR_ADDRESS_MASK_4KB_PAGES;
		PhysicalAddress = table;
		return PhysicalAddress;
	}


	// =====================================================================================================================
	// System Memory Read-Write Virtual Memory via MmMapIoSpace.
	// =====================================================================================================================

	NTSTATUS MiReadSystemMemory(IN PVOID Source, OUT PVOID Destination, IN SIZE_T NumberOfBytes)
	{
		NTSTATUS         Status;
		PHYSICAL_ADDRESS Address;

		Status = STATUS_INVALID_ADDRESS;

		if (!MmIsAddressValid(Destination))
		{
			return Status;
		}

		Status = STATUS_PROCESS_IS_TERMINATING;
		PEX_RUNDOWN_REF rundownRef = (PEX_RUNDOWN_REF)GetProcessRundownProtect(PsInitialSystemProcess);
		if (ExAcquireRundownProtection(rundownRef) == FALSE)
		{
			Log("[-] Process already terminating.");
			return Status;
		}

		Address = MmGetPhysicalAddress(Source);
		Status = STATUS_CONFLICTING_ADDRESSES;

		if (Address.QuadPart)
		{
			Status = MiCopyPhysicalMemory(Address.QuadPart, Destination, NumberOfBytes, FALSE);
		}

		ExReleaseRundownProtection(rundownRef);
		return Status;
	}

	NTSTATUS MiWriteSystemMemory(IN PVOID Destination, OUT PVOID Source, IN SIZE_T NumberOfBytes)
	{
		NTSTATUS         Status;
		PHYSICAL_ADDRESS Address;

		Status = STATUS_INVALID_ADDRESS;

		if (!MmIsAddressValid(Source))
		{
			return Status;
		}

		Status = STATUS_PROCESS_IS_TERMINATING;
		PEX_RUNDOWN_REF rundownRef = (PEX_RUNDOWN_REF)GetProcessRundownProtect(PsInitialSystemProcess);
		if (ExAcquireRundownProtection(rundownRef) == FALSE)
		{
			Log("[-] Process already terminating.");
			return Status;
		}

		Address = MmGetPhysicalAddress(Destination);
		Status = STATUS_CONFLICTING_ADDRESSES;

		if (Address.QuadPart)
		{
			Status = MiCopyPhysicalMemory(Address.QuadPart, Source, NumberOfBytes, TRUE);
		}

		ExReleaseRundownProtection(rundownRef);
		return Status;
	}

	// =====================================================================================================================
	// Define macro to adjust the map threshold value.
	// =====================================================================================================================

	NTSTATUS MiReadProcessMemory(IN PEPROCESS Process, IN PVOID Source, OUT PVOID Destination, IN SIZE_T NumberOfBytes)
	{
		NTSTATUS         Status;
		PHYSICAL_ADDRESS Address;
		PEPROCESS        ProcessToLock;

		// ==================================================================================
		// TODO: Should the add additional check
		// to process object.
		// ==================================================================================
		Status = STATUS_ACCESS_VIOLATION;
		ProcessToLock = Process;
		//if ((RtlOffsetToPointer(Source, NumberOfBytes) < (PCHAR)Source)  )
		//{
		//	Log("[-] Access violation on Usermode Address.");
		//	return Status;
		//}
		//if (RtlOffsetToPointer(Destination, NumberOfBytes) < (PCHAR)Destination)
		//{
		//	Log("[-] Access violation on Usermode Address.");
		//	return Status;
		//}
		//if ( RtlOffsetToPointer(Source, NumberOfBytes) > (PCHAR)MM_HIGHEST_USER_ADDRESS)
		//{
		//	Log("[-] Access violation on Usermode Address.");
		//	return Status;
		//}
		//if ((ULONGLONG)Source <= 10000 || (ULONGLONG)Destination <= 10000)
		//{
		//	Log("[-] Access violation on Usermode Address.");
		//	return Status;
		//}
		//if (RtlOffsetToPointer(Destination, NumberOfBytes) > (PCHAR)MM_HIGHEST_USER_ADDRESS)
		//{
		//	Log("[-] Access violation on Usermode Address.");
		//	return Status;
		//}

		if ((RtlOffsetToPointer(Source, NumberOfBytes) < (PCHAR)Source) || (RtlOffsetToPointer(Destination, NumberOfBytes) < (PCHAR)Destination) || (RtlOffsetToPointer(Source, NumberOfBytes) > (PCHAR)MM_HIGHEST_USER_ADDRESS)
			|| (ULONGLONG)Source <= 10000 || (ULONGLONG)Destination <= 10000)
		{
			Log("[-] Access violation on Usermode Address.");
			return Status;
		}

		Status = STATUS_INVALID_ADDRESS;

		if (!MmIsAddressValid(Destination))
		{
			Log("[-] Invalid Address.");
			return Status;
		}

		Status = STATUS_PROCESS_IS_TERMINATING;

		PEX_RUNDOWN_REF rundownRef = (PEX_RUNDOWN_REF)GetProcessRundownProtect(ProcessToLock);
		if (ExAcquireRundownProtection(rundownRef) == FALSE)
		{
			Log("[-] Process already terminating.");
			return Status;
		}

		Address.QuadPart = MiVirtualToPhysical(*(PULONG_PTR)((PUCHAR)Process + 0x28), (ULONGLONG)Source);
		Status = STATUS_CONFLICTING_ADDRESSES;

		if (Address.QuadPart)
		{
			MM_COPY_ADDRESS MmAddress;
			MmAddress.PhysicalAddress = Address;
			SIZE_T NumberOfBytesCopied;

			Status = MmCopyMemory(Destination, MmAddress, NumberOfBytes, MM_COPY_MEMORY_PHYSICAL, &NumberOfBytesCopied);
		}

		// ==================================================================================
		// Indicate that the vm operation is complete.
		// ==================================================================================
		ExReleaseRundownProtection(rundownRef);
		return Status;
	}

	NTSTATUS MiWriteProcessMemory(IN PEPROCESS Process, IN PVOID Destination, OUT PVOID Source, IN SIZE_T NumberOfBytes)
	{
		NTSTATUS         Status;
		PHYSICAL_ADDRESS Address;
		PEPROCESS        ProcessToLock;

		//
		// TODO: Should the add additional check
		// to process object.
		//

		Status = STATUS_ACCESS_VIOLATION;
		ProcessToLock = Process;

		if ((RtlOffsetToPointer(Source, NumberOfBytes) < (PCHAR)Source) || (RtlOffsetToPointer(Destination, NumberOfBytes) < (PCHAR)Destination) || (RtlOffsetToPointer(Source, NumberOfBytes) > (PCHAR)MM_HIGHEST_USER_ADDRESS)
			|| (RtlOffsetToPointer(Destination, NumberOfBytes) > (PCHAR)MM_HIGHEST_USER_ADDRESS) || (ULONGLONG)Source <= 10000 || (ULONGLONG)Destination <= 10000)
		{
			Log("[-] Access violation on Usermode Address.");
			return Status;
		}

		Status = STATUS_INVALID_ADDRESS;

		if (!MmIsAddressValid(Source))
		{
			Log("[-] Invalid Address.");
			return Status;
		}

		// ==================================================================================
		// Make sure the process still has an address space.
		// ==================================================================================
		Status = STATUS_PROCESS_IS_TERMINATING;
		PEX_RUNDOWN_REF rundownRef = (PEX_RUNDOWN_REF)GetProcessRundownProtect(ProcessToLock);
		if (ExAcquireRundownProtection(rundownRef) == FALSE)
		{
			Log("[-] Process already terminating.");
			return Status;
		}

#if 1
		ULONGLONG DirectoryBase;
		DirectoryBase = *(PULONG_PTR)((PUCHAR)Process + 0x28);
		Address.QuadPart = MiVirtualToPhysical(DirectoryBase, (ULONGLONG)Destination);
#else
		KAPC_STATE ApcState;
		KeStackAttachProcess((PRKPROCESS)&ProcessToLock->Pcb, &ApcState);
		Address = MmGetPhysicalAddress(Destination);
		KeUnstackDetachProcess(&ApcState);
#endif

		if (!Address.QuadPart)
		{
			Log("[-] Failed Translating Source Address.");
			goto CompleteService;
		}

		Status = MiCopyPhysicalMemory(Address.QuadPart, Source, NumberOfBytes, TRUE);

	CompleteService:

		// ==================================================================================
		// Indicate that the vm operation is complete.
		// ==================================================================================
		ExReleaseRundownProtection(rundownRef);
		return Status;
	}
}