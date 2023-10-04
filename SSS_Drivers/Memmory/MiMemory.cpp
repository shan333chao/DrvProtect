#include "MiMemory.h"

#pragma warning(disable : 4554)

// =====================================================================================================================
// Define macro to adjust the map threshold value.
// =====================================================================================================================
#define PHYSICAL_MAP_THRESHOLD(address, TotalSize) ((PAGE_SIZE - ((ULONGLONG)PAGE_SIZE - (address & 0xFFF) & 0xFFF) < (TotalSize)) ? (PAGE_SIZE - (address & 0xFFF)) : (TotalSize))

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
	static QWORD g_memory_range_low = 0;
	static QWORD g_memory_range_high = 0;
	QWORD  read_i64(QWORD address)
	{
		QWORD result = 0;
		if (!read(address, &result, sizeof(result), 0))
		{
			return 0;
		}
		return result;
	}
	QWORD  translate(QWORD dir, QWORD va)
	{
		if (!g_memory_range_low || !g_memory_range_low)
		{
			PPHYSICAL_MEMORY_RANGE memory_range = imports::mm_get_physical_memory_ranges();
			if (memory_range == 0)
				return FALSE;

			int counter = 0;
			while (1)
			{
				if (memory_range[counter].BaseAddress.QuadPart == 0)
				{
					break;
				}
				counter++;
			}

			g_memory_range_low = memory_range[0].BaseAddress.QuadPart;
			g_memory_range_high = memory_range[counter - 1].BaseAddress.QuadPart + memory_range[counter - 1].NumberOfBytes.QuadPart;
			imports::ex_free_pool_with_tag(memory_range, 0);
		}
		__int64 v2; // rax
		__int64 v3; // rax
		__int64 v5; // rax
		__int64 v6; // rax

		v2 = read_i64(8 * ((va >> 39) & 0x1FF) + dir);
		if (!v2)
			return 0i64;

		if ((v2 & 1) == 0)
			return 0i64;

		v3 = read_i64((v2 & 0xFFFFFFFFF000i64) + 8 * ((va >> 30) & 0x1FF));
		if (!v3 || (v3 & 1) == 0)
			return 0i64;

		if ((v3 & 0x80u) != 0i64)
			return (va & 0x3FFFFFFF) + (v3 & 0xFFFFFFFFF000i64);

		v5 = read_i64((v3 & 0xFFFFFFFFF000i64) + 8 * ((va >> 21) & 0x1FF));
		if (!v5 || (v5 & 1) == 0)
			return 0i64;

		if ((v5 & 0x80u) != 0i64)
			return (va & 0x1FFFFF) + (v5 & 0xFFFFFFFFF000i64);

		v6 = read_i64((v5 & 0xFFFFFFFFF000i64) + 8 * ((va >> 12) & 0x1FF));
		if (v6 && (v6 & 1) != 0)
			return (va & 0xFFF) + (v6 & 0xFFFFFFFFF000i64);

		return 0i64;
	}
 
	BOOL read(QWORD address, PVOID buffer, QWORD length, QWORD* ret)
	{
		BYTE MM_COPY_BUFFER[0x1000];

		if (address < (QWORD)g_memory_range_low)
		{
			return 0;
		}

		if (address + length > g_memory_range_high)
		{
			return 0;
		}

		if (length > 0x1000)
		{
			length = 0x1000;
		}

		MM_COPY_ADDRESS physical_address{};
		physical_address.PhysicalAddress.QuadPart = (LONGLONG)address;

		BOOL v = imports::mm_copy_memory(MM_COPY_BUFFER, physical_address, length, MM_COPY_MEMORY_PHYSICAL, &length) == 0;
		if (v)
		{
			for (QWORD i = length; i--;)
			{
				((unsigned char*)buffer)[i] = ((unsigned char*)MM_COPY_BUFFER)[i];
			}
		}

		if (ret)
			*ret = length;

		return v;
	}

	BOOL  write(QWORD address, PVOID buffer, QWORD length)
	{
		if (address < (QWORD)g_memory_range_low)
		{
			return 0;
		}

		if (address + length > g_memory_range_high)
		{
			return 0;
		}

		PVOID va = imports::mm_map_io_space(*(PHYSICAL_ADDRESS*)&address, length, MEMORY_CACHING_TYPE::MmNonCached);
		if (va)
		{
			for (QWORD i = length; i--;)
			{
				((BYTE*)va)[i] = ((BYTE*)buffer)[i];
			}
			imports::mm_unmap_io_space(va, length);
			return 1;
		}
		return 0;
	}
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




	NTSTATUS MiReadProcessMemory(IN PEPROCESS process, IN PVOID address, OUT PVOID buffer, IN SIZE_T readSize)
	{

		NTSTATUS         Status;
		if (process == 0)
		{
			Status = STATUS_PROCESS_IS_TERMINATING;
			return Status;
		}

		QWORD cr3 = *(QWORD*)((QWORD)process + 0x28);
		if (cr3 == 0)
		{
			Status = STATUS_ACCESS_VIOLATION;
			return Status;
		}

		QWORD total_size = readSize;
		QWORD offset = 0;
		QWORD bytes_read = 0;
		QWORD physical_address;
		QWORD current_size;
		while (total_size)
		{
			physical_address = translate(cr3, (QWORD)((QWORD)address + offset));
			if (!physical_address)
			{
				Utils::self_safe_copy(process, (PVOID)((QWORD)address + offset), (PVOID)((QWORD)address + offset), 0x1000);
				physical_address = translate(cr3, (QWORD)((QWORD)address + offset));
			}

			if (!physical_address)
			{
				if (total_size >= 0x1000)
				{
					bytes_read = 0x1000;
				}
				else
				{
					bytes_read = total_size;
				}
				goto E0;
			}

			current_size = min(0x1000 - (physical_address & 0xFFF), total_size);
			if (!read(physical_address, (PVOID)((QWORD)buffer + offset), current_size, &bytes_read))
			{
				break;
			}
		E0:
			total_size -= bytes_read;
			offset += bytes_read;
		}

		Status = STATUS_SUCCESS;
		return Status;
	}

	NTSTATUS  MiWriteProcessMemory(PEPROCESS process, PVOID address, PVOID buffer, SIZE_T length)
	{
		NTSTATUS         Status;
		if (process == 0)
		{
			Status = STATUS_PROCESS_IS_TERMINATING;
			return Status;
		}

		QWORD cr3 = *(QWORD*)((QWORD)process + 0x28);
		if (cr3 == 0)
		{
			Status = STATUS_ACCESS_VIOLATION;
			return Status;
		}

		QWORD total_size = length;
		QWORD offset = 0;
		QWORD bytes_write = 0;

		QWORD physical_address;
		QWORD current_size;

		while (total_size) {
			physical_address = translate(cr3, (QWORD)((QWORD)address + offset));
			if (!physical_address) {
				if (total_size >= 0x1000)
				{
					bytes_write = 0x1000;
				}
				else
				{
					bytes_write = total_size;
				}
				goto E0;
			}
			current_size = min(0x1000 - (physical_address & 0xFFF), total_size);
			if (!write(physical_address, (PVOID)((QWORD)buffer + offset), current_size))
			{
				break;
			}
			bytes_write = current_size;
		E0:
			total_size -= bytes_write;
			offset += bytes_write;
		}
		Status = STATUS_SUCCESS;
		return Status;
	}

}