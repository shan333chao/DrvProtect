#include "PatternSearch.h"
#include "../Process/Process.h"
#include "../Memmory/Memory.h"
#include "../Memmory/VadModules.h"

namespace patternSearch {

	
	UCHAR read_i8(PEPROCESS process, ULONGLONG address)
	{
		UCHAR result = 0;

		if (!NT_SUCCESS(MiMemory::MiReadProcessMemory(process, (PVOID)address, &result, sizeof(result))))
		{
			return 0;
		}
		return result;
	}

	USHORT read_i16(PEPROCESS process, ULONGLONG address)
	{
		USHORT result = 0;
		if (!NT_SUCCESS(MiMemory::MiReadProcessMemory(process, (PVOID)address, &result, sizeof(result))))
		{
			return 0;
		}
		return result;
	}

	ULONG read_i32(PEPROCESS process, ULONGLONG address)
	{
		ULONG result = 0;
		if (!NT_SUCCESS(MiMemory::MiReadProcessMemory(process, (PVOID)address, &result, sizeof(result))))
		{
			return 0;
		}
		return result;
	}

	ULONGLONG read_i64(PEPROCESS process, ULONGLONG address)
	{
		ULONGLONG result = 0;
		if (!NT_SUCCESS(MiMemory::MiReadProcessMemory(process, (PVOID)address, &result, sizeof(result))))
		{
			return 0;
		}
		return result;
	}

	//float read_float(PEPROCESS process, ULONGLONG address)
	//{
	//	float result = 0;
	//	if (!MiMemory::MiReadProcessMemory(process, (PVOID)address, &result, sizeof(result)))
	//	{
	//		return 0;
	//	}
	//	return result;
	//}

	BOOLEAN write_i8(PEPROCESS process, ULONGLONG address, UCHAR value)
	{

		return NT_SUCCESS(MiMemory::MiWriteProcessMemory(process, (PVOID)address, &value, sizeof(value)));
	}

	BOOLEAN write_i16(PEPROCESS process, ULONGLONG address, USHORT value)
	{
		return NT_SUCCESS(MiMemory::MiWriteProcessMemory(process, (PVOID)address, &value, sizeof(value)));
	}

	BOOLEAN write_i32(PEPROCESS process, ULONGLONG address, ULONG value)
	{
		return NT_SUCCESS(MiMemory::MiWriteProcessMemory(process, (PVOID)address, &value, sizeof(value)));
	}

	BOOLEAN write_i64(PEPROCESS process, ULONGLONG address, ULONGLONG value)
	{
		return NT_SUCCESS(MiMemory::MiWriteProcessMemory(process, (PVOID)address, &value, sizeof(value)));
	}

	//BOOLEAN write_float(PEPROCESS process, ULONGLONG address, float value)
	//{
	//	return MiMemory::MiWriteProcessMemory(process, (PVOID)address, &value, sizeof(value));
	//}


	ULONGLONG  get_relative_address(PEPROCESS process, ULONGLONG instruction, ULONG offset, ULONG instruction_size)
	{
		INT32 rip_address = read_i32(process, instruction + offset);
		return (ULONGLONG)(instruction + instruction_size + rip_address);
	}
	//
// this function is very old, because back in that time i used short variable names it's quite difficult
// to remember how exactly this works :D
// it's mimimal port of Windows GetModuleHandleA to external. structure offsets are just fixed for both x86/x64.
//

	ULONGLONG get_module(PEPROCESS process, PCSTR dll_name, PULONG moduleSize)
	{


		ULONGLONG peb = (ULONGLONG)imports::ps_get_process_wow64_process(process);

		ULONG a0[6] = { 0 };
		ULONGLONG a1, a2;
		unsigned short a3[120] = { 0 };

		ULONGLONG(*read_ptr)(PEPROCESS process, ULONGLONG address) = 0;
		if (peb)
		{
			*(ULONGLONG*)&read_ptr = (ULONGLONG)read_i32;
			a0[0] = 0x04, a0[1] = 0x0C, a0[2] = 0x14, a0[3] = 0x28, a0[4] = 0x10, a0[5] = 0x18;
		}
		else
		{
			*(ULONGLONG*)&read_ptr = (ULONGLONG)read_i64;
			peb = (ULONGLONG)imports::ps_get_process_peb(process);
			a0[0] = 0x08, a0[1] = 0x18, a0[2] = 0x20, a0[3] = 0x50, a0[4] = 0x20, a0[5] = 0x30;
		}

		if (peb == 0)
		{
			return 0;
		}
		//读取ldr
		a1 = read_ptr(process, peb + a0[1]);
		if (a1 == 0)
		{
			return 0;
		}
		//[+0x020] InMemoryOrderModuleList [Type: _LIST_ENTRY]
		a1 = read_ptr(process, a1 + a0[2]);
		if (a1 == 0)
		{
			return 0;
		}
		//InMemoryOrderModuleList.FLink
		a2 = read_ptr(process, a1 + a0[0]);


		while (a1 != a2) {
			//读取unicodcodeString  maxlength
			ULONGLONG a4 = read_ptr(process, a1 + a0[3]);
			if (a4 != 0)
			{
				//读取字符串内容
				MiMemory::MiReadProcessMemory(process, (PVOID)a4, a3, sizeof(a3));
				if (dll_name == 0)
					return read_ptr(process, a1 + a0[4]);

				char final_name[120]{};
				for (int i = 0; i < 120; i++) {
					final_name[i] = (char)a3[i];
					if (a3[i] == 0)
						break;
				}

				if (strcmpi_imp((PCSTR)final_name, dll_name) == 0)
				{
					*moduleSize = read_ptr(process, a1 + a0[5]);
					//读取imageBase
					return read_ptr(process, a1 + a0[4]);
				}
			}
			a1 = read_ptr(process, a1);
			if (a1 == 0)
				break;
		}
		return 0;

	}

	//
	// this function is very old, because back in that time i used short variable names it's quite difficult
	// to remember how exactly this works :D
	// it's mimimal port of Windows GetProcAddress to external. structure offsets are just fixed for both x86/x64.
	//
	ULONGLONG get_module_export(PEPROCESS process, ULONGLONG base, PCSTR export_name)
	{
		ULONGLONG a0;
		ULONG a1[4]{};
		char a2[260]{};
		//NT HEADER
		a0 = base + read_i16(process, base + 0x3C);
		if (a0 == base)
		{
			return 0;
		}

		USHORT  machine = read_i16(process, a0 + 0x4);
		ULONG wow64_offset = machine == 0x8664 ? 0x88 : 0x78;
		//定位导出表地址
		a0 = base + (ULONGLONG)read_i32(process, a0 + wow64_offset);
		if (a0 == base)
		{
			return 0;
		}

		int name_length = (int)strlen_imp(export_name);
		if (name_length > 259)
			name_length = 259;
		//0x18  NumberOfNames
		MiMemory::MiReadProcessMemory(process, (PVOID)(a0 + 0x18), &a1, sizeof(a1));
		while (a1[0]--)
		{
			 //a[0] NumberOfNames
			// a[1] AddressOfFunctions
			// a[2] AddressOfNames
			// a[3] AddressOfNameOrdinals
			//读取导出名称的地址
			a0 = (ULONGLONG)read_i32(process, base + a1[2] + ((ULONGLONG)a1[0] * 4));
			if (a0)
			{
				//读取导出名称
				MiMemory::MiReadProcessMemory(process, (PVOID)(base + a0), &a2, name_length);
				a2[name_length] = 0;

				if (!strcmpi_imp(a2, export_name))
				{
					//通过AddressOfNameOrdinals  NumberOfNames*2  获取名字在导出表中的序号
					ULONG tmp = read_i16(process, base + a1[3] + ((ULONGLONG)a1[0] * 2)) * 4;
					//通过导出序号  在AddressOfNameOrdinals 找到函数偏移
					ULONG tmp2 = read_i32(process, base + a1[1] + tmp);
					return (base + tmp2);
				}
			}
		}
		return 0;
	}

	ULONGLONG scan_pattern(PVOID dumped_module, char* pattern, char* mask, ULONGLONG length)
	{
		ULONGLONG ret = 0;

		if (dumped_module == 0)
			return 0;

		ULONGLONG dos_header = (ULONGLONG)dumped_module;
		ULONGLONG nt_header = (ULONGLONG) * (ULONG*)(dos_header + 0x03C) + dos_header;
		USHORT  machine = *(USHORT*)(nt_header + 0x4);
		ULONGLONG section_header = machine == 0x8664 ?
			nt_header + 0x0108 :
			nt_header + 0x00F8;

		for (USHORT i = 0; i < *(USHORT*)(nt_header + 0x06); i++) {

			ULONGLONG section = section_header + ((ULONGLONG)i * 40);
			ULONG section_characteristics = *(ULONG*)(section + 0x24);

			if (section_characteristics & 0x00000020)
			{
				ULONGLONG section_address = dos_header + (ULONGLONG) * (ULONG*)(section + 0x0C);
				ULONG section_size = *(ULONG*)(section + 0x08);
				ULONGLONG address = Utils::find_pattern(section_address, section_size, pattern, mask, length);
				if (address)
				{
					ret = (address - (ULONGLONG)dumped_module) +
						*(ULONGLONG*)((ULONGLONG)dumped_module - 16);
					break;
				}
			}

		}
		return ret;
	}
	PVOID  dump_module(PEPROCESS process, ULONGLONG base, UCHAR module_type)
	{
		ULONGLONG nt_header;
		ULONG image_size;
		UCHAR* ret = 0;

		if (base == 0)
		{
			return 0;
		}

		nt_header = (ULONGLONG)read_i32(process, base + 0x03C) + base;
		if (nt_header == base)
		{
			return 0;
		}

		image_size = read_i32(process, nt_header + 0x050);
		if (image_size == 0)
		{
			return 0;
		}


		ret = (UCHAR*)imports::ex_allocate_pool(NonPagedPool, (ULONGLONG)(image_size + 16));

		if (ret == 0)
			return 0;

		*(ULONGLONG*)(ret + 0) = base;
		*(ULONGLONG*)(ret + 8) = image_size;
		ret += 16;


		ULONG headers_size = read_i32(process, nt_header + 0x54);

		MiMemory::MiReadProcessMemory(process, (PVOID)base, ret, headers_size);

		ULONGLONG dos_header = (ULONGLONG)ret;
		ULONGLONG pent_header = (ULONGLONG)(*(ULONG*)(dos_header + 0x03C) + dos_header);
		USHORT  machine = *(USHORT*)(pent_header + 0x4);

		ULONGLONG section_header = machine == 0x8664 ?
			nt_header + 0x0108 :
			nt_header + 0x00F8;


		USHORT NumberOfSections = *(USHORT*)(pent_header + 0x06);

		for (USHORT i = 0; i < NumberOfSections; i++) {
			ULONGLONG section = section_header + ((ULONGLONG)i * 40);
			if (module_type == VM_MODULE_CODESECTIONSONLY)
			{
				ULONG section_characteristics = read_i32(process, section + 0x24);
				if (!(section_characteristics & 0x00000020))
					continue;
			}

			ULONGLONG target_address = (ULONGLONG)ret + (ULONGLONG)read_i32(process, section + ((module_type == VM_MODULE_RAW) ? 0x14 : 0x0C));
			ULONGLONG virtual_address = base + (ULONGLONG)read_i32(process, section + 0x0C);
			ULONG virtual_size = read_i32(process, section + 0x08);
			MiMemory::MiReadProcessMemory(process, (PVOID)virtual_address, (PVOID)target_address, virtual_size);
		}

		return (PVOID)ret;
	}
	BOOLEAN  IsAddressInModule(PEPROCESS process, ULONGLONG base, UCHAR module_type, ULONG64 exportAddr)
	{
		ULONGLONG nt_header; 
		if (base == 0)
		{
			return 0;
		} 
		nt_header = (ULONGLONG)read_i32(process, base + 0x03C) + base;
		if (nt_header == base)
		{
			return 0;
		}

		USHORT  machine = read_i16(process, nt_header + 0x4);

		ULONGLONG section_header = machine == 0x8664 ?
			nt_header + 0x0108 :
			nt_header + 0x00F8;


		USHORT NumberOfSections = read_i16(process, nt_header + 0x06);

		for (USHORT i = 0; i < NumberOfSections; i++) {
			ULONGLONG section = section_header + ((ULONGLONG)i * 40);
			if (module_type == VM_MODULE_CODESECTIONSONLY)
			{
				ULONG section_characteristics = read_i32(process, section + 0x24);
				if (!(section_characteristics & 0x00000020))
					continue;
			}
			ULONGLONG virtual_address = base + (ULONGLONG)read_i32(process, section + 0x0C);
			ULONG virtual_size = read_i32(process, section + 0x08);
			if (exportAddr > virtual_address && exportAddr < (virtual_address + virtual_size))
			{
				return TRUE;
			} 
		} 
		return  FALSE;
	}
	void  free_module(PVOID dumped_module)
	{
		ULONGLONG a0 = (ULONGLONG)dumped_module;

		a0 -= 16;

		imports::ex_free_pool_with_tag((void*)a0, 0);

	}

	ULONGLONG scan_pattern_direct(PEPROCESS process, ULONGLONG base, char* pattern, char* mask, ULONG moduleSize)
	{
		if (base == 0)
		{
			return 0;
		}

		PVOID dumped_module = dump_module(process, base, VM_MODULE_CODESECTIONSONLY);

		if (dumped_module == 0)
		{
			return 0;
		}

		ULONGLONG patt = scan_pattern(dumped_module, pattern, mask, strlen_imp(mask));

		free_module(dumped_module);
		return patt;
	}



	ULONGLONG search_process_pattern(HANDLE pid, PCSTR dllName, char* pattern, char* mask)
	{

		if (!pid)
		{
			return 0;
		}
		PEPROCESS eprocess = Utils::lookup_process_by_id(pid);
		if (!eprocess)
		{
			return 0;
		}

		ULONGLONG moduleBase = 0;
		ULONG moduleSize = 0;
		moduleBase = get_module(eprocess, dllName, &moduleSize);
		if (!moduleBase)
		{
			return 0;
		}
		ULONGLONG addr = scan_pattern_direct(eprocess, moduleBase, pattern, mask, moduleSize);
		Log("search_process_pattern  %p \r\n ", addr);
		return addr;

	}
	VOID test() {

		search_process_pattern((HANDLE)6224, skCrypt("WinRAR.exe"),
			skCrypt("\x84\xC0\x41\x0F\x94\xC5\x45\x8A\xC6\xBE\x00\x00\x00\x00\x8B\xD6\x48\x8D\x00\x00\x00\x00\x00\x00\xE8\x00\x00\x00\x00"),
			skCrypt("xxxxxxxxxx????xxxx??????x????"));

	}


}