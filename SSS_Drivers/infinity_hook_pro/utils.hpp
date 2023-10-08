#pragma once
#include "imports.hpp"
#include "hde/hde64.h"

namespace k_utils
{
	// 获取系统版本号
	unsigned long get_system_build_number()
	{
		unsigned long number = 0;
		RTL_OSVERSIONINFOEXW info{ 0 };
		info.dwOSVersionInfoSize = sizeof(OSVERSIONINFOEXW);
		
		if (NT_SUCCESS(imports::rtl_get_version((PRTL_OSVERSIONINFOW)&info))) number = info.dwBuildNumber;
		return number;
	}

	// 获取指定模块基址
	unsigned long long get_module_address(const char* name, unsigned long* size)
	{
		unsigned long long result = 0;

		unsigned long length = 0;
		
		imports::zw_query_system_information(SystemModuleInformation, &length, 0, &length);
		if (!length) return result;

		const unsigned long tag = 'VMON';
		
		PSYSTEM_MODULE_INFORMATION system_modules = (PSYSTEM_MODULE_INFORMATION)imports::ex_allocate_pool_with_tag(NonPagedPool, length, tag);
		if (!system_modules) return result;

		NTSTATUS status = imports::zw_query_system_information(SystemModuleInformation, system_modules, length, 0);
		if (NT_SUCCESS(status))
		{
			for (unsigned long long i = 0; i < system_modules->ulModuleCount; i++)
			{
				PSYSTEM_MODULE mod = &system_modules->Modules[i];
				if (Utils::kstrstr(mod->ImageName, name))
				{
					result = (unsigned long long)mod->Base;
					if (size) *size = (unsigned long)mod->Size;
					break;
				}
			}
		}
		
		imports::ex_free_pool_with_tag(system_modules, tag);
		return result;
	}
	 

	// 获取映像地址
	unsigned long long get_image_address(unsigned long long addr, const char* name, unsigned long* size)
	{
		PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)addr;
		if (dos->e_magic != IMAGE_DOS_SIGNATURE) return 0;

		PIMAGE_NT_HEADERS64 nt = (PIMAGE_NT_HEADERS64)(addr + dos->e_lfanew);
		if (nt->Signature != IMAGE_NT_SIGNATURE) return 0;

		PIMAGE_SECTION_HEADER section = IMAGE_FIRST_SECTION(nt);
		for (unsigned short i = 0; i < nt->FileHeader.NumberOfSections; i++)
		{
			PIMAGE_SECTION_HEADER p = &section[i];

			if (Utils::kstrstr((const char*)p->Name, name))
			{
				if (size) *size = p->SizeOfRawData;
				return (unsigned long long)p + p->VirtualAddress;
			}
		}

		return 0;
	}

	// 获取SSDT表地址
	void* get_syscall_entry(unsigned long long ntoskrnl)
	{
		if (!ntoskrnl) return nullptr;

		/*
		2018年的内核页表隔离补丁 https://bbs.pediy.com/thread-223805.htm
		没有补丁的话就是KiSystemCall64
		*/
		Log("[%s] ntoskrnl 0x%p  \n", __FUNCTION__, ntoskrnl);
#define IA32_LSTAR_MSR 0xC0000082
		void* syscall_entry = (void*)__readmsr(IA32_LSTAR_MSR);

		// 没有补丁过,直接返回KiSystemCall64就行
		unsigned long section_size = 0;
		unsigned long long KVASCODE = get_image_address(ntoskrnl, skCrypt("KVASCODE") , &section_size);
		Log("[%s] ntoskrnl 0x%p   KVASCODE %p \n", __FUNCTION__, ntoskrnl, KVASCODE);
		if (!KVASCODE) return syscall_entry;

		// KiSystemCall64还是在区域内,也是直接返回
		if (!(syscall_entry >= (void*)KVASCODE && syscall_entry < (void*)(KVASCODE + section_size))) return syscall_entry;

		// 来到这一步那就是KiSystemCall64Shadow,代表打补丁了
		hde64s hde_info{ 0 };
		for (char* ki_system_service_user = (char*)syscall_entry; ; ki_system_service_user += hde_info.len)
		{
			// 反汇编
			if (!hde64_disasm(ki_system_service_user, &hde_info)) break;

			// 我们要查找jmp
#define OPCODE_JMP_NEAR 0xE9
			if (hde_info.opcode != OPCODE_JMP_NEAR) continue;

			// 忽略在KVASCODE节区内的jmp指令
			void* possible_syscall_entry = (void*)((long long)ki_system_service_user + (int)hde_info.len + (int)hde_info.imm.imm32);
			if (possible_syscall_entry >= (void*)KVASCODE && possible_syscall_entry < (void*)((unsigned long long)KVASCODE + section_size)) continue;

			// 发现KiSystemServiceUser
			syscall_entry = possible_syscall_entry;
			break;
		}

		return syscall_entry;
	}


}