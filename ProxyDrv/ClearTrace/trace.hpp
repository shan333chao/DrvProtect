#pragma once
#include "../headers.h"

extern POBJECT_TYPE* IoDriverObjectType;
constexpr unsigned int max_unloader_driver = 50;
typedef struct _unloader_information
{
	UNICODE_STRING name;
	PVOID module_start;
	PVOID module_end;
	ULONG64 unload_time;
} unloader_information, * punloader_information;

typedef struct _piddb_cache_entry
{
	LIST_ENTRY list;
	UNICODE_STRING name;
	ULONG stamp;
	NTSTATUS status;
	char _0x0028[16];
}piddb_cache_entry, * ppiddb_cache_entry;

typedef struct _hash_bucket_entry
{
	struct _hash_bucket_entry* next;
	UNICODE_STRING name;
	ULONG hash[5];
} hash_bucket_entry, * phash_bucket_entry;

namespace trace
{
	bool pattern_check(const char* data, const char* pattern, const char* mask)
	{
		size_t len = strlen(mask);

		for (size_t i = 0; i < len; i++)
		{
			if (data[i] == pattern[i] || mask[i] == '?')
				continue;
			else
				return false;
		}

		return true;
	}

	unsigned long long find_pattern(unsigned long long addr, unsigned long size, const char* pattern, const char* mask)
	{
		size -= (unsigned long)strlen(mask);

		for (unsigned long i = 0; i < size; i++)
		{
			if (pattern_check((const char*)addr + i, pattern, mask))
				return addr + i;
		}

		return 0;
	}

	unsigned long long find_pattern_image(unsigned long long addr, const char* pattern, const char* mask)
	{
		PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)addr;
		if (dos->e_magic != IMAGE_DOS_SIGNATURE) return 0;

		PIMAGE_NT_HEADERS64 nt = (PIMAGE_NT_HEADERS64)(addr + dos->e_lfanew);
		if (nt->Signature != IMAGE_NT_SIGNATURE) return 0;

		PIMAGE_SECTION_HEADER section = IMAGE_FIRST_SECTION(nt);
		for (unsigned short i = 0; i < nt->FileHeader.NumberOfSections; i++)
		{
			PIMAGE_SECTION_HEADER p = &section[i];

			if (Utils::kstrstr((const char*)p->Name, skCrypt(".text")) || 'EGAP' == *reinterpret_cast<int*>(p->Name))
			{
				DWORD64 res = find_pattern(addr + p->VirtualAddress, p->Misc.VirtualSize, pattern, mask);
				if (res) return res;
			}
		}

		return 0;
	}

	wchar_t* random_wstring(wchar_t* str, size_t size)
	{
		if (str)
		{
			ULONG64 time = 0;
			KeQuerySystemTime(&time);
			ULONG seed = (ULONG)time;
			static const wchar_t maps[62] = L"123456789ZXCVBNMASDFGHJKLQWERTYUIOPzxcvbnmasdfghjklqwertyuiop";

			if (size == 0) size = wcslen(str);
			for (size_t i = 0; i < size; i++) str[i] = maps[imports::rtl_random_ex(&seed) % 60];
		}

		return str;
	}
	bool clear_cache(const wchar_t* name, unsigned long stamp)
	{
		bool status = false;

		unsigned long long ntoskrnl_address = 0;
		unsigned long ntoskrnl_size = 0;
		ntoskrnl_address = (ULONGLONG)Utils::GetKernelBase();

		Log("[%s] ntoskrnl address 0x%llx\n", __FUNCTION__, ntoskrnl_address);
		if (ntoskrnl_address == 0) return status;

		/*
		 * PpCheckInDriverDatabase proc near
		 * 48 8D 0D ? ? ? ? E8 ? ? ? ? 4C 8B 8C
		 * lea     rcx, PiDDBLock  ; Resource
		 * call    ExAcquireResourceExclusiveLite
		 * mov     r9, [rsp+58h+arg_28]
		 * lea     rcx, [rsp+58h+var_28]
		 * mov     rdx, rsi
		 */
		unsigned long long PiDDBLock = find_pattern_image(ntoskrnl_address,
			"\x48\x8D\x0D\x00\x00\x00\x00\xE8\x00\x00\x00\x00\x4C\x8B\x8C",
			skCrypt("xxx????x????xxx"));
		if (PiDDBLock == 0) return status;
		PiDDBLock = reinterpret_cast<unsigned long long>(reinterpret_cast<char*>(PiDDBLock) + 7 + *reinterpret_cast<int*>(reinterpret_cast<char*>(PiDDBLock) + 3));
		Log("[%s] PiDDBLock address 0x%llx\n", __FUNCTION__, PiDDBLock);

		/*
		 * PiLookupInDDBCache proc near
		 * 66 03 D2 48 8D 0D
		 * add     dx, dx
		 * lea     rcx, PiDDBCacheTable
		 * mov     [rsp+88h+var_58], dx
		 * mov     [rsp+88h+var_56], dx
		 */
		unsigned long long PiDDBCacheTable = find_pattern_image(ntoskrnl_address,
			"\x66\x03\xD2\x48\x8D\x0D",
			skCrypt("xxxxxx"));
		if (PiDDBCacheTable == 0) return status;
		PiDDBCacheTable += 3;
		PiDDBCacheTable = reinterpret_cast<unsigned long long>(reinterpret_cast<char*>(PiDDBCacheTable) + 7 + *reinterpret_cast<int*>(reinterpret_cast<char*>(PiDDBCacheTable) + 3));
		Log("[%s] PiDDBCacheTable address 0x%llx \n", __FUNCTION__, PiDDBCacheTable);

		piddb_cache_entry in_entry{ };
		in_entry.stamp = stamp;
		imports::rtl_init_unicode_string(&in_entry.name, name);

		if (imports::ex_acquire_resource_exclusive_lite((PERESOURCE)PiDDBLock, TRUE))
		{
			ppiddb_cache_entry ret_entry = (ppiddb_cache_entry)imports::rtl_lookup_element_generic_table_avl((PRTL_AVL_TABLE)PiDDBCacheTable, &in_entry);
			if (ret_entry)
			{
				Log("[%s] found %ws driver cache 0x%p \n", __FUNCTION__, ret_entry->name.Buffer, ret_entry->status);

				// 指针断链
				PLIST_ENTRY prev = ret_entry->list.Blink;	// 指向上一个
				PLIST_ENTRY next = ret_entry->list.Flink;	// 指向下一个
				if (prev && next)
				{
					prev->Flink = next;
					next->Blink = prev;
				}

				if (imports::rtl_delete_element_generic_table_avl((PRTL_AVL_TABLE)PiDDBCacheTable, ret_entry))
				{
					PRTL_AVL_TABLE avl = ((PRTL_AVL_TABLE)PiDDBCacheTable);
					if (avl->DeleteCount > 0) avl->DeleteCount--;

					status = true;
				}
			}

			imports::ex_release_resource_lite((PERESOURCE)PiDDBLock);
		}

		return status;
	}

	bool clear_unloaded_driver(const wchar_t* name)
	{
		bool status = false;

		unsigned long long ntoskrnl_address = 0;
		ntoskrnl_address = (ULONGLONG)Utils::GetKernelBase();
		Log("[%s] ntoskrnl address 0x%llx\n", __FUNCTION__, ntoskrnl_address);
		if (ntoskrnl_address == 0) return status;

		/*
		 * MmLocateUnloadedDriver proc near
		 * 4C 8B 15 ? ? ? ? 4C 8B C9
		 * mov     r10, cs:MmUnloadedDrivers
		 * mov     r9, rcx
		 * test    r10, r10
		 * jz      short loc_1402C4573
		 */
		unsigned long long MmUnloadedDrivers = find_pattern_image(ntoskrnl_address,
			"\x4C\x8B\x15\x00\x00\x00\x00\x4C\x8B\xC9",
			skCrypt("xxx????xxx"));
		if (MmUnloadedDrivers == 0) return status;
		MmUnloadedDrivers = reinterpret_cast<unsigned long long>(reinterpret_cast<char*>(MmUnloadedDrivers) + 7 + *reinterpret_cast<int*>(reinterpret_cast<char*>(MmUnloadedDrivers) + 3));
		Log("[%s] MmUnloadedDrivers address 0x%llx\n", __FUNCTION__, MmUnloadedDrivers);

		/*
		 * MiRememberUnloadedDriver proc near
		 * 8B 05 ? ? ? ? 83 F8 32
		 * mov     eax, cs:MmLastUnloadedDriver
		 * cmp     eax, 32h
		 * jnb     loc_140741D32
		 */
		unsigned long long MmLastUnloadedDriver = find_pattern_image(ntoskrnl_address,
			"\x8B\x05\x00\x00\x00\x00\x83\xF8\x32",
			skCrypt("xx????xxx"));
		if (MmLastUnloadedDriver == 0) return status;
		MmLastUnloadedDriver = reinterpret_cast<unsigned long long>(reinterpret_cast<char*>(MmLastUnloadedDriver) + 6 + *reinterpret_cast<int*>(reinterpret_cast<char*>(MmLastUnloadedDriver) + 2));
		Log("[%s] MmLastUnloadedDriver address 0x%llx \n", __FUNCTION__, MmLastUnloadedDriver);

		punloader_information unloaders = *(punloader_information*)MmUnloadedDrivers;
		unsigned long* unloaders_count = (unsigned long*)MmLastUnloadedDriver;
		if (imports::mm_is_address_valid(unloaders) == FALSE || imports::mm_is_address_valid(unloaders_count) == FALSE) return status;

		static ERESOURCE PsLoadedModuleResource;
		if (imports::ex_acquire_resource_exclusive_lite(&PsLoadedModuleResource, TRUE))
		{
			for (unsigned long i = 0; i < *unloaders_count && i < max_unloader_driver; i++)
			{
				unloader_information& t = unloaders[i];
				const wchar_t* sys = t.name.Buffer;

				Log("[%s] %.2d %ws \n", __FUNCTION__, i, sys);
				if (wcsstr(sys, name))
				{
					Log("[%s] found unloader %ws driver \n", __FUNCTION__, t.name.Buffer);

					t.module_start = (void*)((unsigned long long)t.module_start + 0x1234);
					t.module_end = (void*)((unsigned long long)t.module_end - 0x123);
					t.unload_time += 0x20;
					random_wstring(t.name.Buffer, t.name.Length / 2 - 4);

					Log("[%s] random string is %ws \n", __FUNCTION__, t.name.Buffer);
					status = true;
				}
			}

			imports::ex_release_resource_lite(&PsLoadedModuleResource);
		}

		return status;
	}

	bool clear_hash_bucket_list(const wchar_t* name)
	{
		bool status = false;

		unsigned long long ci_address = 0;
		unsigned long ci_size = 0;
		ci_address = (ULONGLONG)Utils::GetKernelModule(skCrypt("CI.dll"), &ci_size);

		Log("[%s] ci address 0x%llx \n", __FUNCTION__, ci_address);
		if (ci_address == 0) return status;

		unsigned long long HashCacheLock = 0;

		/*
		 * I_SetSecurityState proc near
		 * 48 8B 1D ? ? ? ? EB ? F7 43 40 00 20 00
		 * mov     rbx, cs:g_KernelHashBucketList
		 * jmp     short loc_1C0073C2C
		 */
		unsigned long long KernelHashBucketList = find_pattern_image(ci_address,
			"\x48\x8B\x1D\x00\x00\x00\x00\xEB\x00\xF7\x43\x40\x00\x20\x00\x00",
			skCrypt("xxx????x?xxxxxxx"));
		if (KernelHashBucketList == 0) return status;
		else HashCacheLock = KernelHashBucketList - 0x13;

		KernelHashBucketList = reinterpret_cast<unsigned long long>(reinterpret_cast<char*>(KernelHashBucketList) + 7 + *reinterpret_cast<int*>(reinterpret_cast<char*>(KernelHashBucketList) + 3));
		Log("[%s] g_KernelHashBucketList address 0x%llx\n", __FUNCTION__, KernelHashBucketList);

		/*
		 * I_SetSecurityState proc near
		 * 48 8D 0D ? ? ? ? 48 FF 15 ? ? ? ? 0F 1F 44 00 ? 48 8B 1D ? ? ? ? EB
		 * lea     rcx, g_HashCacheLock ; Resource
		 * call    cs:__imp_ExAcquireResourceExclusiveLite
		 * nop     dword ptr [rax+rax+00h]
		 * mov     rbx, cs:g_KernelHashBucketList
		 */
		HashCacheLock = reinterpret_cast<unsigned long long>(reinterpret_cast<char*>(HashCacheLock) + 7 + *reinterpret_cast<int*>(reinterpret_cast<char*>(HashCacheLock) + 3));
		Log("[%s] g_HashCacheLock address 0x%llx\n", __FUNCTION__, HashCacheLock);

		if (imports::ex_acquire_resource_exclusive_lite((PERESOURCE)HashCacheLock, TRUE))
		{
			phash_bucket_entry current_entry = ((phash_bucket_entry)KernelHashBucketList)->next;
			phash_bucket_entry prev_entry = (phash_bucket_entry)KernelHashBucketList;

			UNICODE_STRING drv_name;
			imports::rtl_init_unicode_string(&drv_name, name);

			while (current_entry)
			{
				Log("[%s] %ws 0x%x\n", __FUNCTION__, current_entry->name.Buffer, current_entry->hash[0]);

				if (wcsstr(current_entry->name.Buffer, name))
				{
					Log("[%s] found %ws driver \n", __FUNCTION__, current_entry->name.Buffer);

					// 指针断链
					prev_entry->next = current_entry->next;

					// 指针断链后就释放内存了，何必执行这些操作?
					current_entry->hash[0] = current_entry->hash[1] = 1;
					current_entry->hash[2] = current_entry->hash[3] = 1;
					random_wstring(current_entry->name.Buffer, current_entry->name.Length / 2 - 4);

					imports::ex_free_pool_with_tag(current_entry, 0);
					status = true;
					break;
				}
				else
				{
					prev_entry = current_entry;
					current_entry = current_entry->next;
				}
			}

			imports::ex_release_resource_lite((PERESOURCE)HashCacheLock);
		}

		return status;
	}

	bool clear_ci_ea_cache_lookaside_list()
	{
		bool status = false;

		unsigned long long ci_address = 0;
		unsigned long ci_size = 0;
		ci_address = (ULONGLONG)Utils::GetKernelModule(skCrypt("CI.dll"), &ci_size);

		Log("[%s] ci address 0x%llx \n", __FUNCTION__, ci_address);
		if (ci_address == 0) return status;

		/*
		 * CiInitializePhase2 proc near
		 * 8B 15 ? ? ? ? 48 8B 05 ? ? ? ? 44 8B 05 ? ? ? ? 8B 0D ? ? ? ? FF 05 ? ? ? ? FF 15
		 * lea     rcx, g_CiEaCacheLookasideList ; ListHead
		 * call    cs:__imp_ExpInterlockedPopEntrySList
		 * nop     dword ptr [rax+rax+00h]
		 * mov     rsi, rax
		 * test    rax, rax
		 * jnz     short loc_1C0044EB8
		 * mov     edx, cs:g_CiEaCacheLookasideList.L.Size
		 * mov     rax, cs:g_CiEaCacheLookasideList.L.Allocate
		 * mov     r8d, cs:g_CiEaCacheLookasideList.L.Tag
		 * mov     ecx, cs:g_CiEaCacheLookasideList.L.Type
		 * inc     dword ptr cs:g_CiEaCacheLookasideList.L.anonymous_0
		 */
		unsigned long long CiEaCacheLookasideList = find_pattern_image(ci_address,
			"\x8B\x15\x00\x00\x00\x00\x48\x8B\x05\x00\x00\x00\x00\x44\x8B\x05\x00\x00\x00\x00\x8B\x0D\x00\x00\x00\x00\xFF\x05\x00\x00\x00\x00\xFF\x15",
			skCrypt("xx????xxx????xxx????xx????xx????xx"));
		if (CiEaCacheLookasideList == 0) return status;
		CiEaCacheLookasideList -= 0x1B;
		CiEaCacheLookasideList = reinterpret_cast<unsigned long long>(reinterpret_cast<char*>(CiEaCacheLookasideList) + 7 + *reinterpret_cast<int*>(reinterpret_cast<char*>(CiEaCacheLookasideList) + 3));
		Log("[%s] g_CiEaCacheLookasideList address 0x%llx\n", __FUNCTION__, CiEaCacheLookasideList);

		PLOOKASIDE_LIST_EX g_CiEaCacheLookasideList = (PLOOKASIDE_LIST_EX)CiEaCacheLookasideList;
		ULONG size = g_CiEaCacheLookasideList->L.Size;
		imports::ex_delete_lookaside_list_ex(g_CiEaCacheLookasideList);
		if (NT_SUCCESS(imports::ex_initialize_lookaside_list_ex(g_CiEaCacheLookasideList, NULL, NULL, PagedPool, 0, size, 'csIC', 0)))
		{
			Log("[%s] clear g_CiEaCacheLookasideList \n", __FUNCTION__);
			status = true;
		}

		return status;
	}
}