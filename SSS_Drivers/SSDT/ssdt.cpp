#pragma once
#include "ssdt.h"



namespace ssdt_serv {

	PSSDTStruct InitSSDTAndShadow(BOOLEAN IsShadowSSDT)
	{
		static PSSDTStruct SSDT = 0;
		static PSSDTStruct ShadowSSDT = 0;

		if (!SSDT || !ShadowSSDT)
		{
			ULONG_PTR kernelBase;
			kernelBase = (ULONG_PTR)Utils::GetKernelBase();

			if (!kernelBase)
			{
				return NULL;
			}

			// Find .text section
			PIMAGE_NT_HEADERS ntHeaders = imports::rtl_image_nt_header((PVOID)kernelBase);
			PIMAGE_SECTION_HEADER textSection = NULL;
			PIMAGE_SECTION_HEADER section = IMAGE_FIRST_SECTION(ntHeaders);



			for (ULONG i = 0; i < ntHeaders->FileHeader.NumberOfSections; ++i)
			{
				char sectionName[IMAGE_SIZEOF_SHORT_NAME + 1];
				RtlCopyMemory(sectionName, section->Name, IMAGE_SIZEOF_SHORT_NAME);
				sectionName[IMAGE_SIZEOF_SHORT_NAME] = '\0';
				if (crt::strcmp(sectionName, skCrypt(".text")) == 0)
				{
					textSection = section;
					break;
				}
				section++;
			}
			if (textSection == NULL)
				return NULL;
			// Find KiSystemServiceStart in .text
			UCHAR KiSystemServiceStartPattern[] = { 0x8B, 0xF8, 0xC1, 0xEF, 0x07, 0x83, 0xE7, 0x20, 0x25, 0xFF, 0x0F, 0x00, 0x00 };
			const ULONG signatureSize = sizeof(KiSystemServiceStartPattern);
			BOOLEAN found = FALSE;
			ULONG KiSSSOffset;
			for (KiSSSOffset = 0; KiSSSOffset < textSection->Misc.VirtualSize - signatureSize; KiSSSOffset++)
			{
				if (imports::rtl_compare_memory(((PUCHAR)kernelBase + textSection->VirtualAddress + KiSSSOffset), KiSystemServiceStartPattern, signatureSize) == signatureSize)
				{
					found = TRUE;
					break;
				}
			}
			if (!found)
				return NULL;

			// lea r10, KeServiceDescriptorTable
			ULONG_PTR address = kernelBase + textSection->VirtualAddress + KiSSSOffset + signatureSize;
			LONG SSDTOffset = 0;
			LONG SSDTShadowOffset = 0;
			if ((*(PUCHAR)address == 0x4c) &&
				(*(PUCHAR)(address + 1) == 0x8d) &&
				(*(PUCHAR)(address + 2) == 0x15))
			{
				SSDTOffset = *(PLONG)(address + 3);
				SSDTShadowOffset = *(PLONG)(address + 10);
			}
			if (SSDTOffset == 0)
				return NULL;

			SSDT = (PSSDTStruct)(address + SSDTOffset + 7);
			ShadowSSDT = (PSSDTStruct)(address + SSDTShadowOffset + 14 + 0x20); 
		} 
		return  IsShadowSSDT ? ShadowSSDT : SSDT; 
	}
	PVOID  GetFunctionAddrInSSDT(ULONG serviceNum)
	{
		PVOID ret = NULL;
		if (!serviceNum)
			return NULL;

		BOOLEAN isShadow = (serviceNum >> 12) > 0;
		PSSDTStruct	SSDT = InitSSDTAndShadow(isShadow);


		if (!SSDT)
		{
			Log("[SSS] SSDT not found...\r\n");
			return ret;
		}
		ULONG_PTR SSDTbase = (ULONG_PTR)SSDT->pServiceTable;
		if (!SSDTbase)
		{
			Log("[SSS] ServiceTable not found...\r\n");
			return ret;
		}
		//shadowssdt 服务号 取后12位
		if (isShadow)
		{
			serviceNum &= 0xfff;
		}
		if (serviceNum >= SSDT->NumberOfServices)
		{

			Log("[SSS] Invalid read offset...\r\n");
			return ret;
		}
		ret = (PVOID)((SSDT->pServiceTable[serviceNum] >> 4) + SSDTbase);
		return ret;
	}

	static PULONG W32pServiceTable = NULL;
	ULONG64 GetShadowSSDTFuncCurAddr(ULONG id) {
		LONG dwtmp = 0;
		PULONG ServiceTableBase = NULL;
		ServiceTableBase = W32pServiceTable;
		dwtmp = ServiceTableBase[id];
		dwtmp = dwtmp >> 4;
		return (LONGLONG)dwtmp + (ULONGLONG)ServiceTableBase;
	}
	ULONG64 GetWin32kFunc10(PCHAR inFuncName) {
		static PVOID Win32KBase = NULL;
		if (!Win32KBase)
		{
			ULONG moduleSize = 0;
			Win32KBase = (PVOID)Utils::GetKernelModule(skCrypt("win32k.sys"), &moduleSize);
			Log("[%s] Win32k.sys = 0x%llx\n", __FUNCTION__, Win32KBase);
		}

		if (!W32pServiceTable)
		{
			W32pServiceTable = (PULONG)imports::rtl_find_exported_routine_by_name(Win32KBase, skCrypt("W32pServiceTable"));

			Log("[%s] W32pServiceTable = 0x%llx\n", __FUNCTION__, W32pServiceTable);
		}

		PIMAGE_DOS_HEADER lpDosHeader = (PIMAGE_DOS_HEADER)Win32KBase;

		PIMAGE_NT_HEADERS64 lpNtHeader = (PIMAGE_NT_HEADERS64)((ULONG64)Win32KBase + lpDosHeader->e_lfanew);

		if (!lpNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size) {
			return 0;
		}

		if (!lpNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress) {
			return 0;
		}

		PIMAGE_EXPORT_DIRECTORY lpExports = (PIMAGE_EXPORT_DIRECTORY)((ULONG64)Win32KBase + (ULONG64)lpNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);

		PULONG lpdwFunName = (PULONG)((ULONG64)Win32KBase + (ULONG64)lpExports->AddressOfNames);

		PUSHORT lpword = (PUSHORT)((ULONG64)Win32KBase + (ULONG64)lpExports->AddressOfNameOrdinals);

		PULONG lpdwFunAddr = (PULONG)((ULONG64)Win32KBase + (ULONG64)lpExports->AddressOfFunctions);

		for (ULONG i = 0; i <= lpExports->NumberOfNames - 1; i++) {
			char* pFunName = (char*)(lpdwFunName[i] + (ULONG64)Win32KBase);
			if (Utils::kstrstr(pFunName, skCrypt("__win32kstub_")))
			{
				PVOID _FunctionAddress = (PVOID)(lpdwFunAddr[lpword[i]] + (ULONG64)Win32KBase);
				char* FunctionName = Utils::kstrstr(pFunName, skCrypt("Nt"));
				if (crt::strcmp(FunctionName, inFuncName) == 0)
				{
					ULONG lFunctionIndex = *(ULONG*)((PUCHAR)_FunctionAddress + 1);
					ULONG64 FunctionAddress = GetShadowSSDTFuncCurAddr(lFunctionIndex);
					//Log("[%s] \t Index: %d \t Address: 0x%llx \n", FunctionName, lFunctionIndex, FunctionAddress);
					return FunctionAddress;
				}

			}
		}
		return 0;
	}
}
