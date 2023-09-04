#pragma once
#include "../Tools/Utils.h"
#include <ntimage.h>
#include "../Tools/Log.h"
#include "ssdt.h"




PSSDTStruct InitSSDTAndShadow(BOOLEAN IsShadowSSDT)
{
	static PSSDTStruct SSDT = 0;
	static PSSDTStruct ShadowSSDT = 0;

	if (!SSDT || !ShadowSSDT)
	{
#ifndef _WIN64
		//x86 code
		UNICODE_STRING routineName;
		RtlInitUnicodeString(&routineName, L"KeServiceDescriptorTable");
		SSDT = (PKSERVICE_TABLE_DESCRIPTOR)MmGetSystemRoutineAddress(&routineName);
		RtlInitUnicodeString(&routineName, L"KeServiceDescriptorTableShadow");
		ShadowSSDT = (PKSERVICE_TABLE_DESCRIPTOR)MmGetSystemRoutineAddress(&routineName);
#else
		//x64 code
		ULONG kernelSize;
		ULONG_PTR kernelBase;
		RTL_PROCESS_MODULE_INFORMATION moduleInfo = { 0 };
		GetKernelModule("ntoskrnl.exe", &moduleInfo);
		if (!moduleInfo.ImageSize || !moduleInfo.ImageBase)
		{
			return NULL;
		}
		kernelBase = moduleInfo.ImageBase;
		kernelSize = moduleInfo.ImageSize;

 
		// Find .text section
		PIMAGE_NT_HEADERS ntHeaders = RtlImageNtHeader((PVOID)kernelBase);
		PIMAGE_SECTION_HEADER textSection = NULL;
		PIMAGE_SECTION_HEADER section = IMAGE_FIRST_SECTION(ntHeaders);
		for (ULONG i = 0; i < ntHeaders->FileHeader.NumberOfSections; ++i)
		{
			char sectionName[IMAGE_SIZEOF_SHORT_NAME + 1];
			RtlCopyMemory(sectionName, section->Name, IMAGE_SIZEOF_SHORT_NAME);
			sectionName[IMAGE_SIZEOF_SHORT_NAME] = '\0';
			if (strncmp(sectionName, ".text", sizeof(".text") - sizeof(char)) == 0)
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
			if (RtlCompareMemory(((PUCHAR)kernelBase + textSection->VirtualAddress + KiSSSOffset), KiSystemServiceStartPattern, signatureSize) == signatureSize)
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

#endif
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
#ifdef _WIN64

	ret = (PVOID)((SSDT->pServiceTable[serviceNum] >> 4) + SSDTbase);
#else
	ret = (PVOID)SSDTShadow->pServiceTable[serviceNum];
#endif

	return ret;
}