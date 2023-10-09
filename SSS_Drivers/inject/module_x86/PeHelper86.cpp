#include "PeHelper86.h"
#include "../../PatternSearch/PatternSearch.h"
#define MAX(a,b) (a>b?a:b)
typedef unsigned short      WORD;
typedef unsigned long       DWORD;
typedef unsigned char       BYTE;
//#ifdef _WIN32
//
//typedef ULONGLONG	QDWORD;
//typedef PULONGLONG	PQDWORD;
//#else
//typedef DWORD	QDWORD;
//typedef PDWORD	PQDWORD;
//#endif
typedef ULONG	QDWORD;
typedef PULONG	PQDWORD;


typedef WORD* PWORD;
typedef DWORD* PDWORD;
typedef int		 BOOL;

typedef INT_PTR(FAR _stdcall* FARPROC)();


namespace pehelper86 {
	// 计算对齐后大小
	static DWORD AlignedSize(DWORD dwOrigin, DWORD dwAlignment)
	{

		return (dwOrigin + dwAlignment - 1) / dwAlignment * dwAlignment;
	}
	// 获取导出函数
	ULONG_PTR MyGetProcAddress(
		PVOID hModule,    // handle to DLL module  
		LPCSTR lpProcName,   // function name  
		PEPROCESS pEprocess
	)
	{
		int i = 0;
		char* pRet = NULL;


		PIMAGE_DOS_HEADER pImageDosHeader = NULL;
		PIMAGE_NT_HEADERS32 pImageNtHeader = NULL;
		PIMAGE_EXPORT_DIRECTORY pImageExportDirectory = NULL;

		pImageDosHeader = (PIMAGE_DOS_HEADER)hModule;
		pImageNtHeader = (PIMAGE_NT_HEADERS32)((ULONG_PTR)hModule + pImageDosHeader->e_lfanew);
		pImageExportDirectory = (PIMAGE_EXPORT_DIRECTORY)((ULONG_PTR)hModule + pImageNtHeader->OptionalHeader.DataDirectory
			[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);

		DWORD dwExportRVA = pImageNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
		DWORD dwExportSize = pImageNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;

		DWORD* pAddressOfFunction = (DWORD*)(pImageExportDirectory->AddressOfFunctions + (ULONG_PTR)hModule);
		DWORD* pAddressOfNames = (DWORD*)(pImageExportDirectory->AddressOfNames + (ULONG_PTR)hModule);
		DWORD dwNumberOfNames = (DWORD)(pImageExportDirectory->NumberOfNames);
		DWORD dwBase = (DWORD)(pImageExportDirectory->Base);

		WORD* pAddressOfNameOrdinals = (WORD*)(pImageExportDirectory->AddressOfNameOrdinals + (ULONG_PTR)hModule);

		//这个是查一下是按照什么方式（函数名称or函数序号）来查函数地址的  
		DWORD dwName = (DWORD)(ULONG_PTR)lpProcName;
		if ((dwName & 0xFFFF0000) == 0)
		{
			goto xuhao;
		}

		for (i = 0; i < (int)dwNumberOfNames; i++)
		{
			char* strFunction = (char*)(pAddressOfNames[i] + (ULONG_PTR)hModule);
			if (strcmp(strFunction, (char*)lpProcName) == 0)
			{
				pRet = (char*)(pAddressOfFunction[pAddressOfNameOrdinals[i]] + (ULONG_PTR)hModule);
				goto _exit11;
			}
		}
		//这个是通过以序号的方式来查函数地址的  
	xuhao:
		if (dwName < dwBase || dwName > dwBase + pImageExportDirectory->NumberOfFunctions - 1)
		{
			return 0;
		}
		pRet = (char*)(pAddressOfFunction[dwName - dwBase] + (ULONG_PTR)hModule);
	_exit11:
		//判断得到的地址有没有越界  
		if ((ULONG_PTR)pRet<dwExportRVA + (ULONG_PTR)hModule || (ULONG_PTR)pRet > dwExportRVA + (ULONG_PTR)hModule + dwExportSize)
		{
			return (ULONG_PTR)pRet;
		}
		char pTempDll[100] = { 0 };
		char pTempFuction[100] = { 0 };
		strcpy(pTempDll, pRet);
		char* p = strchr(pTempDll, '.');
		if (!p)
		{
			return (ULONG_PTR)pRet;
		}
		*p = 0;
		strcpy(pTempFuction, p + 1);
		strcat(pTempDll, ".dll");
		PVOID h = NULL;
		
		ULONG moduleSize = 0;
		h = (PVOID)patternSearch::get_module(pEprocess, pTempDll, &moduleSize);
		if (h == NULL)
		{
			return (ULONG_PTR)pRet;
		}
		return MyGetProcAddress(h, pTempFuction, pEprocess);
	}

	// 重定向
	BOOL DoRelocation(ULONG_PTR lpMemModule, PUCHAR virtualBase)
	{
		PIMAGE_DOS_HEADER lpDosHeader = (PIMAGE_DOS_HEADER)lpMemModule;
		PIMAGE_NT_HEADERS32 lpNtHeader = (PIMAGE_NT_HEADERS32)(lpMemModule + lpDosHeader->e_lfanew);
		QDWORD dwDelta = (QDWORD)(lpMemModule - lpNtHeader->OptionalHeader.ImageBase);

		if (0 == dwDelta || 0 == lpNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size) {
			return TRUE;
		}

		ULONG index = 1;

		DWORD dwRelocationOffset = lpNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress;
		PIMAGE_BASE_RELOCATION lpBaseRelocation = (PIMAGE_BASE_RELOCATION)(lpMemModule + dwRelocationOffset);
		while (0 != lpBaseRelocation->VirtualAddress)
		{
			DWORD dwRelocationSize = (lpBaseRelocation->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
			for (DWORD i = 0; i < dwRelocationSize; i++)
			{
				WORD wRelocationValue = *((PWORD)(lpMemModule + dwRelocationOffset + sizeof(IMAGE_BASE_RELOCATION) + i * sizeof(WORD)));
				WORD wRelocationType = wRelocationValue >> 12;

				if (IMAGE_REL_BASED_DIR64 == wRelocationType && sizeof(PULONGLONG) == sizeof(PQDWORD))
				{
					PQDWORD lpAddress = (PQDWORD)(lpMemModule + lpBaseRelocation->VirtualAddress + (wRelocationValue & 4095));
					*lpAddress = (ULONG_PTR)virtualBase + (*lpAddress - lpMemModule) + dwDelta;
					index++;
					
				}
				else if (IMAGE_REL_BASED_HIGHLOW == wRelocationType && sizeof(PDWORD) == sizeof(PQDWORD))
				{
					PQDWORD lpAddress = (PQDWORD)(lpMemModule + lpBaseRelocation->VirtualAddress + (wRelocationValue & 4095));
					*lpAddress += dwDelta;
				}
				else if (IMAGE_REL_BASED_ABSOLUTE != wRelocationType)
				{
					return FALSE;
				}
			}

			dwRelocationOffset += lpBaseRelocation->SizeOfBlock;
			lpBaseRelocation = (PIMAGE_BASE_RELOCATION)(lpMemModule + dwRelocationOffset);
		}
		Logf("My重定向: %d \r\n", index);
		return TRUE;
	}

	// 填充导入表
	static BOOL FillRavAddress(ULONG_PTR lpMemModule, PVOID virtualBase, PEPROCESS pEprocess)
	{
		PIMAGE_DOS_HEADER lpDosHeader = (PIMAGE_DOS_HEADER)lpMemModule;
		PIMAGE_NT_HEADERS32 lpNtHeader = (PIMAGE_NT_HEADERS32)(lpMemModule + lpDosHeader->e_lfanew);

		if (0 == lpNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size) {
			return TRUE;
		}

		DWORD i = 0;
		PIMAGE_IMPORT_DESCRIPTOR lpImportDescriptor = (PIMAGE_IMPORT_DESCRIPTOR)(lpMemModule + lpNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);
		while (0 != lpImportDescriptor[i].Name)
		{
			DWORD j = 0;
			QDWORD realIAT = 0;
			LPCSTR lpModuleName = (LPCSTR)(lpMemModule + lpImportDescriptor[i].Name);	// 模块名 
			ULONG modulsSize = 0;
			PVOID	moudlebase = (PVOID)patternSearch::get_module(pEprocess, lpModuleName, &modulsSize);
			Logf("模块名 : %s 基地址： %p %11x \r\n", lpModuleName, moudlebase, modulsSize);

			DWORD dwFirstThunk = lpImportDescriptor[i].OriginalFirstThunk ? lpImportDescriptor[i].OriginalFirstThunk : lpImportDescriptor[i].FirstThunk;	// IAT表

			while (0 != (realIAT = ((PQDWORD)(lpMemModule + dwFirstThunk))[j]))
			{
				// 序号 或 名称
				LPCSTR lpProcName = realIAT & IMAGE_ORDINAL_FLAG64 ? (LPCSTR)(realIAT & 65535) : (LPCSTR)(lpMemModule + realIAT + 2);
				//FARPROC ProcAddr = GetProcAddress(moudlebase, lpProcName);
				PVOID ProcAddr = (PVOID)MyGetProcAddress(moudlebase, lpProcName, pEprocess);
				Logf("lpProcName : %s ProcAddr : %p\r\n", lpProcName, ProcAddr);

				// 有效 把地址写入FirstThunk
				((FARPROC*)(lpMemModule + lpImportDescriptor[i].FirstThunk))[j] = (FARPROC)ProcAddr;

				j++;
			}

			i++;
		}

		return TRUE;
	}


	//获取映像大小
	DWORD GetImageSize(PUCHAR fileBuffer) {
		DWORD dwSizeOfImage = 0;
		ULONGLONG dos_header = (ULONGLONG)fileBuffer;
		ULONGLONG nt_header = (ULONGLONG) * (ULONG*)(dos_header + 0x03C) + dos_header;
		USHORT  machine = *(USHORT*)(nt_header + 0x4);
		PIMAGE_DOS_HEADER lpDosHeader = (PIMAGE_DOS_HEADER)fileBuffer;
		if (machine == 0x8664)
		{
			PIMAGE_NT_HEADERS lpNtHeader = (PIMAGE_NT_HEADERS)(fileBuffer + lpDosHeader->e_lfanew);

			// 计算映像大小
			WORD wOptionalHeaderOffset = lpNtHeader->FileHeader.SizeOfOptionalHeader - sizeof(IMAGE_OPTIONAL_HEADER);
			PIMAGE_SECTION_HEADER lpSectionHeader = (PIMAGE_SECTION_HEADER)(fileBuffer + lpDosHeader->e_lfanew + sizeof(IMAGE_NT_HEADERS) + wOptionalHeaderOffset);
			dwSizeOfImage = lpNtHeader->OptionalHeader.SizeOfImage;

			// 取最大值
			for (WORD i = 0; i < lpNtHeader->FileHeader.NumberOfSections; i++) {
				dwSizeOfImage = MAX(dwSizeOfImage,
					AlignedSize(lpSectionHeader[i].VirtualAddress + MAX(lpSectionHeader[i].SizeOfRawData,
						lpSectionHeader[i].Misc.VirtualSize),
						lpNtHeader->OptionalHeader.SectionAlignment));
			}
		}
		else
		{
			PIMAGE_NT_HEADERS32 lpNtHeader = (PIMAGE_NT_HEADERS32)(fileBuffer + lpDosHeader->e_lfanew);

			// 计算映像大小
			WORD wOptionalHeaderOffset = lpNtHeader->FileHeader.SizeOfOptionalHeader - sizeof(IMAGE_OPTIONAL_HEADER32);
			PIMAGE_SECTION_HEADER lpSectionHeader = (PIMAGE_SECTION_HEADER)(fileBuffer + lpDosHeader->e_lfanew + sizeof(IMAGE_NT_HEADERS32) + wOptionalHeaderOffset);
			dwSizeOfImage = lpNtHeader->OptionalHeader.SizeOfImage;

			// 取最大值
			for (WORD i = 0; i < lpNtHeader->FileHeader.NumberOfSections; i++) {
				dwSizeOfImage = MAX(dwSizeOfImage,
					AlignedSize(lpSectionHeader[i].VirtualAddress + MAX(lpSectionHeader[i].SizeOfRawData,
						lpSectionHeader[i].Misc.VirtualSize),
						lpNtHeader->OptionalHeader.SectionAlignment));
			}
		}
		return dwSizeOfImage;
	}

	/*清空PE头*/
	VOID CleanPeHeader(PUCHAR base) {
		PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)base;
		PIMAGE_NT_HEADERS32 nt = (PIMAGE_NT_HEADERS32)(dos->e_lfanew + base);
		Utils::kmemset(base, 0, nt->OptionalHeader.SizeOfHeaders);
		Logf("清空PE头!");
	}

	//远程PE拉伸
	BOOLEAN PELoaderDLL(PUCHAR fileBuffer, PUCHAR virtualBase, ULONG_PTR lpMemModule,   PVOID* entrypoint, PEPROCESS pEprocess) {
		// PE头
		PIMAGE_DOS_HEADER lpDosHeader = (PIMAGE_DOS_HEADER)fileBuffer; 
		PIMAGE_NT_HEADERS32 lpNtHeader = (PIMAGE_NT_HEADERS32)(fileBuffer + lpDosHeader->e_lfanew);

		//// 计算映像大小
		WORD wOptionalHeaderOffset = lpNtHeader->FileHeader.SizeOfOptionalHeader - sizeof(IMAGE_OPTIONAL_HEADER32);
		PIMAGE_SECTION_HEADER lpSectionHeader = (PIMAGE_SECTION_HEADER)(fileBuffer + lpDosHeader->e_lfanew + sizeof(IMAGE_NT_HEADERS32) + wOptionalHeaderOffset);

		// 复制section 数据
		Utils::kmemcpy((PVOID)lpMemModule, fileBuffer, lpDosHeader->e_lfanew + sizeof(IMAGE_NT_HEADERS32) + wOptionalHeaderOffset + lpNtHeader->FileHeader.NumberOfSections * sizeof(IMAGE_SECTION_HEADER));
		for (WORD i = 0; i < lpNtHeader->FileHeader.NumberOfSections; i++)
		{
			if (0 != lpSectionHeader[i].SizeOfRawData && 0 != lpSectionHeader[i].VirtualAddress) {
				Utils::kmemcpy((PVOID)(lpMemModule + lpSectionHeader[i].VirtualAddress), fileBuffer + lpSectionHeader[i].PointerToRawData, lpSectionHeader[i].SizeOfRawData);
			}
		}

		// 重定向地址
		if (FALSE == DoRelocation(lpMemModule, virtualBase))
		{
			return false;
		}

		// 填充导入表
		if (FALSE == FillRavAddress(lpMemModule, virtualBase, pEprocess))
		{
			return false;
		}
		//清空PE头
		CleanPeHeader((PUCHAR)lpMemModule);
		PVOID dllmain = (PVOID)(virtualBase + lpNtHeader->OptionalHeader.AddressOfEntryPoint);
		*entrypoint = dllmain;

		return true;
	}


}