#include "LoadDriver.h"
#include "../DestoryReg/ClearReg.h"
#include "../MyDriver.h"
#include <ntimage.h>
#include "AllDefines.h"

VOID DecryptDriverData() {
	int count = COUNT1;
	for (size_t i = 0; i < FILE_LEN; i++)
	{
		if (fileData[i] != 0)
		{
			if (i % 2 == 0)
			{
				count = COUNT2;
			}
			for (size_t t = 11; t < count; t++)
			{
				fileData[i] ^= t;
			}
		}
		count = COUNT1;
	}
}
PUCHAR FileBufferToImageBuffer()
{
	//File ->image
	PUCHAR pBuffer = (PUCHAR)fileData;
	PUCHAR pImageBuffer = NULL;


	//��λ�ṹ
	PIMAGE_DOS_HEADER		pDos = (PIMAGE_DOS_HEADER)pBuffer;
	//if (pDos->e_magic != IMAGE_DOS_SIGNATURE) return NULL;	// ���DOSͷ����Ч��
	PIMAGE_NT_HEADERS		pNth = (PIMAGE_NT_HEADERS)(pBuffer + pDos->e_lfanew);
	PIMAGE_SECTION_HEADER	pSec = IMAGE_FIRST_SECTION(pNth);

	//�����ڴ�
	pImageBuffer = ExAllocatePool(NonPagedPool, pNth->OptionalHeader.SizeOfImage);
	if (!pImageBuffer)
	{

		return NULL;
	}
	// ����ڴ沢����ͷ��
	memset(pImageBuffer, 0, pNth->OptionalHeader.SizeOfImage);
	memcpy(pImageBuffer, pBuffer, pNth->OptionalHeader.SizeOfHeaders);

	//��������
	for (size_t i = 0; i < pNth->FileHeader.NumberOfSections; i++)
	{
		ULONG VirtualAddress = pSec[i].VirtualAddress;
		ULONG SizeOfRawData = pSec[i].SizeOfRawData;
		ULONG PointerToRawData = pSec[i].PointerToRawData;
		if (pSec[i].SizeOfRawData != 0)
		{
			memcpy(
				pImageBuffer + pSec[i].VirtualAddress,
				pBuffer + pSec[i].PointerToRawData,
				pSec[i].SizeOfRawData
			);
		}

	}
	return pImageBuffer;
}

void Relocation(PUCHAR pImageBuffer)
{
	//��λ�ṹ
	PIMAGE_DOS_HEADER		pDos = (PIMAGE_DOS_HEADER)pImageBuffer;
	//if (pDos->e_magic != IMAGE_DOS_SIGNATURE) return NULL;	// ���DOSͷ����Ч��
	PIMAGE_NT_HEADERS		pNth = (PIMAGE_NT_HEADERS)(pImageBuffer + pDos->e_lfanew);

	PIMAGE_BASE_RELOCATION  pRel = (PIMAGE_BASE_RELOCATION)(pImageBuffer + pNth->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);
	if (pNth->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress == 0)
	{
		return;
	}

	//�����ض���
	while (pRel->VirtualAddress && pRel->SizeOfBlock)
	{
		//VirtualAddress
		//SizeOfBlock

		ULONG_PTR	uRelEntry = (pRel->SizeOfBlock - 8) / 2;
		PUSHORT		pRelEntry = (PUSHORT)((PUCHAR)pRel + 8); 
		for (size_t i = 0; i < uRelEntry; i++)
		{
			//�жϱ�־ 
			if ((pRelEntry[i] >> 12) == IMAGE_REL_BASED_DIR64)
			{
				ULONG_PTR uLowOffset = pRelEntry[i] & 0XFFF;
				ULONG_PTR* uRepairAddr = (ULONG_PTR*)(pImageBuffer + pRel->VirtualAddress + uLowOffset);
				*uRepairAddr = *uRepairAddr - pNth->OptionalHeader.ImageBase + pImageBuffer;
			} 
		} 
		pRel = (PIMAGE_BASE_RELOCATION)((PUCHAR)pRel + pRel->SizeOfBlock);
	}

}

 
 
ULONG_PTR GetModuleInfo(PUCHAR szModuleName, PULONG pModuleSize)
{
	NTSTATUS Status;
	PRTL_PROCESS_MODULES            Module;
	PRTL_PROCESS_MODULE_INFORMATION ModuleInfo;
	PVOID Buffer;
	ULONG BufferSize = 4096;
	ULONG ReturnLength;

FLAG:

	//�����ڴ� �洢ģ����Ϣ
	Buffer = ExAllocatePool(NonPagedPool, BufferSize);
	if (!Buffer)
	{
		return STATUS_NO_MEMORY;
	}
	//��ȡ�ں�ģ����Ϣ(��һ�ε�����Ϊ�����ڵ�ǰ���ȷ���STATUS_INFO_LENGTH_MISMATCH ���Ұ���ʵ���ȴ���ReturnLength)
	Status = ZwQuerySystemInformation(
		11,
		Buffer,
		BufferSize,
		&ReturnLength);
	if (Status == STATUS_INFO_LENGTH_MISMATCH)
	{
		ExFreePool(Buffer);
		BufferSize = ReturnLength;
		goto FLAG;
	}
	if (NT_SUCCESS(Status))
	{
		Module = (PRTL_PROCESS_MODULES)Buffer;

		//�����ں�ģ��

		for (size_t i = 0; i < Module->NumberOfModules; i++)
		{
			ModuleInfo = &Module->Modules[i];

			if (strstr(ModuleInfo->FullPathName, szModuleName) != 0)
			{
				if (pModuleSize != NULL)
				{
					*pModuleSize = ModuleInfo->ImageSize;
				}

				return ModuleInfo->ImageBase;
			}
		}
	}

}

ULONG_PTR GetExportFunAddrByName(PUCHAR pimageBase, PUCHAR pName)
{
	//��λ�ṹ
	PIMAGE_DOS_HEADER		pDos = (PIMAGE_DOS_HEADER)pimageBase;
	PIMAGE_NT_HEADERS		pNth = (PIMAGE_NT_HEADERS)(pimageBase + pDos->e_lfanew);
	PIMAGE_EXPORT_DIRECTORY pExp = (PIMAGE_EXPORT_DIRECTORY)(pimageBase + pNth->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);

	if (pNth->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress == NULL)
	{
		return NULL;
	}

	//��λ����
	PULONG pFunAddr = (PULONG)(pimageBase + pExp->AddressOfFunctions);
	PULONG pFunName = (PULONG)(pimageBase + pExp->AddressOfNames);
	PUSHORT pFunOrdi = (PUSHORT)(pimageBase + pExp->AddressOfNameOrdinals);

	//��������
	for (size_t i = 0; i < pExp->NumberOfNames; i++)
	{
		PUCHAR pExpName = pimageBase + pFunName[i];

		if (strcmp(pName, pExpName) == 0)
		{
			return (ULONG_PTR)(pimageBase + pFunAddr[pFunOrdi[i]]);
		}
	}

	return NULL;
}


VOID RepairImportData(PUCHAR pImageBuffer)
{
	//��λ�ṹ
	PIMAGE_DOS_HEADER			pDos = (PIMAGE_DOS_HEADER)pImageBuffer;
	//if (pDos->e_magic != IMAGE_DOS_SIGNATURE) return NULL;	// ���DOSͷ����Ч��
	PIMAGE_NT_HEADERS			pNth = (PIMAGE_NT_HEADERS)(pImageBuffer + pDos->e_lfanew);

	PIMAGE_IMPORT_DESCRIPTOR		pImp = (PIMAGE_BASE_RELOCATION)(pImageBuffer + pNth->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);
	if (pNth->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress == 0)
	{
		return;
	}
	//��������
	while (pImp->FirstThunk && pImp->OriginalFirstThunk)
	{

		PIMAGE_THUNK_DATA  pIAI = (PIMAGE_THUNK_DATA)(pImageBuffer + pImp->FirstThunk);
		PIMAGE_THUNK_DATA  pINT = (PIMAGE_THUNK_DATA)(pImageBuffer + pImp->OriginalFirstThunk);
		PUCHAR DLLName = (PUCHAR)(pImageBuffer + pImp->Name);
		while (pINT->u1.AddressOfData && pIAI->u1.Function)
		{
			NTSTATUS st = NULL;
			PIMAGE_IMPORT_BY_NAME pName = (PIMAGE_IMPORT_BY_NAME)(pINT->u1.AddressOfData + pImageBuffer);
			ANSI_STRING aFunName = { 0 };
			UNICODE_STRING uFunName = { 0 };
			ULONG_PTR uFunAddr = 0;
			RtlInitAnsiString(&aFunName, pName->Name);

			if (_stricmp(DLLName, "ntoskrnl.exe") == 0 ||
				_stricmp(DLLName, "ntkrnlpa.exe") == 0 ||
				_stricmp(DLLName, "hal.exe") == 0)
			{

				st = RtlAnsiStringToUnicodeString(&uFunName, &aFunName, TRUE);
				if (!NT_SUCCESS(st))return;
				DbgPrint("%wZ \r\n", uFunName);
				uFunAddr = MmGetSystemRoutineAddress(&uFunName);

				//�ͷ��ڴ�
				RtlFreeUnicodeString(&uFunName);

			}
			else
			{
				PUCHAR pImageBase = GetModuleInfo(DLLName, NULL);
				if (!pImageBase)
				{
					return;
				}

				uFunAddr = GetExportFunAddrByName(pImageBase, pName->Name);
			}

			if (!uFunAddr)
			{
				return;
			}


			//�޸ĵ�ַ
			pIAI->u1.Function = uFunAddr;



			//ָ���¸�
			pIAI++;
			pINT++;
		}

		pImp++;
	}
}


//�޸��߰汾�����ڵͰ汾����ϵͳ���������ļ�����
void Repaircookie(PUCHAR imagebuffer) {
	PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)imagebuffer;

	PIMAGE_NT_HEADERS pNts = (PIMAGE_NT_HEADERS)(imagebuffer + pDos->e_lfanew);
	PIMAGE_DATA_DIRECTORY pDir = &pNts->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG];
	PIMAGE_LOAD_CONFIG_DIRECTORY pconfig = (PIMAGE_LOAD_CONFIG_CODE_INTEGRITY)(pDir->VirtualAddress + imagebuffer);
	*(PULONG_PTR)(pconfig->SecurityCookie) += 10;
}
void RunDriver(PUCHAR imageBuffer)
{

	PIMAGE_DOS_HEADER pDosImage = (PIMAGE_DOS_HEADER)imageBuffer; 
	PIMAGE_NT_HEADERS pNtsImage = (PIMAGE_NT_HEADERS)(imageBuffer + pDosImage->e_lfanew); 
	PDRIVER_INITIALIZE oep = (PDRIVER_INITIALIZE)(pNtsImage->OptionalHeader.AddressOfEntryPoint + imageBuffer);  
	if (NT_SUCCESS(oep(NULL, NULL)))
	{
		DbgPrintEx(77, 0, "[SSS]%p oep %p\r\n", imageBuffer, oep);
	}
 
}

void ClearPeSection(PUCHAR imageBuffer)
{
	PIMAGE_DOS_HEADER pDosImage = (PIMAGE_DOS_HEADER)imageBuffer; 
	PIMAGE_NT_HEADERS pNtsImage = (PIMAGE_NT_HEADERS)(imageBuffer + pDosImage->e_lfanew);

	
	//ɾ��������Ϣ
	PIMAGE_DEBUG_DIRECTORY pDEBUG =(PIMAGE_DEBUG_DIRECTORY)(pNtsImage->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG].VirtualAddress + imageBuffer);
	ULONG dbgDirCount = pNtsImage->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG].Size/sizeof(IMAGE_DEBUG_DIRECTORY);
	for (size_t i = 0; i < dbgDirCount; i++)
	{
		memset(pDEBUG[i].AddressOfRawData + imageBuffer, 0xcc, pDEBUG[i].SizeOfData);
		DbgPrintEx(77, 0, "[SSS]clear dbg %p  %d  \r\n", pDEBUG[i].AddressOfRawData + imageBuffer, pDEBUG[i].SizeOfData);
	}
	memset(pNtsImage->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG].VirtualAddress + imageBuffer, 0xcc, pNtsImage->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG].Size);
	//������ñ�
	PIMAGE_DATA_DIRECTORY pCONFIG = &pNtsImage->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG];
	memset(pCONFIG->VirtualAddress + imageBuffer, 0xcc, pCONFIG->Size);

	 //��ո�����Ϣ �� ǩ����Ϣ
	PIMAGE_DATA_DIRECTORY pSECURITY = &pNtsImage->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_SECURITY];
	memset(pSECURITY->VirtualAddress + imageBuffer, 0xcc, pSECURITY->Size);



	DbgPrintEx(77, 0, "[SSS]Clear Section\r\n", imageBuffer);
	//���peͷ
	memset(imageBuffer, 0xcc, USN_PAGE_SIZE);
}




PUCHAR LoadDriver(PDRIVER_OBJECT pDriver, PUNICODE_STRING pReg)
{
	PUCHAR pFileBuffer = NULL;
	//ɾ������
	PUCHAR pImageBuffer = NULL;
	PLDR_DATA_TABLE_ENTRY pLDR_DATA_TABLE_ENTRY = (PLDR_DATA_TABLE_ENTRY)pDriver->DriverSection;
	DestroyDriverFile(&pLDR_DATA_TABLE_ENTRY->FullDllName);
	//ɾ��ע���
	DeleteRegeditEntry(pReg);
	//////���ݽ���
	 //DecryptDriverData(); 
	//�����ڴ�
	pImageBuffer = FileBufferToImageBuffer();
	if (!pImageBuffer) {
		// �������߼�
		return;
	}

	//�޸��ض�λ
	Relocation(pImageBuffer);
	//�޸������
	RepairImportData(pImageBuffer);

	//�޸�У��
	Repaircookie(pImageBuffer);
	//ִ����ں���
 	RunDriver(pImageBuffer);
	return pImageBuffer;
}
