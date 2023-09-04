#pragma once
#include "WIN32uDLL.h"
#include  "../Tools/Log.h"
#include "../Tools/PE.h"
#include "../Tools/DefineCommon.h"

PUCHAR pImageBase;
NTSTATUS InitializeWin32uDLL()
{
	PAGED_CODE();
	if (pImageBase)
	{
		return STATUS_SUCCESS;
	}
	UNICODE_STRING uModulePath = { 0 };
	RtlInitUnicodeString(&uModulePath, L"\\??\\C:\\Windows\\System32\\win32u.dll");
	OBJECT_ATTRIBUTES ObjectAttributes;
	InitializeObjectAttributes(&ObjectAttributes, &uModulePath,
		OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
		NULL, NULL);
	if (KeGetCurrentIrql() != PASSIVE_LEVEL)
	{
#ifdef _DEBUG
		DbgPrint("[SSS] KeGetCurrentIrql != PASSIVE_LEVEL!\n");
#endif
		return STATUS_UNSUCCESSFUL;
	}

	HANDLE FileHandle;
	IO_STATUS_BLOCK IoStatusBlock;
	NTSTATUS NtStatus = ZwCreateFile(&FileHandle,
		GENERIC_READ,
		&ObjectAttributes,
		&IoStatusBlock, NULL,
		FILE_ATTRIBUTE_NORMAL,
		FILE_SHARE_READ,
		FILE_OPEN,
		FILE_SYNCHRONOUS_IO_NONALERT,
		NULL, 0);
	if (NT_SUCCESS(NtStatus))
	{
		FILE_STANDARD_INFORMATION StandardInformation = { 0 };
		NtStatus = ZwQueryInformationFile(FileHandle, &IoStatusBlock, &StandardInformation, sizeof(FILE_STANDARD_INFORMATION), FileStandardInformation);
		if (NT_SUCCESS(NtStatus))
		{
			FileSize = StandardInformation.EndOfFile.LowPart;
			Log("[SSS] FileSize of ntdll.dll is %08X!\r\n", StandardInformation.EndOfFile.LowPart);

			FileData = (PUCHAR)ExAllocatePool(NonPagedPool, FileSize);

			LARGE_INTEGER ByteOffset;
			ByteOffset.LowPart = ByteOffset.HighPart = 0;
			NtStatus = ZwReadFile(FileHandle,
				NULL, NULL, NULL,
				&IoStatusBlock,
				FileData,
				FileSize,
				&ByteOffset, NULL);

			if (!NT_SUCCESS(NtStatus))
			{
				ExFreePool(FileData);
				Log("[SSS] ZwReadFile failed with status %08X...\r\n", NtStatus);
			}
		}
		else
			Log("[SSS] ZwQueryInformationFile failed with status %08X...\r\n", NtStatus);
		ZwClose(FileHandle);
	}
	else
		Log("[SSS] ZwCreateFile failed with status %08X...\r\n", NtStatus);
	return NtStatus;

}

void DeinitializeWin32uDLL()
{
	ExFreePool(FileData);
}







/// <summary>
/// 通过方法名获取pe文件导出函数地址
/// </summary>
/// <param name="funcName">导出函数名</param>
/// <returns>导出函数地址</returns>
ULONG_PTR GetFuncAddrByExportName(PCHAR funcName) {


	ULONG_PTR ExportOffset = GetExportOffset(FileData, FileSize, funcName);
	if (ExportOffset == PE_ERROR_VALUE)
		return -1;

	int SsdtOffset = -1;
	PUCHAR ExportData = FileData + ExportOffset;
	for (int i = 0; i < 32 && ExportOffset + i < FileSize; i++)
	{
		if (ExportData[i] == 0xC2 || ExportData[i] == 0xC3)  //RET
			break;
		if (ExportData[i] == 0xB8)  //mov eax,X
		{
			SsdtOffset = *(int*)(ExportData + i + 1);
			break;
		}
	}

	if (SsdtOffset == -1)
	{
		Log("[SSS] SSDT Offset for %s not found...\r\n", funcName);
	}

	return SsdtOffset;
}



