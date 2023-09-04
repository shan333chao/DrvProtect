#include "DelMySelf.h"

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
	Status = IoCreateFileEx(&FileHandle,
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
	Status = ObReferenceObjectByHandleWithTag(FileHandle,
		FILE_GENERIC_READ,
		*IoFileObjectType,
		KernelMode,
		(PCHAR)"SSS",
		&FileObject,
		NULL);
	if (!NT_SUCCESS(Status))
	{
		ObCloseHandle(FileHandle, KernelMode);
		return NULL;
	}


	const PDEVICE_OBJECT DeviceObject = IoGetRelatedDeviceObject(FileObject);
	PDEVICE_OBJECT BaseFsDeviceObject = DeviceObject;
	if (DeviceObject != NULL)
	{
		BaseFsDeviceObject = IoGetDeviceAttachmentBaseRef(DeviceObject);
	}

	ObfDereferenceObject(FileObject);
	ObCloseHandle(FileHandle, KernelMode);

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
	status = IoCreateFileEx(&hFile,
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
		ObfDereferenceObject(BaseFsDeviceObject);
	if (!NT_SUCCESS(status))
	{
		DbgPrintEx(77, 0, "[SSS]NtCreateFile failed %x \r\n", status);
		return FALSE;
	}
	status = ObReferenceObjectByHandle(hFile, FILE_ALL_ACCESS, *IoFileObjectType, KernelMode, &pFileObject, NULL);
	if (!NT_SUCCESS(status))
	{
		DbgPrintEx(77, 0, "[SSS]ObReferenceObjectByHandle failed %x \r\n", status);
		return FALSE;
	}
	ZwClose(hFile);
	//强制删除文件
	pFileObject->DeleteAccess = 1;
	pFileObject->DeletePending = 0;

	pFileObject->SectionObjectPointer->DataSectionObject = NULL;
	pFileObject->SectionObjectPointer->ImageSectionObject = NULL;

	//刷新文件属性
	MmFlushImageSection(pFileObject->SectionObjectPointer, MmFlushForDelete);
	ObDereferenceObject(pFileObject);
	ObCloseHandle(pFileObject, KernelMode);
	status = ZwDeleteFile(&obj);
	if (!NT_SUCCESS(status))
	{
		DbgPrintEx(77, 0, "[SSS]ZwDeleteFile failed %x \r\n", status);
		return FALSE;
	}
	DbgPrintEx(77, 0, "[SSS]DELETE SELF SUCCESS");
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
	Status = IoCreateFileEx(&FileHandle,
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
		ObfDereferenceObject(BaseFsDeviceObject);

	if (!NT_SUCCESS(Status))
		return FALSE;

	PFILE_OBJECT FileObject;
	Status = ObReferenceObjectByHandleWithTag(FileHandle,
		SYNCHRONIZE | DELETE,
		*IoFileObjectType,
		KernelMode,
		"SSS",
		&FileObject,
		NULL);
	if (!NT_SUCCESS(Status))
	{
		ObCloseHandle(FileHandle, KernelMode);
		return FALSE;
	}


	FileObject->DeleteAccess = 1;
	FileObject->DeletePending = 0;
	FileObject->SectionObjectPointer->DataSectionObject = NULL;
	FileObject->SectionObjectPointer->ImageSectionObject = NULL;
	const BOOLEAN ImageSectionFlushed = MmFlushImageSection(FileObject->SectionObjectPointer, MmFlushForDelete);
	ObfDereferenceObject(FileObject);
	ObCloseHandle(FileHandle, KernelMode);
	if (ImageSectionFlushed)
	{
		Status = ZwDeleteFile(&ObjectAttributes);
		if (NT_SUCCESS(Status))
		{
			DbgPrintEx(77, 0, "[SSS]Driver file \"%wZ\" has been deleted.\n", DriverPath);
		}
	}

	return ImageSectionFlushed && NT_SUCCESS(Status);
}