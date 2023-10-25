#include "FileUtil.h"
BOOLEAN ForceDeleteFile(_In_ PUNICODE_STRING DriverPath)
{
	return FALSE;
}

BOOLEAN RemoveFileLink(PEPROCESS eprocess)
{
	HANDLE fileHandle;
	NTSTATUS result;
	IO_STATUS_BLOCK ioBlock;
	DEVICE_OBJECT* device_object = NULL;
	void* object = NULL;
	OBJECT_ATTRIBUTES fileObject;
	UNICODE_STRING uPath;


	PFILE_OBJECT MaskFiles = NULL;
	POBJECT_NAME_INFORMATION pName = 0;
	PsReferenceProcessFilePointer(eprocess, &MaskFiles);

	IoQueryFileDosDeviceName(MaskFiles, &pName);

	wchar_t prefix[0x256] = L"\\??\\";
	wcscat(prefix, pName->Name.Buffer);
	Log("%ws  ", prefix);
	RtlInitUnicodeString(&uPath, prefix);
	ObDereferenceObject(MaskFiles);

	//switch context to UserMode
	//KeAttachProcess(eprocess);


	InitializeObjectAttributes(&fileObject,
		&uPath,
		OBJ_CASE_INSENSITIVE,
		NULL,
		NULL);

	result = IoCreateFileSpecifyDeviceObjectHint(
		&fileHandle,
		SYNCHRONIZE | FILE_WRITE_ATTRIBUTES | FILE_READ_ATTRIBUTES | FILE_READ_DATA, //0x100181 
		&fileObject,
		&ioBlock,
		0,
		0,
		FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, //FILE_SHARE_VALID_FLAGS,
		FILE_OPEN,
		FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT,//0x60,
		0,
		0,
		CreateFileTypeNone,
		0,
		IO_IGNORE_SHARE_ACCESS_CHECK,
		device_object);

	if (result != STATUS_SUCCESS)
	{
		Log("error in IoCreateFileSpecifyDeviceObjectHint");
		goto _Error;
	}

	result = ObReferenceObjectByHandle(fileHandle, 0, 0, 0, &object, 0);

	if (result != STATUS_SUCCESS)
	{
		Log("error in ObReferenceObjectByHandle");
		ZwClose(fileHandle);

		goto _Error;
	}

	/*
	METHOD 1
	*/
	((FILE_OBJECT*)object)->SectionObjectPointer->ImageSectionObject = 0;
	((FILE_OBJECT*)object)->DeleteAccess = 1;
	ObDereferenceObject(object);

	ZwClose(fileHandle);


	return TRUE;
_Error:

	return FALSE;
}

