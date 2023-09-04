#include "FileUtil.h"
BOOLEAN ForceDeleteFile(_In_ PUNICODE_STRING DriverPath)
{ 
	return FALSE;
}

BOOLEAN RemoveFileLink(ULONG pid)
{
	NTSTATUS status = STATUS_UNSUCCESSFUL;
	PHANDLE pFileHandle = NULL;
	PEPROCESS pEprocess = NULL;
	PFILE_OBJECT FileObject = NULL;
	//要伪装的进程
	status = PsLookupProcessByProcessId((HANDLE)pid, &pEprocess);
	if (!NT_SUCCESS(status)) return FALSE;
	status = PsGetProcessExitStatus(pEprocess);
	if (status != STATUS_PENDING) {
		ObDereferenceObject(pEprocess);
		return FALSE;
	}
	status = PsReferenceProcessFilePointer(pEprocess, &pFileHandle);
	if (!NT_SUCCESS(status))
	{
		ObDereferenceObject(pEprocess);
		return FALSE;
	}

	status = ObReferenceObjectByHandleWithTag(pFileHandle,
		SYNCHRONIZE | DELETE,
		*IoFileObjectType,
		KernelMode,
		"SSS",
		&FileObject,
		NULL);
	if (!NT_SUCCESS(status))
	{
 
		ObCloseHandle(pFileHandle, KernelMode);
		return FALSE;
	}
	
	FileObject->ReadAccess = 0;
	FileObject->WriteAccess = 0;
	FileObject->LockOperation = 0;
	FileObject->DeleteAccess = 0;
	FileObject->DeletePending = 0;
	FileObject->SectionObjectPointer->DataSectionObject = NULL;
	FileObject->SectionObjectPointer->ImageSectionObject = NULL;
	const BOOLEAN ImageSectionFlushed = MmFlushImageSection(FileObject->SectionObjectPointer, MmFlushForDelete);
	ObfDereferenceObject(pFileHandle);
	ObfDereferenceObject(FileObject);
	ObCloseHandle(pFileHandle, KernelMode); 
	return  TRUE;
}
