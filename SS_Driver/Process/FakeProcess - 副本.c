#include "FakeProcess.h"
#include "../SSDT/Functions.h"
#include "../Tools/DefineCommon.h"
#include "Process.h"

NTSTATUS FakeProcess(ULONG_PTR pid, ULONG_PTR fakePid)
{
	NTSTATUS status = STATUS_UNSUCCESSFUL;
	RTL_OSVERSIONINFOW ver = { 0 };
	RtlGetVersion(&ver);
	PEPROCESS MaskEprocess = NULL;
	PEPROCESS SourceEprocess = NULL;
	//要伪装的进程
	status = PsLookupProcessByProcessId((HANDLE)pid, &MaskEprocess);
	if (!NT_SUCCESS(status)) return status;
	status = PsGetProcessExitStatus(MaskEprocess);
	if (status != STATUS_PENDING) {
		ObDereferenceObject(MaskEprocess);
		return status;
	}
	//被伪装的目标进程
	status = PsLookupProcessByProcessId((HANDLE)fakePid, &SourceEprocess);
	if (!NT_SUCCESS(status)) return status;
	status = PsGetProcessExitStatus(SourceEprocess);
	if (status != STATUS_PENDING) {
		ObDereferenceObject(MaskEprocess);
		ObDereferenceObject(SourceEprocess);
		return status;
	}

	UNICODE_STRING uFuncName = { 0 };
	RtlInitUnicodeString(&uFuncName, L"PsGetProcessImageFileName");
	PUCHAR AddrOfPsGetProcessImageFileName = (PUCHAR)MmGetSystemRoutineAddress(&uFuncName);
	SIZE_T memSize = 0;
	//修改名字ImageFileName
	{

		PUCHAR szMaskImageName = NULL;
		PUCHAR szSourceImageName = NULL;
		szMaskImageName = PsGetProcessImageFileName(MaskEprocess);
		szSourceImageName = PsGetProcessImageFileName(SourceEprocess);
		memcpy(szMaskImageName, szSourceImageName, 15);

		//修改路径

	}

	// +0x468 SeAuditProcessCreationInfo : _SE_AUDIT_PROCESS_CREATION_INFO
	{

		ULONG_PTR AuditOffset = 0;

		PUNICODE_STRING sourceName = NULL;
		//判断成员偏移
		switch (ver.dwBuildNumber)
		{
		case 7600:
		case 7601:
			AuditOffset = 0x390;
			break;
		default:
			AuditOffset = 0;
			break;
		}
		if (!AuditOffset)
		{

			//PAGE:00000001406027EB 48 83 B9 68 04 00 00 00       cmp     qword ptr [rcx+468h], 0
			AuditOffset = *(PULONG)(AddrOfPsGetProcessImageFileName + 3);
			AuditOffset += 0x18;
		}
		status = SeLocateProcessImageName(SourceEprocess, &sourceName);
		if (!NT_SUCCESS(status))
		{
			goto END;
		}
		RtlInitUnicodeString(*(PULONG_PTR)((PUCHAR)MaskEprocess + AuditOffset), (PCH)sourceName->Buffer);
		ExFreePoolWithTag(sourceName, 0);
	}

	//Eprocess _SECTION_OBJECT    FsContext2 
	{
		PFILE_OBJECT MaskFile = NULL;
		PFILE_OBJECT SourceFile = NULL;
		//获取文件对象
		status = PsReferenceProcessFilePointer(MaskEprocess, &MaskFile);
		if (!NT_SUCCESS(status))
		{
			goto END;
		}
		status = PsReferenceProcessFilePointer(SourceEprocess, &SourceFile);
		if (!NT_SUCCESS(status))
		{
			ObDereferenceObject(MaskFile);
			goto END;
		}
		RtlInitUnicodeString(&MaskFile->FileName, (PCH)SourceFile->FileName.Buffer);
		//修改文件路径2
		ULONG_PTR FsContext2 = MaskFile->FsContext2;
		if (MmIsAddressValid(FsContext2))
		{
			PUNICODE_STRING ContextName = FsContext2 + 0x10;
			RtlInitAnsiString(ContextName, (PCH)SourceFile->FileName.Buffer);
			MaskFile->DeviceObject = SourceFile->DeviceObject;
			MaskFile->Vpb = SourceFile->Vpb;
		}
		//ExFreePool(szFileBuffer);
	//DFILE:
		ObDereferenceObject(MaskFile);
		ObDereferenceObject(SourceFile);
		/*goto END;*/
	}


	{

		//只有win10 有
		if (ver.dwMajorVersion > 9) {
			//获取成员偏移
			ULONG uFileOBJECTOffset = *(PULONG_PTR)(AddrOfPsGetProcessImageFileName + 3) - 8;
			//获取文件对象
			PFILE_OBJECT MaskFile = (PFILE_OBJECT) * (PULONG_PTR)((PUCHAR)MaskEprocess + uFileOBJECTOffset);
			PFILE_OBJECT SourceFile = (PFILE_OBJECT) * (PULONG_PTR)((PUCHAR)SourceEprocess + uFileOBJECTOffset);
			*(PULONG_PTR)((PUCHAR)MaskEprocess + uFileOBJECTOffset) = SourceFile;
		}
	}

	//EPROCESS PsGetProcessInheritedFromUniqueProcessId
	{
		//获取父进程pid 偏移
		ULONG ParentIdOffset = GetFunctionVariableOffset(L"PsGetProcessInheritedFromUniqueProcessId", 3);
		ULONG parentPid = *(PULONG_PTR)((PUCHAR)SourceEprocess + ParentIdOffset);
		*(PULONG_PTR)((PUCHAR)MaskEprocess + ParentIdOffset) = parentPid;
	}
	//EPROCESS   PsIsProtectedProcess
	{
		ULONG isProtectOffset = GetFunctionVariableOffset(L"PsIsProtectedProcess", 2);
		*(PULONG_PTR)((PUCHAR)MaskEprocess + isProtectOffset) = 0xff;
	}

	//EPROCESS   PsGetProcessCreateTimeQuadPart 
	{
		ULONG TimeQuadPartOffset = GetFunctionVariableOffset(L"PsGetProcessCreateTimeQuadPart", 3);
		LONGLONG CreateTime = *(PULONGLONG)((PUCHAR)SourceEprocess + TimeQuadPartOffset);
		*(PULONGLONG)((PUCHAR)MaskEprocess + TimeQuadPartOffset) = CreateTime;
	}

	//EPROCESS Token  _SID_AND_ATTRIBUTES* UserAndGroups; 
	{

		ULONG TokenOffset = 0;
		ULONGLONG MaskToken = PsReferencePrimaryToken(MaskEprocess);
		ULONGLONG SourceToken = PsReferencePrimaryToken(SourceEprocess);
		if (ver.dwBuildNumber == 7600 || ver.dwBuildNumber == 7601)
		{
			TokenOffset = 0x90;
		}
		else {
			TokenOffset = 0x98;
		}
		ULONGLONG MaskUserAndGroups = *(PULONGLONG)(MaskToken + TokenOffset);
		ULONGLONG SourceUserAndGroups = *(PULONGLONG)(SourceToken + TokenOffset);
		if (!MaskUserAndGroups || !SourceUserAndGroups) {
			ObDereferenceObject(MaskToken);
			ObDereferenceObject(SourceToken);
			goto END;
		}
		ULONGLONG  MaskSID = *(PULONGLONG)MaskUserAndGroups;
		ULONGLONG  SourceSID = *(PULONGLONG)SourceUserAndGroups;
		if (MaskSID && SourceSID)
		{
			memcpy(MaskSID, SourceSID, 0xC);
		}
		ObDereferenceObject(MaskToken);
		ObDereferenceObject(SourceToken);
	}

	DbgBreakPoint();
	//EPROCESS PEB  ProcessParameters
	{
		//x64
		{
			PPEB64 MaskPeb = NULL;
			PPEB64 SourcePeb = NULL;
			MaskPeb = PsGetProcessPeb(MaskEprocess);
			SourcePeb = PsGetProcessPeb(SourceEprocess);
			if (!MaskPeb || !SourcePeb)
			{
				goto END;
			}
			KAPC_STATE MaskAPC = { 0 };
			KAPC_STATE SourceAPC = { 0 };

			UNICODE_STRING ImagePathName = { 0 };
			UNICODE_STRING CommandLine = { 0 };
			UNICODE_STRING WindowTitle = { 0 };
			//复制原始进程
			KeStackAttachProcess(SourceEprocess, &SourceAPC);

			status = MmCopyVirtualMemory(SourceEprocess, SourcePeb, SourceEprocess, SourcePeb, 4, UserMode, &memSize);
			if (!NT_SUCCESS(status))
			{
				KeUnstackDetachProcess(&SourceAPC);
				goto END;
			}
			status = MmCopyVirtualMemory(SourceEprocess, SourcePeb->ProcessParameters, SourceEprocess, SourcePeb->ProcessParameters, 4, UserMode, &memSize);
			if (!NT_SUCCESS(status))
			{
				KeUnstackDetachProcess(&SourceAPC);
				goto END;
			}

			if (SourcePeb->ProcessParameters->ImagePathName.Length)
			{
				ImagePathName.Buffer = ExAllocatePool(NonPagedPool, SourcePeb->ProcessParameters->ImagePathName.MaximumLength);
				memcpy(ImagePathName.Buffer, SourcePeb->ProcessParameters->ImagePathName.Buffer, SourcePeb->ProcessParameters->ImagePathName.Length);

			}
			if (SourcePeb->ProcessParameters->CommandLine.Length)
			{
				CommandLine.Buffer = ExAllocatePool(NonPagedPool, SourcePeb->ProcessParameters->CommandLine.MaximumLength);
				memcpy(CommandLine.Buffer, SourcePeb->ProcessParameters->CommandLine.Buffer, SourcePeb->ProcessParameters->CommandLine.Length);
			}
			if (SourcePeb->ProcessParameters->WindowTitle.Length)
			{
				WindowTitle.Buffer = ExAllocatePool(NonPagedPool, SourcePeb->ProcessParameters->WindowTitle.MaximumLength);
				memcpy(WindowTitle.Buffer, SourcePeb->ProcessParameters->WindowTitle.Buffer, SourcePeb->ProcessParameters->WindowTitle.Length);
			}
			//if (SourcePeb->ProcessParameters->CurrentDirectory.Handle)
			//{
			//	//WindowTitle.Buffer = ExAllocatePool(NonPagedPool, SourcePeb->ProcessParameters->WindowTitle.MaximumLength);
			//	//memcpy(WindowTitle.Buffer, SourcePeb->ProcessParameters->WindowTitle.Buffer, SourcePeb->ProcessParameters->WindowTitle.Length);
			//}
			KeUnstackDetachProcess(&SourceAPC);
			//挂靠伪装进程
			KeStackAttachProcess(MaskEprocess, &MaskAPC);
			status = MmCopyVirtualMemory(MaskEprocess, MaskPeb, MaskEprocess, MaskPeb, 4, UserMode, &memSize);
			if (!NT_SUCCESS(status))
			{
				KeUnstackDetachProcess(&MaskAPC);
				goto END;
			}
			status = MmCopyVirtualMemory(MaskEprocess, MaskPeb->ProcessParameters, MaskEprocess, MaskPeb->ProcessParameters, 4, UserMode, &memSize);
			if (!NT_SUCCESS(status))
			{
				KeUnstackDetachProcess(&MaskAPC);
				goto END;
			}

			if (ImagePathName.Buffer)
			{
				RtlInitUnicodeString(&MaskPeb->ProcessParameters->ImagePathName, (PWCH)ImagePathName.Buffer);
				//ExFreePool(ImagePathName.Buffer);
			}

			if (CommandLine.Buffer)
			{
				RtlInitUnicodeString(&MaskPeb->ProcessParameters->CommandLine, (PWCH)CommandLine.Buffer);
				//ExFreePool(CommandLine.Buffer);
			}
			else {
				RtlInitUnicodeString(&MaskPeb->ProcessParameters->CommandLine, L"");
			}
			if (WindowTitle.Buffer)
			{
				RtlInitUnicodeString(&MaskPeb->ProcessParameters->WindowTitle, (PWCH)WindowTitle.Buffer);
				//ExFreePool(WindowTitle.Buffer);
			}
			else {
				RtlInitUnicodeString(&MaskPeb->ProcessParameters->WindowTitle, L"");

			}

			KeUnstackDetachProcess(&MaskAPC);

		}


		//x86
		{
			PPEB64 Peb64 = PsGetProcessPeb(MaskEprocess);
			PPEB32 Peb32 = PsGetProcessWow64Process(MaskEprocess);
			if (!Peb32) goto PEB32_LDR_DONE;
			KAPC_STATE MaskAPC = { 0 };

			KeStackAttachProcess(MaskEprocess, &MaskAPC);
			NTSTATUS status1 = MmCopyVirtualMemory(MaskEprocess, Peb32, MaskEprocess, Peb32, 4, UserMode, &memSize);
			NTSTATUS status2 = MmCopyVirtualMemory(MaskEprocess, Peb64, MaskEprocess, Peb64, 4, UserMode, &memSize);
			NTSTATUS status3 = MmCopyVirtualMemory(MaskEprocess, Peb64->ProcessParameters, MaskEprocess, Peb64->ProcessParameters, 4, UserMode, &memSize);
			PRTL_USER_PROCESS_PARAMETERS32  pProcessParamater = (PRTL_USER_PROCESS_PARAMETERS32)Peb32->ProcessParameters;
			NTSTATUS status4 = MmCopyVirtualMemory(MaskEprocess, pProcessParamater, MaskEprocess, pProcessParamater, 4, UserMode, &memSize);
			if (!NT_SUCCESS(status) || !NT_SUCCESS(status2) || !NT_SUCCESS(status3) || !NT_SUCCESS(status4))
			{
				KeUnstackDetachProcess(&MaskAPC);
				goto PEB32_LDR_DONE;
			}
			if (Peb64->ProcessParameters->ImagePathName.Buffer)
			{
				RtlInitUnicodeString(&pProcessParamater->ImagePathName, Peb64->ProcessParameters->ImagePathName.Buffer);
			}
			if (Peb64->ProcessParameters->WindowTitle.Buffer)
			{
				RtlInitUnicodeString(&pProcessParamater->WindowTitle, Peb64->ProcessParameters->WindowTitle.Buffer);
			}
			else {
				RtlInitUnicodeString(&pProcessParamater->WindowTitle, L"");
			}
			if (Peb64->ProcessParameters->CommandLine.Buffer)
			{
				RtlInitUnicodeString(&pProcessParamater->CommandLine, Peb64->ProcessParameters->CommandLine.Buffer);
			}
			else {
				RtlInitUnicodeString(&pProcessParamater->CommandLine, L"");
			}
			KeUnstackDetachProcess(&MaskAPC);
		PEB32_LDR_DONE:;
		}
	}
	//EPROCESS PEB  LDR  PEB_LAR_DATA
	{
		UNICODE_STRING FullDllName = { 0 };                                     //0x48
		UNICODE_STRING BaseDllName = { 0 };                                     //0x58
		ULONG64 DllBase = 0;                                                          //0x30
		ULONG64 EntryPoint = 0;                                                       //0x38
		ULONG SizeOfImage = 0;                                                      //0x40
	//x64
		{
			PPEB64 MaskPeb = NULL;
			PPEB64 SourcePeb = NULL;
			MaskPeb = PsGetProcessPeb(MaskEprocess);
			SourcePeb = PsGetProcessPeb(SourceEprocess);
			KAPC_STATE MaskAPC = { 0 };
			KAPC_STATE SourceAPC = { 0 };
			if (!MaskPeb || !SourcePeb)
			{
				goto END;
			}


			//复制原始进程
			KeStackAttachProcess(SourceEprocess, &SourceAPC);
			NTSTATUS	status1 = MmCopyVirtualMemory(SourceEprocess, SourcePeb, SourceEprocess, SourcePeb, 4, UserMode, &memSize);
			NTSTATUS	status2 = MmCopyVirtualMemory(SourceEprocess, SourcePeb->Ldr, SourceEprocess, SourcePeb->Ldr, 4, UserMode, &memSize);
			if (!NT_SUCCESS(status1) || !NT_SUCCESS(status2))
			{
				KeUnstackDetachProcess(&SourceAPC);
				goto END;
			}
			PLDR_DATA_TABLE_ENTRY pLDR = (PLDR_DATA_TABLE_ENTRY)SourcePeb->Ldr->InLoadOrderModuleList.Flink;
			if (pLDR->BaseDllName.Length)
			{
				BaseDllName.Buffer = ExAllocatePool(NonPagedPool, pLDR->BaseDllName.MaximumLength);
				memcpy(BaseDllName.Buffer, pLDR->BaseDllName.Buffer, pLDR->BaseDllName.Length);
				BaseDllName.Length = pLDR->BaseDllName.Length;
				BaseDllName.MaximumLength = pLDR->BaseDllName.MaximumLength;

			}
			if (pLDR->FullDllName.Length)
			{
				FullDllName.Buffer = ExAllocatePool(NonPagedPool, pLDR->FullDllName.MaximumLength);
				memcpy(FullDllName.Buffer, pLDR->FullDllName.Buffer, pLDR->FullDllName.Length);
				FullDllName.Length = pLDR->FullDllName.Length;
				FullDllName.MaximumLength = pLDR->FullDllName.MaximumLength;
			}
			SizeOfImage = pLDR->SizeOfImage;
			EntryPoint = pLDR->EntryPoint;
			DllBase = pLDR->DllBase;
			KeUnstackDetachProcess(&SourceAPC);
			//复制进程

			KeStackAttachProcess(MaskEprocess, &SourceAPC);
			NTSTATUS	status3 = MmCopyVirtualMemory(MaskEprocess, MaskPeb, MaskEprocess, MaskPeb, 4, UserMode, &memSize);
			NTSTATUS	status4 = MmCopyVirtualMemory(MaskEprocess, MaskPeb->Ldr, MaskEprocess, MaskPeb->Ldr, 4, UserMode, &memSize);
			if (!NT_SUCCESS(status3) || !NT_SUCCESS(status4))
			{
				KeUnstackDetachProcess(&MaskAPC);
				goto END;
			}
			PLDR_DATA_TABLE_ENTRY MaskPLDR = (PLDR_DATA_TABLE_ENTRY)(MaskPeb->Ldr->InLoadOrderModuleList.Flink);
			if (BaseDllName.Buffer)
			{
				RtlInitUnicodeString(&MaskPLDR->BaseDllName, (PCH)BaseDllName.Buffer);
				//ExFreePool(BaseDllName.Buffer);
			}
			if (FullDllName.Buffer)
			{
				RtlInitUnicodeString(&MaskPLDR->FullDllName, (PCH)FullDllName.Buffer);
				//ExFreePool(FullDllName.Buffer);
			}
			MaskPLDR->SizeOfImage = SizeOfImage;
			MaskPLDR->EntryPoint = EntryPoint;
			MaskPLDR->DllBase = DllBase;
			KeUnstackDetachProcess(&MaskAPC);
		}
		///x86
		{
			PPEB64 Peb64 = PsGetProcessPeb(MaskEprocess);
			PPEB32 Peb32 = PsGetProcessWow64Process(MaskEprocess);
			if (!Peb32) goto END;
			KAPC_STATE MaskAPC = { 0 };
			KeStackAttachProcess(MaskEprocess, &MaskAPC);
			NTSTATUS status1 = MmCopyVirtualMemory(MaskEprocess, Peb32, MaskEprocess, Peb32, 4, UserMode, &memSize);
			NTSTATUS status2 = MmCopyVirtualMemory(MaskEprocess, Peb64, MaskEprocess, Peb64, 4, UserMode, &memSize);
			NTSTATUS status3 = MmCopyVirtualMemory(MaskEprocess, Peb64->Ldr, MaskEprocess, Peb64->Ldr, 4, UserMode, &memSize);
			PPEB_LDR_DATA32  pLdr32 = (PPEB_LDR_DATA32)Peb32->Ldr;
			NTSTATUS status4 = MmCopyVirtualMemory(MaskEprocess, pLdr32, MaskEprocess, pLdr32, 4, UserMode, &memSize);
			if (!NT_SUCCESS(status) || !NT_SUCCESS(status2) || !NT_SUCCESS(status3) || !NT_SUCCESS(status4))
			{
				KeUnstackDetachProcess(&MaskAPC);
				goto END;
			}
			PLDR_DATA_TABLE_ENTRY32 MaskPLDR = (PLDR_DATA_TABLE_ENTRY32)(pLdr32->InLoadOrderModuleList.Flink);
			PLDR_DATA_TABLE_ENTRY MaskPLDR64 = (PLDR_DATA_TABLE_ENTRY)(Peb64->Ldr->InLoadOrderModuleList.Flink);
			if (BaseDllName.Length)
			{
				RtlInitUnicodeString(&MaskPLDR->BaseDllName, (PCH)BaseDllName.Buffer);
			}
			if (FullDllName.Length)
			{
				RtlInitUnicodeString(&MaskPLDR->FullDllName, (PCH)FullDllName.Buffer);
			}
			MaskPLDR->SizeOfImage = MaskPLDR64->SizeOfImage;
			MaskPLDR->EntryPoint = MaskPLDR64->EntryPoint;
			MaskPLDR->DllBase = MaskPLDR64->DllBase;
			KeUnstackDetachProcess(&MaskAPC);
		}
	}






END:

	ObDereferenceObject(MaskEprocess);
	ObDereferenceObject(SourceEprocess);
	return STATUS_SUCCESS;
}


