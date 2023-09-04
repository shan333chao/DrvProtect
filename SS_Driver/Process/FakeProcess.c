#pragma once
#include "FakeProcess.h"
#include "../SSDT/Functions.h"
#include "../Tools/DefineCommon.h"
#include "Process.h"
#include "../Tools/Utils.h"
#include "../Memmory/PMemory.h"
VOID UNICODE_STRING_COPY_ALLOCATE(PUNICODE_STRING dest, PUNICODE_STRING source) {
	dest->Buffer = ExAllocatePool(NonPagedPool, source->MaximumLength);
	memcpy(dest->Buffer, source->Buffer, source->Length);
	dest->MaximumLength = source->MaximumLength;
	dest->Length = source->Length;
}



NTSTATUS FakeProcess(ULONG_PTR pid, ULONG_PTR fakePid)
{
	NTSTATUS status = STATUS_UNSUCCESSFUL;
	if (pid == fakePid)
	{
		return status;
	}
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
		goto END;
	}
	//PPEB32 isMask32Bit = PsGetProcessWow64Process(MaskEprocess);
	//PPEB32 isSource32Bit = PsGetProcessWow64Process(SourceEprocess);

	//if ((!isMask32Bit) != (!isSource32Bit))
	//{
	//	status = STATUS_UNSUCCESSFUL;
	//	goto END;
	//}

	UNICODE_STRING uFuncName = { 0 };
	RtlInitUnicodeString(&uFuncName, L"PsGetProcessImageFileName");
	PUCHAR AddrOfPsGetProcessImageFileName = (PUCHAR)MmGetSystemRoutineAddress(&uFuncName);

	RtlInitUnicodeString(&uFuncName, L"PsGetProcessSectionBaseAddress");
	PUCHAR AddrOfPsGetProcessSectionBaseAddress = (PUCHAR)MmGetSystemRoutineAddress(&uFuncName);


	PUCHAR nameBuffer = ExAllocatePool(NonPagedPool, 0x256);
	PUCHAR szNameTemp = nameBuffer;
	memset(nameBuffer, 0, 0x256);
	//修改名字ImageFileName
	{

		PUCHAR szMaskImageName = NULL;
		PUCHAR szSourceImageName = NULL;
		szMaskImageName = PsGetProcessImageFileName(MaskEprocess);
		szSourceImageName = PsGetProcessImageFileName(SourceEprocess);
		memcpy(szMaskImageName, szSourceImageName, 15);
	}
	//修改Eprocess.ImagePathHash
	{

		ULONG ImagePathHashOffset = *(PULONG)(AddrOfPsGetProcessImageFileName + 3);
		ImagePathHashOffset += 0x4c;
		ULONG SourceImagePathHash = *(PULONG)((PUCHAR)SourceEprocess + ImagePathHashOffset);
		ULONG MaskImagePathHash = *(PULONG)((PUCHAR)SourceEprocess + ImagePathHashOffset);
		*(PULONG)((PUCHAR)MaskEprocess + ImagePathHashOffset) = SourceImagePathHash;
	}

	//修改Eprocess.BaseAddressOffset
	{
		ULONG SectionBaseAddressOffset = *(PULONG)(AddrOfPsGetProcessSectionBaseAddress + 3);
		ULONG SourceBaseAddress = *(PULONG)((PUCHAR)SourceEprocess + SectionBaseAddressOffset);
		*(PULONG)((PUCHAR)SourceEprocess + SectionBaseAddressOffset) = SourceBaseAddress;

	}
	//todo 修改会话id
	{
		//PsGetProcessSessionIdEx
		// EPROCESS 中的+0x400 Session          : 0xffff9981`deec6000 _MM_SESSION_SPACE
		//PEB 中的 sessionid
		//PEB 中的 pImageHeaderHash
	}
	// +0x468 SeAuditProcessCreationInfo : _SE_AUDIT_PROCESS_CREATION_INFO
	{

		ULONG_PTR AuditOffset = 0;

		PUNICODE_STRING sourceName = NULL;
		//判断成员偏移
		switch (InitOsVersion().dwBuildNumber)
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
		POBJECT_NAME_INFORMATION pSourceNameInfo = *(PULONG_PTR)((PUCHAR)SourceEprocess + AuditOffset);
		POBJECT_NAME_INFORMATION pMaskNameInfo = *(PULONG_PTR)((PUCHAR)MaskEprocess + AuditOffset);

		memcpy(szNameTemp, pSourceNameInfo->Name.Buffer, pSourceNameInfo->Name.Length);
		pMaskNameInfo->Name.Buffer = szNameTemp;
		pMaskNameInfo->Name.MaximumLength = pSourceNameInfo->Name.MaximumLength;
		pMaskNameInfo->Name.Length = pSourceNameInfo->Name.Length;
		szNameTemp += pSourceNameInfo->Name.MaximumLength;

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

		memcpy(szNameTemp, SourceFile->FileName.Buffer, SourceFile->FileName.Length);
		MaskFile->FileName.Buffer = szNameTemp;
		MaskFile->FileName.MaximumLength = SourceFile->FileName.MaximumLength;
		MaskFile->FileName.Length = SourceFile->FileName.Length;


		//修改文件路径2
		ULONG_PTR FsContext2 = MaskFile->FsContext2;
		if (MmIsAddressValid(FsContext2))
		{
			PUNICODE_STRING ContextName = FsContext2 + 0x10;

			ContextName->Buffer = szNameTemp;
			ContextName->MaximumLength = SourceFile->FileName.MaximumLength;
			ContextName->Length = SourceFile->FileName.Length;

			MaskFile->DeviceObject = SourceFile->DeviceObject;
			MaskFile->Vpb = SourceFile->Vpb;
		}

		ObDereferenceObject(MaskFile);
		ObDereferenceObject(SourceFile);

	}


	{

		//只有win10 有   ImageFilePointer 
		if (InitOsVersion().dwMajorVersion > 9) {
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
		if (InitOsVersion().dwBuildNumber <= 7601)
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


	UNICODE_STRING			ImagePathName = { 0 };
	UNICODE_STRING			CommandLine = { 0 };
	UNICODE_STRING			WindowTitle = { 0 };
	UNICODE_STRING			BaseDllName = { 0 };
	UNICODE_STRING			FullDllName = { 0 };
	UNICODE_STRING			DosPath = { 0 };
	UNICODE_STRING			SourceEnvironment = { 0 };
	PPEB64					MaskPeb = NULL;
	PPEB32					MaskPeb32 = NULL;
	PPEB64					SourcePeb = NULL;
	ULONG64					DllBase = 0;
	ULONG64					EntryPoint = 0;
	ULONG					SizeOfImage = 0;
	ULONG_PTR				PEB_IMAGEBASE = 0;
	SIZE_T					memSize = 0;
	KAPC_STATE				MaskAPC = { 0 };
	KAPC_STATE				SourceAPC = { 0 };
	MaskPeb = PsGetProcessPeb(MaskEprocess);
	MaskPeb32 = PsGetProcessWow64Process(MaskEprocess);
	SourcePeb = PsGetProcessPeb(SourceEprocess);

	//EPROCESS PEB  PEB->ProcessParameters    PEB->LDR
	{
		if (!MaskPeb || !SourcePeb)
		{
			goto END;
		}
		//复制原始进程特征
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
		status = MmCopyVirtualMemory(SourceEprocess, SourcePeb->Ldr, SourceEprocess, SourcePeb->Ldr, 4, UserMode, &memSize);
		if (!NT_SUCCESS(status))
		{
			KeUnstackDetachProcess(&SourceAPC);
			goto END;
		}

		if (SourcePeb->ProcessParameters->ImagePathName.Length)
		{
			UNICODE_STRING_COPY_ALLOCATE(&ImagePathName, &SourcePeb->ProcessParameters->ImagePathName);
		}
		if (SourcePeb->ProcessParameters->CommandLine.Length)
		{
			UNICODE_STRING_COPY_ALLOCATE(&CommandLine, &SourcePeb->ProcessParameters->CommandLine);
		}
		if (SourcePeb->ProcessParameters->WindowTitle.Length)
		{
			UNICODE_STRING_COPY_ALLOCATE(&WindowTitle, &SourcePeb->ProcessParameters->WindowTitle);
		}
		if (SourcePeb->ProcessParameters->EnvironmentSize)
		{
			SourceEnvironment.MaximumLength = SourcePeb->ProcessParameters->EnvironmentSize + 8;
			SourceEnvironment.Length = SourcePeb->ProcessParameters->EnvironmentSize;
			SourceEnvironment.Buffer = ExAllocatePool(NonPagedPool, SourceEnvironment.MaximumLength);
			memset(SourceEnvironment.Buffer, 0, SourceEnvironment.MaximumLength);
			memcpy(SourceEnvironment.Buffer, SourcePeb->ProcessParameters->Environment, SourceEnvironment.Length);
		}
		if (SourcePeb->ProcessParameters->CurrentDirectory.DosPath.Length)
		{
			UNICODE_STRING_COPY_ALLOCATE(&DosPath, &SourcePeb->ProcessParameters->CurrentDirectory.DosPath);
		}
		//获取LADR
		PLDR_DATA_TABLE_ENTRY pLDR = (PLDR_DATA_TABLE_ENTRY)SourcePeb->Ldr->InLoadOrderModuleList.Flink;
		if (pLDR->BaseDllName.Length)
		{
			UNICODE_STRING_COPY_ALLOCATE(&BaseDllName, &pLDR->BaseDllName);

		}
		if (pLDR->FullDllName.Length)
		{
			UNICODE_STRING_COPY_ALLOCATE(&FullDllName, &pLDR->FullDllName);
		}
		PEB_IMAGEBASE = SourcePeb->ImageBaseAddress;
		SizeOfImage = pLDR->SizeOfImage;
		EntryPoint = pLDR->EntryPoint;
		DllBase = pLDR->DllBase;
		KeUnstackDetachProcess(&SourceAPC);
		{

			///---------------------------------------开始伪装-------------------------------------------------/// 
			//挂靠伪装进程
			KeStackAttachProcess(MaskEprocess, &MaskAPC);
			status = MmCopyVirtualMemory(MaskEprocess, MaskPeb, MaskEprocess, MaskPeb, 4, UserMode, &memSize);
			if (!NT_SUCCESS(status))
			{
				KeUnstackDetachProcess(&MaskAPC);
				goto FREEMEMORY;
			}
			status = MmCopyVirtualMemory(MaskEprocess, MaskPeb->ProcessParameters, MaskEprocess, MaskPeb->ProcessParameters, 4, UserMode, &memSize);
			if (!NT_SUCCESS(status))
			{
				KeUnstackDetachProcess(&MaskAPC);
				goto FREEMEMORY;
			}
			status = MmCopyVirtualMemory(MaskEprocess, MaskPeb, MaskEprocess, MaskPeb, 4, UserMode, &memSize);
			if (!NT_SUCCESS(status))
			{
				KeUnstackDetachProcess(&MaskAPC);
				goto FREEMEMORY;
			}
			status = MmCopyVirtualMemory(MaskEprocess, MaskPeb->Ldr, MaskEprocess, MaskPeb->Ldr, 4, UserMode, &memSize);
			if (!NT_SUCCESS(status))
			{
				KeUnstackDetachProcess(&MaskAPC);
				goto FREEMEMORY;
			}


			PUCHAR szBuffer = NULL;
			 
			SIZE_T AllocateSize = PAGE_SIZE * 2;
			//R3环境需要申请空间
			status = ZwAllocateVirtualMemory(NtCurrentProcess(), &szBuffer, 0, &AllocateSize, MEM_COMMIT, PAGE_READWRITE);
			if (!NT_SUCCESS(status))
			{
				KeUnstackDetachProcess(&MaskAPC);
				goto FREEMEMORY;
			}
			PUCHAR szTemp = szBuffer;
			if (ImagePathName.Length)
			{
				memcpy(szTemp, ImagePathName.Buffer, ImagePathName.Length);
				MaskPeb->ProcessParameters->ImagePathName.Buffer = szTemp;
				MaskPeb->ProcessParameters->ImagePathName.Length = ImagePathName.Length;
				MaskPeb->ProcessParameters->ImagePathName.MaximumLength = ImagePathName.MaximumLength;
				szTemp += ImagePathName.MaximumLength;
				ExFreePool(ImagePathName.Buffer);
			}
			if (CommandLine.Length)
			{

				memcpy(szTemp, CommandLine.Buffer, CommandLine.Length);
				MaskPeb->ProcessParameters->CommandLine.Buffer = szTemp;
				MaskPeb->ProcessParameters->CommandLine.Length = CommandLine.Length;
				MaskPeb->ProcessParameters->CommandLine.MaximumLength = CommandLine.MaximumLength;
				szTemp += CommandLine.MaximumLength;
				ExFreePool(CommandLine.Buffer);
			}
			else {
				szTemp += 8;
				MaskPeb->ProcessParameters->CommandLine.Buffer = szTemp;
				MaskPeb->ProcessParameters->CommandLine.Length = 0;
				MaskPeb->ProcessParameters->CommandLine.MaximumLength = 0;
			}
			if (WindowTitle.Length)
			{

				memcpy(szTemp, WindowTitle.Buffer, WindowTitle.Length);

				MaskPeb->ProcessParameters->WindowTitle.Buffer = szTemp;
				MaskPeb->ProcessParameters->WindowTitle.Length = WindowTitle.Length;
				MaskPeb->ProcessParameters->WindowTitle.MaximumLength = WindowTitle.MaximumLength;
				szTemp += WindowTitle.MaximumLength;
				ExFreePool(WindowTitle.Buffer);
			}
			else {
				szTemp += 8;
				MaskPeb->ProcessParameters->WindowTitle.Buffer = szTemp;
				MaskPeb->ProcessParameters->WindowTitle.Length = 0;
				MaskPeb->ProcessParameters->WindowTitle.MaximumLength = 0;
			}
			if (DosPath.Length)
			{
				memcpy(szTemp, DosPath.Buffer, DosPath.Length);
				MaskPeb->ProcessParameters->CurrentDirectory.DosPath.Buffer = szTemp;
				MaskPeb->ProcessParameters->CurrentDirectory.DosPath.Length = DosPath.Length;
				MaskPeb->ProcessParameters->CurrentDirectory.DosPath.MaximumLength = DosPath.MaximumLength;
				szTemp += DosPath.MaximumLength;
				ExFreePool(DosPath.Buffer);
			}
			if (SourceEnvironment.Length)
			{
				memcpy(szTemp, SourceEnvironment.Buffer, SourceEnvironment.Length);
				MaskPeb->ProcessParameters->Environment = szTemp;
				MaskPeb->ProcessParameters->EnvironmentSize = SourceEnvironment.Length;
				szTemp += SourceEnvironment.MaximumLength;
				ExFreePool(SourceEnvironment.Buffer);
			}



			//////处理LDR/////
			PLDR_DATA_TABLE_ENTRY MaskPLDR64 = (PLDR_DATA_TABLE_ENTRY)(MaskPeb->Ldr->InLoadOrderModuleList.Flink);
			if (BaseDllName.Buffer)
			{
				memcpy(szTemp, BaseDllName.Buffer, BaseDllName.Length);
				MaskPLDR64->BaseDllName.Buffer = szTemp;
				MaskPLDR64->BaseDllName.Length = BaseDllName.Length;
				MaskPLDR64->BaseDllName.MaximumLength = BaseDllName.MaximumLength;
				szTemp += BaseDllName.MaximumLength;
				ExFreePool(BaseDllName.Buffer);
			}
			if (FullDllName.Buffer)
			{
				memcpy(szTemp, FullDllName.Buffer, FullDllName.Length);
				MaskPLDR64->FullDllName.Length = FullDllName.Length;
				MaskPLDR64->FullDllName.MaximumLength = FullDllName.MaximumLength;
				MaskPLDR64->FullDllName.Buffer = szTemp;
				szTemp += FullDllName.MaximumLength;
				ExFreePool(FullDllName.Buffer);
			}
			MaskPeb->ImageBaseAddress = PEB_IMAGEBASE;
			MaskPLDR64->SizeOfImage = SizeOfImage;
			MaskPLDR64->EntryPoint = EntryPoint;
			MaskPLDR64->DllBase = DllBase;


			if (MaskPeb32)
			{
				NTSTATUS status = MmCopyVirtualMemory(MaskEprocess, MaskPeb32, MaskEprocess, MaskPeb32, 4, UserMode, &memSize);
				if (!NT_SUCCESS(status))
				{
					KeUnstackDetachProcess(&MaskAPC);
					goto END;
				}
				if (MaskPeb32->ProcessParameters)
				{
					PRTL_USER_PROCESS_PARAMETERS32  pProcessParamater = (PRTL_USER_PROCESS_PARAMETERS32)MaskPeb32->ProcessParameters;
					MmCopyVirtualMemory(MaskEprocess, pProcessParamater, MaskEprocess, pProcessParamater, 4, UserMode, &memSize);

					if (MaskPeb->ProcessParameters->ImagePathName.Length)
					{

						memcpy(szTemp, MaskPeb->ProcessParameters->ImagePathName.Buffer, MaskPeb->ProcessParameters->ImagePathName.Length);
						pProcessParamater->ImagePathName.Buffer = szTemp;
						pProcessParamater->ImagePathName.Length = MaskPeb->ProcessParameters->ImagePathName.Length;
						pProcessParamater->ImagePathName.MaximumLength = MaskPeb->ProcessParameters->ImagePathName.MaximumLength;
						szTemp += MaskPeb->ProcessParameters->ImagePathName.MaximumLength;
					}
					if (MaskPeb->ProcessParameters->CommandLine.Length)
					{

						memcpy(szTemp, MaskPeb->ProcessParameters->CommandLine.Buffer, MaskPeb->ProcessParameters->CommandLine.Length);
						pProcessParamater->CommandLine.Buffer = szTemp;
						pProcessParamater->CommandLine.Length = MaskPeb->ProcessParameters->CommandLine.Length;
						pProcessParamater->CommandLine.MaximumLength = MaskPeb->ProcessParameters->CommandLine.MaximumLength;
						szTemp += MaskPeb->ProcessParameters->CommandLine.MaximumLength;
					}
					else {
						szTemp += 4;
						pProcessParamater->CommandLine.Buffer = szTemp;
						pProcessParamater->CommandLine.Length = 0;
						pProcessParamater->CommandLine.MaximumLength = 0;
					}
					if (MaskPeb->ProcessParameters->WindowTitle.Length)
					{

						memcpy(szTemp, MaskPeb->ProcessParameters->WindowTitle.Buffer, MaskPeb->ProcessParameters->WindowTitle.Length);
						pProcessParamater->WindowTitle.Buffer = szTemp;
						pProcessParamater->WindowTitle.Length = MaskPeb->ProcessParameters->WindowTitle.Length;
						pProcessParamater->WindowTitle.MaximumLength = MaskPeb->ProcessParameters->WindowTitle.MaximumLength;
						szTemp += MaskPeb->ProcessParameters->WindowTitle.MaximumLength;
					}
					else {
						szTemp += 4;
						pProcessParamater->WindowTitle.Buffer = szTemp;
						pProcessParamater->WindowTitle.Length = 0;
						pProcessParamater->WindowTitle.MaximumLength = 0;
					}
					if (MaskPeb->ProcessParameters->CurrentDirectory.DosPath.Length)
					{
						memcpy(szTemp, MaskPeb->ProcessParameters->CurrentDirectory.DosPath.Buffer, MaskPeb->ProcessParameters->CurrentDirectory.DosPath.Length);
						pProcessParamater->CurrentDirectory.DosPath.Buffer = szTemp;
						pProcessParamater->CurrentDirectory.DosPath.Length = MaskPeb->ProcessParameters->CurrentDirectory.DosPath.Length;
						pProcessParamater->CurrentDirectory.DosPath.MaximumLength = MaskPeb->ProcessParameters->CurrentDirectory.DosPath.MaximumLength;
						szTemp += MaskPeb->ProcessParameters->CurrentDirectory.DosPath.MaximumLength;
					}
					memset(pProcessParamater->Environment, 0, pProcessParamater->EnvironmentSize);
					memcpy(pProcessParamater->Environment, MaskPeb->ProcessParameters->Environment, MaskPeb->ProcessParameters->EnvironmentSize);
					//复制环境变量
					//pProcessParamater->Environment = MaskPeb->ProcessParameters->Environment;
					pProcessParamater->EnvironmentSize = MaskPeb->ProcessParameters->EnvironmentSize;

				}
				status = MmCopyVirtualMemory(MaskEprocess, MaskPeb32->Ldr, MaskEprocess, MaskPeb32->Ldr, 4, UserMode, &memSize);
				if (!NT_SUCCESS(status))
				{
					KeUnstackDetachProcess(&MaskAPC);
					goto FREEMEMORY;
				}
				PPEB_LDR_DATA32  pLdr32 = (PPEB_LDR_DATA32)MaskPeb32->Ldr;
				status = MmCopyVirtualMemory(MaskEprocess, pLdr32, MaskEprocess, pLdr32, 4, UserMode, &memSize);
				if (!NT_SUCCESS(status))
				{
					KeUnstackDetachProcess(&MaskAPC);
					goto FREEMEMORY;
				}
				PLDR_DATA_TABLE_ENTRY32 MaskLDR32 = (PLDR_DATA_TABLE_ENTRY32)(pLdr32->InLoadOrderModuleList.Flink);

				if (MaskPLDR64->BaseDllName.Length)
				{
					memcpy(szTemp, MaskLDR32->BaseDllName.Buffer, MaskPLDR64->BaseDllName.Length);
					MaskLDR32->BaseDllName.Buffer = szTemp;
					MaskLDR32->BaseDllName.Length = MaskPLDR64->BaseDllName.Length;
					MaskLDR32->BaseDllName.MaximumLength = MaskPLDR64->BaseDllName.MaximumLength;
					szTemp += MaskPLDR64->BaseDllName.MaximumLength;
				}
				if (MaskPLDR64->FullDllName.Length)
				{
					memcpy(szTemp, MaskPLDR64->FullDllName.Buffer, MaskPLDR64->FullDllName.Length);
					MaskLDR32->FullDllName.Buffer = MaskPLDR64->FullDllName.Buffer;
					MaskLDR32->FullDllName.Length = MaskPLDR64->FullDllName.Length;
					MaskLDR32->FullDllName.MaximumLength = MaskPLDR64->FullDllName.MaximumLength;
					szTemp += MaskPLDR64->FullDllName.MaximumLength;
				}
				MaskPeb32->ImageBaseAddress = PEB_IMAGEBASE;
				MaskLDR32->SizeOfImage = MaskPLDR64->SizeOfImage;
				MaskLDR32->EntryPoint = MaskPLDR64->EntryPoint;
				MaskLDR32->DllBase = MaskPLDR64->DllBase;
			}
			KeUnstackDetachProcess(&MaskAPC);
		FREEMEMORY:;
			if (!NT_SUCCESS(status))
			{
				ExFreePool(ImagePathName.Buffer);
				if (CommandLine.Length)
				{
					ExFreePool(CommandLine.Buffer);
				}
				if (WindowTitle.Length)
				{
					ExFreePool(WindowTitle.Buffer);
				}
				ExFreePool(BaseDllName.Buffer);
				ExFreePool(FullDllName.Buffer);
			}
		}
	}
END:
	ObDereferenceObject(MaskEprocess);
	ObDereferenceObject(SourceEprocess);
	return STATUS_SUCCESS;

}




