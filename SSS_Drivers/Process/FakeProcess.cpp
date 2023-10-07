#pragma once
#include "FakeProcess.h"




namespace fuck_process {


	VOID UNICODE_STRING_COPY_ALLOCATE(PUNICODE_STRING dest, PUNICODE_STRING source) {

		dest->Buffer = (PWCH)imports::ex_allocate_pool(NonPagedPool, source->MaximumLength);
		Utils::kmemcpy(dest->Buffer, source->Buffer, source->Length);
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
		UNICODE_STRING			ImagePathName = { 0 };
		UNICODE_STRING			CommandLine = { 0 };
		UNICODE_STRING			WindowTitle = { 0 };
		UNICODE_STRING			BaseDllName = { 0 };
		UNICODE_STRING			FullDllName = { 0 };
		UNICODE_STRING			DosPath = { 0 };
		UNICODE_STRING			SourceEnvironment = { 0 };

		while (1)
		{



			//要伪装的进程
			MaskEprocess = Utils::lookup_process_by_id((HANDLE)pid);
			if (!MaskEprocess) return status;
 

			//被伪装的目标进程
			SourceEprocess = Utils::lookup_process_by_id((HANDLE)fakePid);  
			if (!SourceEprocess) return status;
 
			//PPEB32 isMask32Bit = PsGetProcessWow64Process(MaskEprocess);
			//PPEB32 isSource32Bit = PsGetProcessWow64Process(SourceEprocess);

			//if ((!isMask32Bit) != (!isSource32Bit))
			//{
			//	status = STATUS_UNSUCCESSFUL;
			//	break;
			//}


			PUCHAR nameBuffer = (PUCHAR)imports::ex_allocate_pool(NonPagedPool, USN_PAGE_SIZE);
			PUCHAR szNameTemp = nameBuffer;
			Utils::kmemset(nameBuffer, 0, USN_PAGE_SIZE);
			USHORT imageNameOffset = *(PUSHORT)(imports::imported.ps_get_process_image_file_name + 3);
			//修改名字ImageFileName
			{

				PCHAR szMaskImageName = NULL;
				PCHAR szSourceImageName = NULL;
				szMaskImageName = (PCHAR)MaskEprocess + imageNameOffset;
				szSourceImageName = (PCHAR)SourceEprocess + imageNameOffset;
				Utils::kmemcpy(szMaskImageName, szSourceImageName, 15);
			}

			//修改Eprocess.ImagePathHash
			{

				ULONG ImagePathHashOffset = imageNameOffset + 0x4c;
				ULONG SourceImagePathHash = *(PULONG)((PUCHAR)SourceEprocess + ImagePathHashOffset);

				*(PULONG)((PUCHAR)MaskEprocess + ImagePathHashOffset) = SourceImagePathHash;
			}

			//修改Eprocess.BaseAddressOffset
			{
				ULONG SectionBaseAddressOffset = *(PULONG)(imports::imported.ps_get_process_section_base_address + 3);
				ULONG SourceBaseAddress = *(PULONG)((PUCHAR)SourceEprocess + SectionBaseAddressOffset);
				*(PULONG)((PUCHAR)MaskEprocess + SectionBaseAddressOffset) = SourceBaseAddress;

			}

			//+0x468 SeAuditProcessCreationInfo : _SE_AUDIT_PROCESS_CREATION_INFO
			{

				ULONG_PTR AuditOffset = 0;

				PUNICODE_STRING sourceName = NULL;
				//判断成员偏移
				switch (Utils::InitOsVersion().dwBuildNumber)
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
					AuditOffset = (ULONG_PTR)imageNameOffset + 0x18;

				}
				POBJECT_NAME_INFORMATION pSourceNameInfo = (POBJECT_NAME_INFORMATION) * (PULONG_PTR)((PUCHAR)SourceEprocess + AuditOffset);
				POBJECT_NAME_INFORMATION pMaskNameInfo = (POBJECT_NAME_INFORMATION) * (PULONG_PTR)((PUCHAR)MaskEprocess + AuditOffset);

				Utils::kmemcpy(szNameTemp, pSourceNameInfo->Name.Buffer, pSourceNameInfo->Name.Length);
				pMaskNameInfo->Name.Buffer = (PWCH)szNameTemp;
				pMaskNameInfo->Name.MaximumLength = pSourceNameInfo->Name.MaximumLength;
				pMaskNameInfo->Name.Length = pSourceNameInfo->Name.Length;
				szNameTemp += pSourceNameInfo->Name.MaximumLength;

			}

			//Eprocess _SECTION_OBJECT    FsContext2 
			{
				PFILE_OBJECT MaskFile = NULL;
				PFILE_OBJECT SourceFile = NULL;
				//获取文件对象
				status = imports::ps_reference_process_file_pointer(MaskEprocess, (PVOID*)&MaskFile);
				if (!NT_SUCCESS(status))
				{
					break;
				}
				status = imports::ps_reference_process_file_pointer(SourceEprocess, (PVOID*)&SourceFile);
				if (!NT_SUCCESS(status))
				{
					imports::obf_dereference_object(MaskFile);
					break;
				}

				Utils::kmemcpy(szNameTemp, SourceFile->FileName.Buffer, SourceFile->FileName.Length);
				MaskFile->FileName.Buffer = (PWCH)szNameTemp;
				MaskFile->FileName.MaximumLength = SourceFile->FileName.MaximumLength;
				MaskFile->FileName.Length = SourceFile->FileName.Length;
				szNameTemp += SourceFile->FileName.MaximumLength;

				//修改文件路径2
				ULONG_PTR MaskFsContext2 = (ULONG_PTR)MaskFile->FsContext2;
				ULONG_PTR SourceFsContext2 = (ULONG_PTR)SourceFile->FsContext2;
				if (imports::mm_is_address_valid((PVOID)SourceFsContext2))
				{
					PUNICODE_STRING SourceContextName = (PUNICODE_STRING)(SourceFsContext2 + 0x10);
					Utils::kmemcpy(szNameTemp, SourceContextName->Buffer, SourceContextName->Length);
					PUNICODE_STRING MaskContextName = (PUNICODE_STRING)(MaskFsContext2 + 0x10);

					MaskContextName->Buffer = (PWCH)szNameTemp;
					MaskContextName->MaximumLength = SourceContextName->MaximumLength;
					MaskContextName->Length = SourceContextName->Length;

					szNameTemp += SourceContextName->MaximumLength;

					MaskFile->DeviceObject = SourceFile->DeviceObject;
					MaskFile->Vpb = SourceFile->Vpb;
				}

				imports::obf_dereference_object(MaskFile);
				imports::obf_dereference_object(SourceFile);

			}



			//只有win10 有   ImageFilePointer 
			if (Utils::InitOsVersion().dwMajorVersion > 9) {
				//获取成员偏移
				ULONG uFileOBJECTOffset = imageNameOffset - 8;
				//获取文件对象
				//PFILE_OBJECT MaskFile = (PFILE_OBJECT) * (PULONG_PTR)((PUCHAR)MaskEprocess + uFileOBJECTOffset);
				PFILE_OBJECT SourceFile = (PFILE_OBJECT) * (PULONG_PTR)((PUCHAR)SourceEprocess + uFileOBJECTOffset);
				*(PULONG_PTR)((PUCHAR)MaskEprocess + uFileOBJECTOffset) = (ULONGLONG)SourceFile;
			}


			//EPROCESS PsGetProcessInheritedFromUniqueProcessId
			{
				//获取父进程pid 偏移
				ULONG ParentIdOffset = functions::GetFunctionVariableOffset(skCrypt(L"PsGetProcessInheritedFromUniqueProcessId"), 3);
				ULONG parentPid = *(PULONG_PTR)((PUCHAR)SourceEprocess + ParentIdOffset);
				*(PULONG_PTR)((PUCHAR)MaskEprocess + ParentIdOffset) = parentPid;
			}
			//EPROCESS   PsIsProtectedProcess
			{
				ULONG isProtectOffset = functions::GetFunctionVariableOffset(skCrypt(L"PsIsProtectedProcess"), 2);
				*(PULONG_PTR)((PUCHAR)MaskEprocess + isProtectOffset) = 0xff;
			}

			//EPROCESS   PsGetProcessCreateTimeQuadPart 
			{
				ULONG TimeQuadPartOffset = functions::GetFunctionVariableOffset(skCrypt(L"PsGetProcessCreateTimeQuadPart"), 3);
				LONGLONG CreateTime = *(PULONGLONG)((PUCHAR)SourceEprocess + TimeQuadPartOffset);
				*(PULONGLONG)((PUCHAR)MaskEprocess + TimeQuadPartOffset) = CreateTime;
			}

			//EPROCESS Token  _SID_AND_ATTRIBUTES* UserAndGroups; 
			{

				ULONG TokenOffset = 0;
				ULONGLONG MaskToken = (ULONGLONG)imports::ps_reference_primary_token(MaskEprocess);
				ULONGLONG SourceToken = (ULONGLONG)imports::ps_reference_primary_token(SourceEprocess);
				if (Utils::InitOsVersion().dwBuildNumber <= 7601)
				{
					TokenOffset = 0x90;
				}
				else {
					TokenOffset = 0x98;
				}
				ULONGLONG MaskUserAndGroups = *(PULONGLONG)(MaskToken + TokenOffset);
				ULONGLONG SourceUserAndGroups = *(PULONGLONG)(SourceToken + TokenOffset);
				if (!MaskUserAndGroups || !SourceUserAndGroups) {
					imports::obf_dereference_object((PVOID)MaskToken);
					imports::obf_dereference_object((PVOID)SourceToken);
					break;
				}
				ULONGLONG  MaskSID = *(PULONGLONG)MaskUserAndGroups;
				ULONGLONG  SourceSID = *(PULONGLONG)SourceUserAndGroups;
				if (MaskSID && SourceSID)
				{
					Utils::kmemcpy((PVOID)MaskSID, (PVOID)SourceSID, 0xC);
				}
				imports::obf_dereference_object((PVOID)MaskToken);
				imports::obf_dereference_object((PVOID)SourceToken);
			}



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
			MaskPeb = (PPEB64)imports::ps_get_process_peb(MaskEprocess);
			MaskPeb32 = (PPEB32)imports::ps_get_process_wow64_process(MaskEprocess);
			SourcePeb = (PPEB64)imports::ps_get_process_peb(SourceEprocess);

			//EPROCESS PEB  PEB->ProcessParameters    PEB->LDR
			{
				if (!MaskPeb || !SourcePeb)
				{
					break;
				}
				//复制原始进程特征
				imports::ke_stack_attach_process(SourceEprocess, &SourceAPC);
				status = imports::mm_copy_virtual_memory(SourceEprocess, SourcePeb, SourceEprocess, SourcePeb, 4, UserMode, &memSize);
				if (!NT_SUCCESS(status))
				{
					imports::ke_unstack_detach_process(&SourceAPC);
					break;
				}
				status = imports::mm_copy_virtual_memory(SourceEprocess, SourcePeb->ProcessParameters, SourceEprocess, SourcePeb->ProcessParameters, 4, UserMode, &memSize);
				if (!NT_SUCCESS(status))
				{
					imports::ke_unstack_detach_process(&SourceAPC);
					break;
				}
				status = imports::mm_copy_virtual_memory(SourceEprocess, SourcePeb->Ldr, SourceEprocess, SourcePeb->Ldr, 4, UserMode, &memSize);
				if (!NT_SUCCESS(status))
				{
					imports::ke_unstack_detach_process(&SourceAPC);
					break;
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
					SourceEnvironment.Buffer = (PWCH)imports::ex_allocate_pool(NonPagedPool, SourceEnvironment.MaximumLength);
					memset(SourceEnvironment.Buffer, 0, SourceEnvironment.MaximumLength);
					Utils::kmemcpy(SourceEnvironment.Buffer, SourcePeb->ProcessParameters->Environment, SourceEnvironment.Length);
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
				EntryPoint = (ULONG64)pLDR->EntryPoint;
				DllBase = pLDR->DllBase;
				imports::ke_unstack_detach_process(&SourceAPC);
				{

					///---------------------------------------开始伪装-------------------------------------------------/// 
					//挂靠伪装进程
					imports::ke_stack_attach_process(MaskEprocess, &MaskAPC);
					status = imports::mm_copy_virtual_memory(MaskEprocess, MaskPeb, MaskEprocess, MaskPeb, 4, UserMode, &memSize);
					if (!NT_SUCCESS(status))
					{
						imports::ke_unstack_detach_process(&MaskAPC);
						break;
					}
					status = imports::mm_copy_virtual_memory(MaskEprocess, MaskPeb->ProcessParameters, MaskEprocess, MaskPeb->ProcessParameters, 4, UserMode, &memSize);
					if (!NT_SUCCESS(status))
					{
						imports::ke_unstack_detach_process(&MaskAPC);
						break;
					}
					status = imports::mm_copy_virtual_memory(MaskEprocess, MaskPeb, MaskEprocess, MaskPeb, 4, UserMode, &memSize);
					if (!NT_SUCCESS(status))
					{
						imports::ke_unstack_detach_process(&MaskAPC);
						break;
					}
					status = imports::mm_copy_virtual_memory(MaskEprocess, MaskPeb->Ldr, MaskEprocess, MaskPeb->Ldr, 4, UserMode, &memSize);
					if (!NT_SUCCESS(status))
					{
						imports::ke_unstack_detach_process(&MaskAPC);
						break;
					}


					PUCHAR szBuffer = NULL;

					SIZE_T AllocateSize = PAGE_SIZE * 2;
					//R3环境需要申请空间
					status = imports::zw_allocate_virtual_memory(NtCurrentProcess(), (PVOID*)&szBuffer, 0, &AllocateSize, MEM_COMMIT, PAGE_READWRITE);
					if (!NT_SUCCESS(status))
					{
						imports::ke_unstack_detach_process(&MaskAPC);
						break;
					}
					PUCHAR szTemp = szBuffer;
					if (ImagePathName.Length)
					{
						Utils::kmemcpy(szTemp, ImagePathName.Buffer, ImagePathName.Length);
						MaskPeb->ProcessParameters->ImagePathName.Buffer = (PWCH)szTemp;
						MaskPeb->ProcessParameters->ImagePathName.Length = ImagePathName.Length;
						MaskPeb->ProcessParameters->ImagePathName.MaximumLength = ImagePathName.MaximumLength;
						szTemp += ImagePathName.MaximumLength;
						imports::ex_free_pool_with_tag(ImagePathName.Buffer, 0);
					}
					if (CommandLine.Length)
					{

						Utils::kmemcpy(szTemp, CommandLine.Buffer, CommandLine.Length);
						MaskPeb->ProcessParameters->CommandLine.Buffer = (PWCH)szTemp;
						MaskPeb->ProcessParameters->CommandLine.Length = CommandLine.Length;
						MaskPeb->ProcessParameters->CommandLine.MaximumLength = CommandLine.MaximumLength;
						szTemp += CommandLine.MaximumLength;
						imports::ex_free_pool_with_tag(CommandLine.Buffer, 0);
					}
					else {
						szTemp += 8;
						MaskPeb->ProcessParameters->CommandLine.Buffer = (PWCH)szTemp;
						MaskPeb->ProcessParameters->CommandLine.Length = 0;
						MaskPeb->ProcessParameters->CommandLine.MaximumLength = 0;
					}
					if (WindowTitle.Length)
					{

						Utils::kmemcpy(szTemp, WindowTitle.Buffer, WindowTitle.Length);

						MaskPeb->ProcessParameters->WindowTitle.Buffer = (PWCH)szTemp;
						MaskPeb->ProcessParameters->WindowTitle.Length = WindowTitle.Length;
						MaskPeb->ProcessParameters->WindowTitle.MaximumLength = WindowTitle.MaximumLength;
						szTemp += WindowTitle.MaximumLength;
						imports::ex_free_pool_with_tag(WindowTitle.Buffer, 0);
					}
					else {
						szTemp += 8;
						MaskPeb->ProcessParameters->WindowTitle.Buffer = (PWCH)szTemp;
						MaskPeb->ProcessParameters->WindowTitle.Length = 0;
						MaskPeb->ProcessParameters->WindowTitle.MaximumLength = 0;
					}
					if (DosPath.Length)
					{
						Utils::kmemcpy(szTemp, DosPath.Buffer, DosPath.Length);
						MaskPeb->ProcessParameters->CurrentDirectory.DosPath.Buffer = (PWCH)szTemp;
						MaskPeb->ProcessParameters->CurrentDirectory.DosPath.Length = DosPath.Length;
						MaskPeb->ProcessParameters->CurrentDirectory.DosPath.MaximumLength = DosPath.MaximumLength;
						szTemp += DosPath.MaximumLength;

						imports::ex_free_pool_with_tag(DosPath.Buffer, 0);
					}
					if (SourceEnvironment.Length)
					{
						Utils::kmemcpy(szTemp, SourceEnvironment.Buffer, SourceEnvironment.Length);
						MaskPeb->ProcessParameters->Environment = (PWCH)szTemp;
						MaskPeb->ProcessParameters->EnvironmentSize = SourceEnvironment.Length;
						szTemp += SourceEnvironment.MaximumLength;
						imports::ex_free_pool_with_tag(SourceEnvironment.Buffer, 0);

					}



					//////处理LDR/////
					PLDR_DATA_TABLE_ENTRY MaskPLDR64 = (PLDR_DATA_TABLE_ENTRY)(MaskPeb->Ldr->InLoadOrderModuleList.Flink);
					if (BaseDllName.Buffer)
					{
						Utils::kmemcpy(szTemp, BaseDllName.Buffer, BaseDllName.Length);
						MaskPLDR64->BaseDllName.Buffer = (PWCH)szTemp;
						MaskPLDR64->BaseDllName.Length = BaseDllName.Length;
						MaskPLDR64->BaseDllName.MaximumLength = BaseDllName.MaximumLength;
						szTemp += BaseDllName.MaximumLength;
						imports::ex_free_pool_with_tag(BaseDllName.Buffer, 0);

					}
					if (FullDllName.Buffer)
					{
						Utils::kmemcpy(szTemp, FullDllName.Buffer, FullDllName.Length);
						MaskPLDR64->FullDllName.Length = FullDllName.Length;
						MaskPLDR64->FullDllName.MaximumLength = FullDllName.MaximumLength;
						MaskPLDR64->FullDllName.Buffer = (PWCH)szTemp;
						szTemp += FullDllName.MaximumLength;
						imports::ex_free_pool_with_tag(FullDllName.Buffer, 0);

					}
					MaskPeb->ImageBaseAddress = PEB_IMAGEBASE;
					MaskPLDR64->SizeOfImage = SizeOfImage;
					MaskPLDR64->EntryPoint = (PVOID)EntryPoint;
					MaskPLDR64->DllBase = DllBase;


					if (MaskPeb32)
					{
						NTSTATUS status = imports::mm_copy_virtual_memory(MaskEprocess, MaskPeb32, MaskEprocess, MaskPeb32, 4, UserMode, &memSize);
						if (!NT_SUCCESS(status))
						{
							imports::ke_unstack_detach_process(&MaskAPC);
							break;
						}
						if (MaskPeb32->ProcessParameters)
						{
							PRTL_USER_PROCESS_PARAMETERS32  pProcessParamater = (PRTL_USER_PROCESS_PARAMETERS32)MaskPeb32->ProcessParameters;
							imports::mm_copy_virtual_memory(MaskEprocess, pProcessParamater, MaskEprocess, pProcessParamater, 4, UserMode, &memSize);

							if (MaskPeb->ProcessParameters->ImagePathName.Length)
							{

								Utils::kmemcpy(szTemp, MaskPeb->ProcessParameters->ImagePathName.Buffer, MaskPeb->ProcessParameters->ImagePathName.Length);
								pProcessParamater->ImagePathName.Buffer = (ULONG)szTemp;
								pProcessParamater->ImagePathName.Length = MaskPeb->ProcessParameters->ImagePathName.Length;
								pProcessParamater->ImagePathName.MaximumLength = MaskPeb->ProcessParameters->ImagePathName.MaximumLength;
								szTemp += MaskPeb->ProcessParameters->ImagePathName.MaximumLength;
							}
							if (MaskPeb->ProcessParameters->CommandLine.Length)
							{

								Utils::kmemcpy(szTemp, MaskPeb->ProcessParameters->CommandLine.Buffer, MaskPeb->ProcessParameters->CommandLine.Length);
								pProcessParamater->CommandLine.Buffer = (ULONG)szTemp;
								pProcessParamater->CommandLine.Length = MaskPeb->ProcessParameters->CommandLine.Length;
								pProcessParamater->CommandLine.MaximumLength = MaskPeb->ProcessParameters->CommandLine.MaximumLength;
								szTemp += MaskPeb->ProcessParameters->CommandLine.MaximumLength;
							}
							else {
								szTemp += 4;
								pProcessParamater->CommandLine.Buffer = (ULONG)szTemp;
								pProcessParamater->CommandLine.Length = 0;
								pProcessParamater->CommandLine.MaximumLength = 0;
							}
							if (MaskPeb->ProcessParameters->WindowTitle.Length)
							{

								Utils::kmemcpy(szTemp, MaskPeb->ProcessParameters->WindowTitle.Buffer, MaskPeb->ProcessParameters->WindowTitle.Length);
								pProcessParamater->WindowTitle.Buffer = (ULONG)szTemp;
								pProcessParamater->WindowTitle.Length = MaskPeb->ProcessParameters->WindowTitle.Length;
								pProcessParamater->WindowTitle.MaximumLength = MaskPeb->ProcessParameters->WindowTitle.MaximumLength;
								szTemp += MaskPeb->ProcessParameters->WindowTitle.MaximumLength;
							}
							else {
								szTemp += 4;
								pProcessParamater->WindowTitle.Buffer = (ULONG)szTemp;
								pProcessParamater->WindowTitle.Length = 0;
								pProcessParamater->WindowTitle.MaximumLength = 0;
							}
							if (MaskPeb->ProcessParameters->CurrentDirectory.DosPath.Length)
							{
								Utils::kmemcpy(szTemp, MaskPeb->ProcessParameters->CurrentDirectory.DosPath.Buffer, MaskPeb->ProcessParameters->CurrentDirectory.DosPath.Length);
								pProcessParamater->CurrentDirectory.DosPath.Buffer = (ULONG)szTemp;
								pProcessParamater->CurrentDirectory.DosPath.Length = MaskPeb->ProcessParameters->CurrentDirectory.DosPath.Length;
								pProcessParamater->CurrentDirectory.DosPath.MaximumLength = MaskPeb->ProcessParameters->CurrentDirectory.DosPath.MaximumLength;
								szTemp += MaskPeb->ProcessParameters->CurrentDirectory.DosPath.MaximumLength;
							}
							Utils::kmemset((PVOID)pProcessParamater->Environment, 0, pProcessParamater->EnvironmentSize);
							Utils::kmemcpy((PVOID)pProcessParamater->Environment, MaskPeb->ProcessParameters->Environment, MaskPeb->ProcessParameters->EnvironmentSize);
							//复制环境变量
							//pProcessParamater->Environment = MaskPeb->ProcessParameters->Environment;
							pProcessParamater->EnvironmentSize = MaskPeb->ProcessParameters->EnvironmentSize;

						}
						status = imports::mm_copy_virtual_memory(MaskEprocess, (PVOID)MaskPeb32->Ldr, MaskEprocess, (PVOID)MaskPeb32->Ldr, 4, UserMode, &memSize);
						if (!NT_SUCCESS(status))
						{
							imports::ke_unstack_detach_process(&MaskAPC);
							break;;
						}
						PPEB_LDR_DATA32  pLdr32 = (PPEB_LDR_DATA32)MaskPeb32->Ldr;
						status = imports::mm_copy_virtual_memory(MaskEprocess, pLdr32, MaskEprocess, pLdr32, 4, UserMode, &memSize);
						if (!NT_SUCCESS(status))
						{
							imports::ke_unstack_detach_process(&MaskAPC);
							break;;
						}
						PLDR_DATA_TABLE_ENTRY32 MaskLDR32 = (PLDR_DATA_TABLE_ENTRY32)(pLdr32->InLoadOrderModuleList.Flink);

						if (MaskPLDR64->BaseDllName.Length)
						{
							Utils::kmemcpy(szTemp, (PVOID)MaskPLDR64->BaseDllName.Buffer, MaskPLDR64->BaseDllName.Length);
							MaskLDR32->BaseDllName.Buffer = (ULONG)szTemp;
							MaskLDR32->BaseDllName.Length = MaskPLDR64->BaseDllName.Length;
							MaskLDR32->BaseDllName.MaximumLength = MaskPLDR64->BaseDllName.MaximumLength;
							szTemp += MaskPLDR64->BaseDllName.MaximumLength;
						}
						if (MaskPLDR64->FullDllName.Length)
						{
							Utils::kmemcpy(szTemp, MaskPLDR64->FullDllName.Buffer, MaskPLDR64->FullDllName.Length);
							MaskLDR32->FullDllName.Buffer = (ULONG)szTemp;
							MaskLDR32->FullDllName.Length = MaskPLDR64->FullDllName.Length;
							MaskLDR32->FullDllName.MaximumLength = MaskPLDR64->FullDllName.MaximumLength;
							szTemp += MaskPLDR64->FullDllName.MaximumLength;
						}
						MaskPeb32->ImageBaseAddress = PEB_IMAGEBASE;
						MaskLDR32->SizeOfImage = MaskPLDR64->SizeOfImage;
						MaskLDR32->EntryPoint = (ULONG)MaskPLDR64->EntryPoint;
						MaskLDR32->DllBase = MaskPLDR64->DllBase;
					}
					imports::ke_unstack_detach_process(&MaskAPC);
				}
			}
			break;
		}
		if (!NT_SUCCESS(status))
		{
			if (ImagePathName.Buffer)
			{
				imports::ex_free_pool_with_tag(ImagePathName.Buffer, 0);
			}
			if (CommandLine.Buffer)
			{
				imports::ex_free_pool_with_tag(CommandLine.Buffer, 0);
			}
			if (WindowTitle.Buffer)
			{
				imports::ex_free_pool_with_tag(WindowTitle.Buffer, 0);
			}
			if (BaseDllName.Buffer)
			{
				imports::ex_free_pool_with_tag(BaseDllName.Buffer, 0);
			}
			if (FullDllName.Buffer)
			{
				imports::ex_free_pool_with_tag(FullDllName.Buffer, 0);
			}
			if (SourceEnvironment.Buffer)
			{
				imports::ex_free_pool_with_tag(SourceEnvironment.Buffer, 0);
			}
		}
 

		return STATUS_SUCCESS;

	}

	NTSTATUS RemoveProcessProtect(ULONG_PTR pid, BOOLEAN isProtect)
	{
		NTSTATUS status = STATUS_UNSUCCESSFUL;
		PEPROCESS TargetEprocess = NULL;
		//要解除保护的进程
		TargetEprocess = Utils::lookup_process_by_id((HANDLE)pid);
		if (!TargetEprocess) return status;
 
		ULONG isProtectOffset = functions::GetFunctionVariableOffset(skCrypt(L"PsIsProtectedProcess"), 2);
		if (!isProtectOffset)
		{
			return STATUS_UNSUCCESSFUL;
		}
		if (isProtect)
		{
			*(PULONG_PTR)((PUCHAR)TargetEprocess + isProtectOffset) = 0xff;
		}
		else
		{
			*(PULONG_PTR)((PUCHAR)TargetEprocess + isProtectOffset) = 0;
		}
 
		status = STATUS_SUCCESS;

		return status;
	}



}




