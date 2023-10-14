#pragma once
#include "FakeProcess.h"
#include "../PatternSearch/PatternSearch.h"



namespace fuck_process {


	VOID UNICODE_STRING_COPY_ALLOCATE(PUNICODE_STRING dest, PUNICODE_STRING source) {

		dest->Buffer = (PWCH)imports::ex_allocate_pool(NonPagedPool, source->MaximumLength);
		Utils::kmemcpy(dest->Buffer, source->Buffer, source->Length);
		dest->MaximumLength = source->MaximumLength;
		dest->Length = source->Length;
	}

	void GET_PEB_DATA(PEPROCESS pEprocess, BOOLEAN IS_WOW64,PVOID  LDR_DATA, PVOID PARAMETERS,PVOID  TABLE_ENTRY,PULONG64 pPeb_ldr_addr,PULONG64 pParamater) {
	 
		ULONG peb_offset[20] = { 0 }; 
		UCHAR  idx_len = 0;
		UCHAR idx_peb_ImageBaseAddress = 1;
		UCHAR idx_peb_ldr = 2;
		UCHAR idx_peb_ProcessParameters = 3;
		ULONG PEB_LDR_DATA_SIZE = 4;
		ULONG LDR_DATA_TABLE_ENTRY_SIZE = 5;
		ULONG RTL_USER_PROCESS_PARAMETERS_SIZE =6; 
		ULONGLONG(*read_ptr)(PEPROCESS process, ULONGLONG address) = 0;
		ULONG64 PEB = 0;
		if (IS_WOW64)
		{ 
			PEB =(ULONG64) imports::ps_get_process_wow64_process(pEprocess);
			*(ULONGLONG*)&read_ptr = (ULONGLONG)patternSearch::read_i32;
				peb_offset[idx_peb_ImageBaseAddress] = 0x8,
				peb_offset[idx_peb_ldr] = 0xc,
				peb_offset[idx_peb_ProcessParameters] = 0x10;
				peb_offset[PEB_LDR_DATA_SIZE] = sizeof(PEB_LDR_DATA32);
				peb_offset[LDR_DATA_TABLE_ENTRY_SIZE] = sizeof(LDR_DATA_TABLE_ENTRY32);
				peb_offset[RTL_USER_PROCESS_PARAMETERS_SIZE] = sizeof(RTL_USER_PROCESS_PARAMETERS32);
		}
		else
		{
			PEB = (ULONG64)imports::ps_get_process_peb(pEprocess);
			*(ULONGLONG*)&read_ptr = (ULONGLONG)patternSearch::read_i64;
				peb_offset[idx_len] = 0x8,
				peb_offset[idx_peb_ImageBaseAddress] = 0x10,
				peb_offset[idx_peb_ldr] = 0x18,
				peb_offset[idx_peb_ProcessParameters] = 0x20;
				peb_offset[PEB_LDR_DATA_SIZE] = sizeof(PEB_LDR_DATA64);
				peb_offset[LDR_DATA_TABLE_ENTRY_SIZE] = sizeof(LDR_DATA_TABLE_ENTRY);
				peb_offset[RTL_USER_PROCESS_PARAMETERS_SIZE] = sizeof(RTL_USER_PROCESS_PARAMETERS);
				
		} 
		ULONG64 ImageBaseAddress= read_ptr(pEprocess, PEB + peb_offset[idx_peb_ImageBaseAddress]);
		ULONG64 peb_ldr_addr= read_ptr(pEprocess, PEB + peb_offset[idx_peb_ldr]);

		MiMemory::MiReadProcessMemory(pEprocess, (PVOID)peb_ldr_addr, LDR_DATA, peb_offset[PEB_LDR_DATA_SIZE]);

		ULONG64 peb_ldr_Module_First = 0;
		if (IS_WOW64)
		{
			peb_ldr_Module_First= ((PPEB_LDR_DATA32)LDR_DATA)->InLoadOrderModuleList.Flink;
		}
		else
		{
			peb_ldr_Module_First = ((PPEB_LDR_DATA64)LDR_DATA)->InLoadOrderModuleList.Flink;
		}
		//   +0x010 InLoadOrderModuleList : _LIST_ENTRY [ 0x00000200`4d8726d0 - 0x00000200`51ee0de0 ]
		*pPeb_ldr_addr = peb_ldr_Module_First;
	
		ULONG64 buffer_addr = patternSearch::read_i64(pEprocess, peb_ldr_Module_First + 0x50);

		MiMemory::MiReadProcessMemory(pEprocess, (PVOID)peb_ldr_Module_First, TABLE_ENTRY, peb_offset[LDR_DATA_TABLE_ENTRY_SIZE]);

		ULONG64 peb_Parameters = read_ptr(pEprocess, PEB + peb_offset[idx_peb_ProcessParameters]);
		*pParamater = peb_Parameters;
		MiMemory::MiReadProcessMemory(pEprocess, (PVOID)peb_Parameters, PARAMETERS, peb_offset[RTL_USER_PROCESS_PARAMETERS_SIZE]);
	}

	VOID FAKE_PEB(PEPROCESS MaskEprocess,PEPROCESS SourceEprocess) {
		
		ULONG64 mask_paramater_addr = 0;
		ULONG64 mask_peb_ldr_addr = 0;
		PEB_LDR_DATA64 mask_peb_data = { 0 };
		LDR_DATA_TABLE_ENTRY mask_table_entry = { 0 };
		RTL_USER_PROCESS_PARAMETERS mask_paramaters = { 0 };
		GET_PEB_DATA(MaskEprocess, FALSE, &mask_peb_data, &mask_paramaters, &mask_table_entry,&mask_peb_ldr_addr,&mask_paramater_addr);



		ULONG64 source_paramater_addr = 0;
		ULONG64 source_peb_ldr_addr = 0;
		PEB_LDR_DATA64 source_peb_data = { 0 };
		LDR_DATA_TABLE_ENTRY source_table_entry = { 0 };
		RTL_USER_PROCESS_PARAMETERS source_paramaters = { 0 };
		GET_PEB_DATA(SourceEprocess, FALSE, &source_peb_data, &source_paramaters, &source_table_entry,&source_peb_ldr_addr,&source_paramater_addr);
		//DllBase
 
		mask_table_entry.BaseDllName.Length = source_table_entry.BaseDllName.Length;
		mask_table_entry.BaseDllName.MaximumLength = source_table_entry.BaseDllName.MaximumLength;
		mask_table_entry.OriginalBase = source_table_entry.OriginalBase;
		mask_table_entry.BaseNameHashValue = source_table_entry.BaseNameHashValue;
		mask_table_entry.EntryPoint = source_table_entry.EntryPoint;
		mask_table_entry.DllBase = source_table_entry.DllBase;
		mask_table_entry.SizeOfImage = source_table_entry.SizeOfImage;
		mask_table_entry.FullDllName.Length = source_table_entry.FullDllName.Length;
		mask_table_entry.FullDllName.MaximumLength = source_table_entry.FullDllName.MaximumLength;
		mask_table_entry.LoadTime = source_table_entry.LoadTime;
		char empty[0x200] = { 0 };
		MiMemory::MiWriteProcessMemory(MaskEprocess,(PVOID)mask_peb_ldr_addr, &mask_table_entry, sizeof(LDR_DATA_TABLE_ENTRY));
		char nameTemp[0x200] = { 0 };

		ULONG64 buffer_addr = patternSearch::read_i64(SourceEprocess, source_peb_ldr_addr + 0x50);

		MiMemory::MiReadProcessMemory(SourceEprocess, (PVOID)buffer_addr, nameTemp, source_table_entry.FullDllName.MaximumLength);
		ULONG64 mask_buffer= patternSearch::read_i64(MaskEprocess, mask_peb_ldr_addr + 0x50);
		ULONG64 FullDllName_addr = mask_buffer;
		//先清空自己
		MiMemory::MiWriteProcessMemory(MaskEprocess, (PVOID)mask_buffer, empty, mask_table_entry.FullDllName.MaximumLength);
		//写入复制数据
		MiMemory::MiWriteProcessMemory(MaskEprocess,(PVOID)mask_buffer, nameTemp, source_table_entry.FullDllName.MaximumLength);

		ULONG64 BaseDllName_addr=  patternSearch::read_i64(SourceEprocess, source_peb_ldr_addr + 0x60); 
		USHORT nameOffset = BaseDllName_addr - buffer_addr;
		patternSearch::write_i64(MaskEprocess, mask_peb_ldr_addr + 0x60, mask_buffer + nameOffset);


		ULONG WindowTitle_MaximumLength = mask_paramaters.WindowTitle.MaximumLength;
		MiMemory::MiWriteProcessMemory(MaskEprocess, mask_paramaters.CurrentDirectory.DosPath.Buffer, empty, mask_paramaters.CurrentDirectory.DosPath.MaximumLength);
		mask_paramaters.CommandLine.Length = source_table_entry.FullDllName.Length;
		mask_paramaters.CommandLine.MaximumLength = source_table_entry.FullDllName.MaximumLength;

	 


		mask_paramaters.WindowTitle.Length = source_table_entry.FullDllName.Length;
		mask_paramaters.WindowTitle.MaximumLength = source_table_entry.FullDllName.MaximumLength;


		mask_paramaters.ImagePathName.Length = source_paramaters.ImagePathName.Length;
		mask_paramaters.ImagePathName.MaximumLength = source_paramaters.ImagePathName.MaximumLength;
		mask_paramaters.DllPath.Length = source_paramaters.DllPath.Length;
		mask_paramaters.DllPath.MaximumLength = source_paramaters.DllPath.MaximumLength;
		mask_paramaters.MaximumLength = source_paramaters.MaximumLength;
		mask_paramaters.Length = source_paramaters.Length;
		mask_paramaters.ProcessGroupId = source_paramaters.ProcessGroupId;
		mask_paramaters.EnvironmentSize = source_paramaters.EnvironmentSize;
		mask_paramaters.CurrentDirectory.DosPath.Length = source_paramaters.CurrentDirectory.DosPath.Length;
		mask_paramaters.CurrentDirectory.DosPath.MaximumLength = source_paramaters.CurrentDirectory.DosPath.MaximumLength;

		MiMemory::MiWriteProcessMemory(MaskEprocess, (PVOID)mask_paramater_addr, &mask_paramaters, sizeof(RTL_USER_PROCESS_PARAMETERS));

		//WindowTitle
		mask_buffer = patternSearch::read_i64(MaskEprocess, mask_paramater_addr + 0xB8);
		MiMemory::MiWriteProcessMemory(MaskEprocess, (PVOID)mask_buffer, empty, WindowTitle_MaximumLength);
		patternSearch::write_i64(MaskEprocess, mask_paramater_addr + 0xB8, FullDllName_addr);
		patternSearch::write_i64(MaskEprocess, mask_paramater_addr + 0x78, FullDllName_addr);





 
	

 
	}
	VOID FAKE_PEB32(PEPROCESS MaskEprocess, PEPROCESS SourceEprocess) {
		if (!imports::ps_get_process_wow64_process(MaskEprocess)||!imports::ps_get_process_wow64_process(SourceEprocess))
		{
			return;
		}
		ULONG64 source_paramater_addr = 0;
		ULONG64 source_peb_ldr_addr = 0;
		PEB_LDR_DATA32 source_peb_data = { 0 };
		LDR_DATA_TABLE_ENTRY32 source_table_entry = { 0 };
		RTL_USER_PROCESS_PARAMETERS32 source_paramaters = { 0 };
		GET_PEB_DATA(SourceEprocess, TRUE, &source_peb_data, &source_paramaters, &source_table_entry, &source_peb_ldr_addr, &source_paramater_addr);

		ULONG64 mask_paramater_addr = 0;
		ULONG64 mask_peb_ldr_addr = 0;
		PEB_LDR_DATA32 mask_peb_data = { 0 };
		LDR_DATA_TABLE_ENTRY32 mask_table_entry = { 0 };
		RTL_USER_PROCESS_PARAMETERS32 mask_paramaters = { 0 };
		GET_PEB_DATA(MaskEprocess, TRUE, &mask_peb_data, &mask_paramaters, &mask_table_entry, &source_peb_ldr_addr, &source_paramater_addr);


		mask_table_entry.BaseDllName.Length = source_table_entry.BaseDllName.Length;
		mask_table_entry.BaseDllName.MaximumLength = source_table_entry.BaseDllName.MaximumLength;
		mask_table_entry.EntryPoint = source_table_entry.EntryPoint;
		mask_table_entry.DllBase = source_table_entry.DllBase;
		mask_table_entry.SizeOfImage = source_table_entry.SizeOfImage;
		mask_table_entry.FullDllName.Length = source_table_entry.FullDllName.Length;
		mask_table_entry.FullDllName.MaximumLength = source_table_entry.FullDllName.MaximumLength;
		char empty[0x500] = { 0 };
		MiMemory::MiWriteProcessMemory(MaskEprocess, (PVOID)mask_peb_ldr_addr, &mask_table_entry, sizeof(LDR_DATA_TABLE_ENTRY));
		char nameTemp[0x200] = { 0 };

		ULONG64 buffer_addr = patternSearch::read_i32(SourceEprocess, source_peb_ldr_addr + 0x28);

		MiMemory::MiReadProcessMemory(SourceEprocess, (PVOID)buffer_addr, nameTemp, source_table_entry.FullDllName.MaximumLength);
		ULONG64 mask_buffer = patternSearch::read_i32(MaskEprocess, mask_peb_ldr_addr + 0x28);
		ULONG64 FullDllName_addr = mask_buffer;
		//先清空自己
		MiMemory::MiWriteProcessMemory(MaskEprocess, (PVOID)mask_buffer, empty, mask_table_entry.FullDllName.MaximumLength);
		//写入复制数据
		MiMemory::MiWriteProcessMemory(MaskEprocess, (PVOID)mask_buffer, nameTemp, source_table_entry.FullDllName.MaximumLength);

		ULONG64 BaseDllName_addr = patternSearch::read_i32(SourceEprocess, source_peb_ldr_addr + 0x30);
		USHORT nameOffset = BaseDllName_addr - buffer_addr;
		patternSearch::write_i64(MaskEprocess, mask_peb_ldr_addr + 0x30, mask_buffer + nameOffset);


		ULONG WindowTitle_MaximumLength = mask_paramaters.WindowTitle.MaximumLength;
		MiMemory::MiWriteProcessMemory(MaskEprocess,(PVOID)mask_paramaters.CurrentDirectory.DosPath.Buffer, empty, mask_paramaters.CurrentDirectory.DosPath.MaximumLength);
		mask_paramaters.CommandLine.Length = source_table_entry.FullDllName.Length;
		mask_paramaters.CommandLine.MaximumLength = source_table_entry.FullDllName.MaximumLength;




		mask_paramaters.WindowTitle.Length = source_table_entry.FullDllName.Length;
		mask_paramaters.WindowTitle.MaximumLength = source_table_entry.FullDllName.MaximumLength;


		mask_paramaters.ImagePathName.Length = source_paramaters.ImagePathName.Length;
		mask_paramaters.ImagePathName.MaximumLength = source_paramaters.ImagePathName.MaximumLength;
		mask_paramaters.DllPath.Length = source_paramaters.DllPath.Length;
		mask_paramaters.DllPath.MaximumLength = source_paramaters.DllPath.MaximumLength;
		mask_paramaters.MaximumLength = source_paramaters.MaximumLength;
		mask_paramaters.Length = source_paramaters.Length;
		mask_paramaters.ProcessGroupId = source_paramaters.ProcessGroupId;
		mask_paramaters.EnvironmentSize = source_paramaters.EnvironmentSize;
		mask_paramaters.CurrentDirectory.DosPath.Length = source_paramaters.CurrentDirectory.DosPath.Length;
		mask_paramaters.CurrentDirectory.DosPath.MaximumLength = source_paramaters.CurrentDirectory.DosPath.MaximumLength;

		MiMemory::MiWriteProcessMemory(MaskEprocess, (PVOID)mask_paramater_addr, &mask_paramaters, sizeof(RTL_USER_PROCESS_PARAMETERS));

		//WindowTitle
		mask_buffer = patternSearch::read_i32(MaskEprocess, mask_paramater_addr + 0x74);
		MiMemory::MiWriteProcessMemory(MaskEprocess, (PVOID)mask_buffer, empty, WindowTitle_MaximumLength);
		patternSearch::write_i32(MaskEprocess, mask_paramater_addr + 0x74, FullDllName_addr);
		//CommandLine
		patternSearch::write_i32(MaskEprocess, mask_paramater_addr + 0x44, FullDllName_addr);




	
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
		MaskEprocess = Utils::lookup_process_by_id((HANDLE)pid);
		if (!MaskEprocess) return status;


		//被伪装的目标进程
		SourceEprocess = Utils::lookup_process_by_id((HANDLE)fakePid);
		if (!SourceEprocess) return status;
	 
		while (1)
		{
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

			////修改Eprocess.ImagePathHash
			//{

			//	ULONG ImagePathHashOffset = imageNameOffset + 0x4c;
			//	ULONG SourceImagePathHash = *(PULONG)((PUCHAR)SourceEprocess + ImagePathHashOffset);

			//	*(PULONG)((PUCHAR)MaskEprocess + ImagePathHashOffset) = SourceImagePathHash;
			//}

			////修改Eprocess.BaseAddressOffset
			//{
			//	ULONG SectionBaseAddressOffset = *(PULONG)(imports::imported.ps_get_process_section_base_address + 3);
			//	ULONG SourceBaseAddress = *(PULONG)((PUCHAR)SourceEprocess + SectionBaseAddressOffset);
			//	*(PULONG)((PUCHAR)MaskEprocess + SectionBaseAddressOffset) = SourceBaseAddress;

			//}

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
			


			FAKE_PEB(MaskEprocess, SourceEprocess);
 
			FAKE_PEB32(MaskEprocess, SourceEprocess);
 
			break;
		}
		//EPROCESS   PsIsProtectedProcess
//{
//	ULONG isProtectOffset = functions::GetFunctionVariableOffset(skCrypt(L"PsIsProtectedProcess"), 2);
//	*(PULONG_PTR)((PUCHAR)MaskEprocess + isProtectOffset) = 0xff;
//} 
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




