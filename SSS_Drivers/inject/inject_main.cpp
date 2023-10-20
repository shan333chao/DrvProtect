#include "inject_main.h"
#include "eip_execute.h"
#include "./module_x64/PeHelper64.h"
#include "./module_x86/PeHelper86.h"
#include "../../Memmory/Memory.h"
#include "thread_execute.h"
#include "ApcExecute.h"
typedef void (*LoopthreadCallback)(PETHREAD thread);
namespace inject_main {
	//��������
	PETHREAD LoopThreadInProcess(PEPROCESS tempep, LoopthreadCallback func)
	{
		PETHREAD pretthreadojb = NULL, ptempthreadobj = NULL;

		PLIST_ENTRY plisthead = NULL;

		PLIST_ENTRY plistflink = NULL;

		int i = 0;

		plisthead = (PLIST_ENTRY)((PUCHAR)tempep + 0x30);

		plistflink = plisthead->Flink;

		//����
		for (plistflink; plistflink != plisthead; plistflink = plistflink->Flink)
		{
			ptempthreadobj = (PETHREAD)((PUCHAR)plistflink - 0x2f8);

			HANDLE threadId = imports::ps_get_thread_id(ptempthreadobj);

			func(ptempthreadobj);

			Logf("%d �߳�ID: %d ", i++, threadId);



		}

		return pretthreadojb;
	}
	void RemoteLoadPeData(PEPROCESS pEprocess, PVOID filebufeer, ULONG64 filesize, PVOID* entry, PVOID virtualbase, ULONG64 kernelImageBase) {
		//����
		KAPC_STATE KAPC = { 0 };
		if (imports::ps_get_process_exit_process_called(pEprocess))
		{
			return;
		}
		Utils::AttachProcess(pEprocess);
		//imports::ke_stack_attach_process(pEprocess, &KAPC);
		PVOID entrypoint = NULL;
		ULONGLONG dos_header = (ULONGLONG)filebufeer;
		USHORT imageMagic = *(PUSHORT)dos_header;
		if (imageMagic != 0x5a4d)
		{
			return;
		}
		ULONGLONG nt_header = (ULONGLONG) * (ULONG*)(dos_header + 0x03C) + dos_header;
		USHORT  machine = *(USHORT*)(nt_header + 0x4);

		PVOID peb32 = imports::ps_get_process_wow64_process(pEprocess);
		if (machine != 0x8664 && peb32)
		{
			pehelper86::PELoaderDLL((PUCHAR)filebufeer, (PUCHAR)virtualbase, kernelImageBase, &entrypoint, pEprocess);
		}
		if (machine == 0x8664 && !peb32)
		{
			pehelper64::PELoaderDLL((PUCHAR)filebufeer, (PUCHAR)virtualbase, kernelImageBase, &entrypoint, pEprocess);
		}
		Logf("DLL ModuleBase:%p  entrypoint��%p", virtualbase, entrypoint);
		//imports::ke_unstack_detach_process(&KAPC);
		Utils::DetachProcess();
		*entry = entrypoint;
	}
	void injectDll(PEPROCESS process, PVOID filebuffer, ULONG64 filesize, UCHAR type) {
		if (!process) {
			Logf("����δ�ҵ�");
			return;
		}
		LoopThreadInProcess(process, [](PETHREAD thread) {});
		//���������ڴ�
		ULONG64 virtualbase = 0;
		ULONG64 kernelAddr = 0;
		MDL mdl = { 0 };
		NTSTATUS allocatePeStatus = memory::CreateMemory(process, pehelper64::GetImageSize((PUCHAR)filebuffer), &virtualbase, &kernelAddr, &mdl);
		if (!NT_SUCCESS(allocatePeStatus))
		{
			Logf("���������ڴ�����ʧ��");
			return;
		}
		Logf("Զ������Pe�ڴ�ɹ���r3: %p  r0: %p", virtualbase, kernelAddr);
		//����PE
		PVOID entrypoint = NULL;
		RemoteLoadPeData(process, filebuffer, filesize, &entrypoint, (PVOID)virtualbase, kernelAddr);
		Logf("entrypoint %p moduleBase %p", entrypoint, virtualbase);
		//Eipִ�к���
		if (entrypoint)
		{
			switch (type)
			{
			case 1: {
				CreateInjectThread(process, virtualbase, (ULONG64)entrypoint, kernelAddr);
				break;
			}
			case 2: {
				eip_execute::EipExcute_x64dll(process, entrypoint, virtualbase, kernelAddr, 1);
				break;
			}case 3: {
				APCExecuteFunction(process, entrypoint, virtualbase);
				break;
			}
			default:
				break;
			}
		} 
	}

	NTSTATUS ReadFile(PCHAR dllpath, PVOID* buffer, PULONG64 size)
	{
		OBJECT_ATTRIBUTES obj = { 0 };
		HANDLE readHandle = NULL;
		IO_STATUS_BLOCK ioStackblock = { 0 };

		ANSI_STRING aFilePath = { 0 };
		imports::rtl_init_ansi_string(&aFilePath, dllpath);
		UNICODE_STRING filepath = { 0 };
		imports::rtl_ansi_string_to_unicode_string(&filepath, &aFilePath, TRUE);


		//��ʼ��OBJECT_ATTRIBUTES
		InitializeObjectAttributes(&obj, &filepath,
			OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE,
			NULL, NULL
		);

		//����һ��handle

		NTSTATUS creafileStatus = imports::zw_create_file(
			&readHandle,	//�ļ����
			GENERIC_READ,   //��Ȩ��
			&obj,			//��ʼ����OBJECT_ATTRIBUTES
			&ioStackblock,	//�ýṹ�����������״̬���й������������������Ϣ
			NULL,			//�����򸲸ǵ��ļ��ĳ�ʼ�����С�����ֽ�Ϊ��λ��
			FILE_ATTRIBUTE_NORMAL,	//��Щ��־��ʾ�ڴ����򸲸��ļ�ʱҪ���õ��ļ�����
			FILE_SHARE_READ,		//����Ȩ��
			FILE_OPEN_IF,			//ָ�����ļ����ڻ򲻴���ʱҪִ�еĲ���
			FILE_NON_DIRECTORY_FILE | FILE_RANDOM_ACCESS | FILE_SYNCHRONOUS_IO_NONALERT,
			NULL,
			0
		);

		if (!NT_SUCCESS(creafileStatus)) {
			Logf("ZwCreateFileʧ��");
			imports::rtl_free_unicode_string(&filepath);
			return STATUS_UNSUCCESSFUL;
		}

		//��ȡ�ļ�����
		FILE_STANDARD_INFORMATION fsi = { 0 };
		NTSTATUS QueryInformationStatus = imports::zw_query_information_file(readHandle,
			&ioStackblock,
			&fsi,
			sizeof(FILE_STANDARD_INFORMATION),
			FileStandardInformation);

		if (!NT_SUCCESS(QueryInformationStatus)) {
			imports::rtl_free_unicode_string(&filepath);
			Logf("ZwQueryInformationFile ��ȡ�ļ���Сʧ��");
			return STATUS_UNSUCCESSFUL;
		}

		//���뻺����
		SIZE_T filesize = (LONG)fsi.EndOfFile.QuadPart;
		PVOID filebuffer = imports::ex_allocate_pool(NonPagedPool, filesize);
		Utils::kmemset(filebuffer, 0, filesize);


		NTSTATUS ReadFilestatus = imports::zw_read_file(
			readHandle,		//�ļ����
			NULL, NULL, NULL,
			&ioStackblock,	//�ýṹ�����������״̬���й�������Ķ�ȡ��������Ϣ
			filebuffer,	//������
			filesize,	//��С
			NULL,
			0
		);

		if (!NT_SUCCESS(ReadFilestatus)) {
			Logf("ZwReadFile ʧ��");
			imports::rtl_free_unicode_string(&filepath);
			return STATUS_UNSUCCESSFUL;
		}

		*buffer = filebuffer;
		*size = filesize;
		if (!NT_SUCCESS(imports::zw_close(readHandle)))
		{
			return STATUS_UNSUCCESSFUL;
		}
		imports::rtl_free_unicode_string(&filepath);
		return STATUS_SUCCESS;
	}

	NTSTATUS inject_x64DLL(PCHAR dllPath, ULONG targetPid, UCHAR type) {
		PEPROCESS eprocess = Utils::lookup_process_by_id(ULongToHandle(targetPid));
		if (!eprocess)
		{
			Logf("����δ�ҵ� \r\n");
			return STATUS_INVALID_PARAMETER_2;
		}
		PVOID filebuffer = NULL;
		ULONG64 filesize = NULL;
		NTSTATUS status = ReadFile(dllPath, &filebuffer, &filesize);
		if (!NT_SUCCESS(status))
		{
			imports::ex_free_pool_with_tag(filebuffer, 0);
			Logf("��ȡ�ļ�ʧ�� \r\n");
			return STATUS_INVALID_PARAMETER_1;
		}
		ULONGLONG dos_header = (ULONGLONG)filebuffer;
		USHORT imageMagic = *(PUSHORT)dos_header;
		if (imageMagic != 0x5a4d)
		{
			return STATUS_INVALID_PARAMETER_1;
		}
		ULONGLONG nt_header = (ULONGLONG) * (ULONG*)(dos_header + 0x03C) + dos_header;
		USHORT  machine = *(USHORT*)(nt_header + 0x4);
		PVOID peb32 = imports::ps_get_process_wow64_process(eprocess);
		if ((peb32 && machine != 0x8664) || (!peb32 && machine == 0x8664))
		{
			injectDll(eprocess, filebuffer, filesize, type);
		}
		imports::ex_free_pool_with_tag(filebuffer, 0);
	}


	NTSTATUS WriteDLLx64_dll(PCHAR dllPath, ULONG targetPid, PULONG64 entry, PULONG64 PEimageBase, PULONG64 PEkernelImageBase)
	{
		NTSTATUS status = STATUS_UNSUCCESSFUL;
		if (!strlen_imp(dllPath))
		{
			Logf(" �ļ�Ϊ�� \r\n");
			status = STATUS_INVALID_PARAMETER_1;
			return status;
		}
		PEPROCESS eprocess = Utils::lookup_process_by_id(ULongToHandle(targetPid));
		if (!eprocess)
		{
			Logf("����δ�ҵ� \r\n");
			return STATUS_INVALID_PARAMETER_2;
		}
		PVOID filebuffer = NULL;
		ULONG64 filesize = NULL;

		status = ReadFile(dllPath, &filebuffer, &filesize);
		if (!NT_SUCCESS(status)) {
			Logf("����δ�ҵ�");
			return status;
		}
		//���������ڴ�
		ULONG64 virtualbase = 0;
		ULONG64 kernelAddr = 0;
		MDL mdl = { 0 };
		NTSTATUS allocatePeStatus = memory::CreateMemory(eprocess, pehelper64::GetImageSize((PUCHAR)filebuffer), &virtualbase, &kernelAddr, &mdl);
		if (!NT_SUCCESS(allocatePeStatus))
		{
			Logf("���������ڴ�����ʧ��");
			imports::ex_free_pool_with_tag(filebuffer, 0);
			return status;
		}
		Logf("Զ������Pe�ڴ�ɹ���r3: %p  r0: %p", virtualbase, kernelAddr);
		//����PE
		PVOID entrypoint = NULL;
		RemoteLoadPeData(eprocess, filebuffer, filesize, &entrypoint, (PVOID)virtualbase, kernelAddr);
		Logf("entrypoint %p moduleBase %p", entrypoint, virtualbase);
		if (!entrypoint)
		{
			imports::ex_free_pool_with_tag(filebuffer, 0);
			status = STATUS_UNSUCCESSFUL;
			return status;
		}
		*PEimageBase = virtualbase;
		*PEkernelImageBase = kernelAddr;
		*entry = (ULONG64)entrypoint;
		status = STATUS_SUCCESS;
		imports::ex_free_pool_with_tag(filebuffer, 0);
		return status;

	}
	NTSTATUS KernelCall(ULONG targetPid, ULONG64 entryPoint, ULONG shellcodeLen)
	{
		NTSTATUS status = STATUS_UNSUCCESSFUL;
		PEPROCESS eprocess = Utils::lookup_process_by_id(ULongToHandle(targetPid));
		if (!eprocess)
		{
			Logf("����δ�ҵ� \r\n");
			return STATUS_INVALID_PARAMETER_2;
		}
		BOOLEAN ret = eip_execute::EipExcuteShellcode(eprocess, entryPoint, 1, shellcodeLen);

		return ret ? STATUS_SUCCESS : STATUS_UNSUCCESSFUL;
	}
}