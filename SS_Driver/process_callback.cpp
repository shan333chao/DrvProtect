
//obCallback.h
#pragma once

#ifdef __cplusplus
extern "C"
{
#endif
#include <ntifs.h>
#include "process_callback.h"

#ifdef __cplusplus
}
#endif 
#include "ProtectWindow/Protect.hpp"

#define arraysize(p) (sizeof(p)/sizeof((p)[0]))
#define PROCESS_TERMINATE         0x0001  
#define PROCESS_VM_OPERATION      0x0008  
#define PROCESS_VM_READ           0x0010  
#define PROCESS_VM_WRITE          0x0020 

typedef struct _DEVICE_EXTENSION {
	PDEVICE_OBJECT pDevice;
	UNICODE_STRING ustrDeviceName;	//�豸����
	UNICODE_STRING ustrSymLinkName;	//����������
} DEVICE_EXTENSION, * PDEVICE_EXTENSION;  //�豸��չ��Ϣ�ṹ��


typedef struct _LDR_DATA_TABLE_ENTRY64
{
	LIST_ENTRY64    InLoadOrderLinks;
	LIST_ENTRY64    InMemoryOrderLinks;
	LIST_ENTRY64    InInitializationOrderLinks;
	PVOID            DllBase;
	PVOID            EntryPoint;
	ULONG            SizeOfImage;
	UNICODE_STRING    FullDllName;
	UNICODE_STRING     BaseDllName;
	ULONG            Flags;
	USHORT            LoadCount;
	USHORT            TlsIndex;
	PVOID            SectionPointer;
	ULONG            CheckSum;
	PVOID            LoadedImports;
	PVOID            EntryPointActivationContext;
	PVOID            PatchInformation;
	LIST_ENTRY64    ForwarderLinks;
	LIST_ENTRY64    ServiceTagLinks;
	LIST_ENTRY64    StaticLinks;
	PVOID            ContextInformation;
	ULONG64            OriginalBase;
	LARGE_INTEGER    LoadTime;
} LDR_DATA_TABLE_ENTRY64, * PLDR_DATA_TABLE_ENTRY64;


 

NTSTATUS ProtectProcess(); //���̱���
OB_PREOP_CALLBACK_STATUS MyCallback(PVOID RegistrationContext, POB_PRE_OPERATION_INFORMATION pOperationInformation); //�ص�����
char* GetProcessNameByProcessID(HANDLE pid); //ȡ������


//obCallback.cpp

 

#ifdef __cplusplus
extern "C"
{
#endif
	UCHAR* PsGetProcessImageFileName(PEPROCESS EProcess);
#ifdef __cplusplus
}
#endif

BOOLEAN pre = FALSE;
 


PVOID obHandle;  //�洢�ص����

NTSTATUS ProtectProcess()
{

	OB_CALLBACK_REGISTRATION obReg;
	OB_OPERATION_REGISTRATION opReg;

	memset(&obReg, 0, sizeof(obReg));
	obReg.Version = ObGetFilterVersion();
	obReg.OperationRegistrationCount = 1;
	obReg.RegistrationContext = NULL;
	RtlInitUnicodeString(&obReg.Altitude, L"321000");

	memset(&opReg, 0, sizeof(opReg)); //��ʼ���ṹ�����

	opReg.ObjectType = PsProcessType;
	opReg.Operations = OB_OPERATION_HANDLE_CREATE | OB_OPERATION_HANDLE_DUPLICATE;

	opReg.PreOperation = (POB_PRE_OPERATION_CALLBACK)(&MyCallback);  //ע��ص�����ָ��

	obReg.OperationRegistration = &opReg; //ע����һ�����
	return ObRegisterCallbacks(&obReg, &obHandle); //ע��ص�����
}

OB_PREOP_CALLBACK_STATUS MyCallback(PVOID RegistrationContext, POB_PRE_OPERATION_INFORMATION pOperationInformation)
{
	HANDLE pid = PsGetProcessId((PEPROCESS)pOperationInformation->Object);
	//char szProcName[16] = { 0 };
	UNREFERENCED_PARAMETER(RegistrationContext);
	//strcpy(szProcName, GetProcessNameByProcessID(pid));

	if (Protect::IsProtectPID(pid))
	{
		if (pOperationInformation->Operation == OB_OPERATION_HANDLE_CREATE)
		{
			if ((pOperationInformation->Parameters->CreateHandleInformation.OriginalDesiredAccess & PROCESS_TERMINATE) == PROCESS_TERMINATE)
			{
				pOperationInformation->Parameters->CreateHandleInformation.DesiredAccess &= ~PROCESS_TERMINATE;
			}
			if ((pOperationInformation->Parameters->CreateHandleInformation.OriginalDesiredAccess & PROCESS_VM_OPERATION) == PROCESS_VM_OPERATION)
			{
				pOperationInformation->Parameters->CreateHandleInformation.DesiredAccess &= ~PROCESS_VM_OPERATION;
			}
			if ((pOperationInformation->Parameters->CreateHandleInformation.OriginalDesiredAccess & PROCESS_VM_READ) == PROCESS_VM_READ)
			{
				pOperationInformation->Parameters->CreateHandleInformation.DesiredAccess &= ~PROCESS_VM_READ;
			}
			if ((pOperationInformation->Parameters->CreateHandleInformation.OriginalDesiredAccess & PROCESS_VM_WRITE) == PROCESS_VM_WRITE)
			{
				pOperationInformation->Parameters->CreateHandleInformation.DesiredAccess &= ~PROCESS_VM_WRITE;
			}
		}
	}
	return OB_PREOP_SUCCESS;
}

char* GetProcessNameByProcessID(HANDLE pid)
{
	NTSTATUS status;
	PEPROCESS EProcess = NULL;
	status = PsLookupProcessByProcessId(pid, &EProcess);

	if (!NT_SUCCESS(status))
	{
		return FALSE;
	}
	ObDereferenceObject(EProcess);
	return (char*)PsGetProcessImageFileName(EProcess);
}



 

void UnRegisterCallBack() {

	if (pre)  //���ע��ص������ɹ���ɾ���ص�
		ObUnRegisterCallbacks(obHandle);
	KdPrint(("��ɾ���ص�"));
}

EXTERN_C VOID RegisterCallback(PDRIVER_OBJECT pDriverOb)
{
	NTSTATUS status = 0;

	PLDR_DATA_TABLE_ENTRY64 ldrDataTable;
	ldrDataTable = (PLDR_DATA_TABLE_ENTRY64)pDriverOb->DriverSection;
	ldrDataTable->Flags |= 0x20;  //��MmVerifyCallbackFunction 
	status = ProtectProcess(); //ʵ�ֶ���ص�
	if (NT_SUCCESS(status))
	{
		KdPrint(("ע��ص������ɹ�"));
		pre = TRUE;
	}
	else
		KdPrint(("ע��ص�����ʧ��"));
	 
}
 