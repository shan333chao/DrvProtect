#pragma once
#ifdef _R3
#include <Windows.h>
#else
#include <ntifs.h>
#endif 
#define COMM_ID 0x1CFE
#define SYMBOL_NAME "\\??\\Nul"
typedef enum _COMM_TYPE {
	//����ͨѶ
	TEST_COMM,
	//����αװ
	PROTECT_PROCESS, 
	//������ɱ
	KILL,
	//��������
	ENUM_PROCESS, 
	//αװ��ȡ�ڴ�
	FAKE_READ_MEMORY,
	//αװд���ڴ�
	FAKE_WRITE_MEMORY, 
	//αװ��ȡ�ڴ�
	PHY_READ_MEMORY,
	//αװд���ڴ�
	PHY_WRITE_MEMORY, 
	//��������
	WND_PROTECT,
	//�����ڴ�
	CREATE_MEMORY,
	//�����߳�
	CREATE_THREAD,
	//��ѯģ��
	QUERY_MODULE,
	//��ѯVADģ��
	QUERY_VAD_MODULE,
	//�ں�ģ��ע��
	INJECT_DLL,
	//�ļ�����
	PROTECT_FILE, 
	//���̱���
	PROTECT_PROCESS_ADD,
	//�Ƴ�Ӧ�ò㱣��
	PROTECT_PROCESS_REMOVE,
	//��������
	PATTERN_SEARCH,
	//�ں�����dll
	WRITE_DLL,
	//���߳�call
	CALL_MAIN,
	//��ȡԶ��ģ�鵼��������ַ
	MODULE_NAME_EXPORT,
	//ͨ��ģ���ַ���ҵ�������
	MODULE_BASE_EXPORT,
	//�޸��ڴ�����
	MEMORY_ATTRIBUTE

};


typedef struct  _COMM_DATA { 
	USHORT			ID;
	UCHAR			InDataLen;
	UCHAR			Type; 
	ULONG64			InData;
	NTSTATUS status;
}COMM_DATA, * PCOMM_DATA;


//����ͨѶ
typedef struct _TEST_DATA { 
	ULONG uTest;
	PVOID regCode;
	UCHAR size;
	ULONG time;
}TEST_DATA, * PTEST_TATA;

//��������
typedef struct _PROTECT_PROCESS_DATA { 
	ULONG		PID;
}PROTECT_PROCESS_DATA, * PPROTECT_PROCESS_DATA;

//αװ���̲�������������
typedef struct _FAKE_PROCESS_DATA { 
	ULONG		FakePID;
	ULONG		PID; 
}FAKE_PROCESS_DATA,*PFAKE_PROCESS_DATA;

//��д�ڴ�
typedef struct _RW_MEM_DATA {
	ULONG		FakePID;
	ULONG		PID;
	PVOID		Address;
	ULONG		uDataSize;
	PVOID		pValBuffer;
}RW_MEM_DATA, * PRW_MEM_DATA;




//���ڱ���
typedef struct _WND_PROTECT_DATA { 
	PULONG32		hwnds;
	ULONG32		Length;
}WND_PROTECT_DATA, * PWND_PROTECT_DATA;


//�����ڴ�
typedef struct _CREATE_MEM_DATA {
	ULONG		PID;
	ULONG_PTR	uSize;
	PULONG64	pVAddress;
}CREATE_MEM_DATA, * PCREATE_MEM_DATA;

//�޸��ڴ�����Ϊ��ִ��
typedef struct _CHANGE_ATTRIBUTE_DATA {
	ULONG	PID;
	ULONG	uSize;
	ULONG64	Address;
}CHANGE_ATTRIBUTE_DATA, * PCHANGE_ATTRIBUTE_DATA;


//�����߳�
typedef struct _CREATE_THREAD_DATA {
	ULONG PID;
	PVOID ShellCode;
	PVOID Argument;
}CREATE_THREAD_DATA, * PCREATE_THREAD_DATA;

//��ѯģ��
typedef struct _QUERY_MODULE_DATA {
	ULONG PID;
	PCHAR pcModuleName;
	ULONG_PTR pModuleBase;
	PULONG pModuleSize;
	USHORT type;
}QUERY_MODULE_DATA, * PQUERY_MODULE_DATA;

//��������
typedef struct _PATTEERN_DATA {
	ULONG PID;
	PCHAR pcModuleName;
	PCHAR pattern;
	PCHAR mask;
	ULONGLONG addr;
}PATTEERN_DATA,*PPATTEERN_DATA;

//ע��dll
typedef struct _INJECT_DLL_DATA {
	ULONG PID;
	PCHAR dllFilePath; 
}INJECT_DLL_DATA,*PINJECT_DLL_DATA;


//д��dll
typedef struct _WRITE_DLL_DATA {
	ULONG PID;
	PCHAR dllFilePath;
	ULONG64 imageBase;
	ULONG64 entryPoint;
	ULONG64 kimageBase;
}WRITE_DLL_DATA, *PWRITE_DLL_DATA;

//Զ��call
typedef struct _CALL_DATA {
	ULONG PID;
	ULONG64 shellcodeAddr; 
	ULONG shellcodeLen;
}CALL_DATA,*PCALL_DATA;


typedef struct _MODULE_EXPORT_DATA {
	ULONG PID;
	PCHAR ModuleName;
	PCHAR ExportFuncName; 
	ULONG64 FuncAddr;
}MODULE_EXPORT_DATA, * PMODULE_EXPORT_DATA;


typedef struct _MODULE_BASE_EXPORT_DATA {
	ULONG PID;
	ULONG64 ModuleBase;
	PCHAR ExportFuncName;
	ULONG64 FuncAddr;
}MODULE_BASE_EXPORT_DATA, * PMODULE_BASE_EXPORT_DATA;