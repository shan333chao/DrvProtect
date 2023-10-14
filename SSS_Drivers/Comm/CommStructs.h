#pragma once
#ifdef _R3
#include <Windows.h>
#else
#include <ntifs.h>
#endif 
#define COMM_ID 0x1CFE
#define SYMBOL_NAME "\\??\\Nul"
typedef enum _COMM_TYPE {
	//测试通讯
	TEST_COMM,
	//进程伪装
	PROTECT_PROCESS, 
	//进程自杀
	KILL,
	//遍历进程
	ENUM_PROCESS, 
	//伪装读取内存
	FAKE_READ_MEMORY,
	//伪装写入内存
	FAKE_WRITE_MEMORY, 
	//伪装读取内存
	PHY_READ_MEMORY,
	//伪装写入内存
	PHY_WRITE_MEMORY, 
	//保护窗口
	WND_PROTECT,
	//申请内存
	CREATE_MEMORY,
	//创建线程
	CREATE_THREAD,
	//查询模块
	QUERY_MODULE,
	//查询VAD模块
	QUERY_VAD_MODULE,
	//内核模块注入
	INJECT_DLL,
	//文件保护
	PROTECT_FILE, 
	//进程保护
	PROTECT_PROCESS_ADD,
	//移除应用层保护
	PROTECT_PROCESS_REMOVE,
	//特征搜索
	PATTERN_SEARCH,
	//内核拉伸dll
	WRITE_DLL,
	//主线程call
	CALL_MAIN,
	//获取远程模块导出函数地址
	MODULE_NAME_EXPORT,
	//通过模块基址查找导出函数
	MODULE_BASE_EXPORT,
	//修改内存属性
	MEMORY_ATTRIBUTE

};


typedef struct  _COMM_DATA { 
	USHORT			ID;
	UCHAR			InDataLen;
	UCHAR			Type; 
	ULONG64			InData;
	NTSTATUS status;
}COMM_DATA, * PCOMM_DATA;


//测试通讯
typedef struct _TEST_DATA { 
	ULONG uTest;
	PVOID regCode;
	UCHAR size;
	ULONG time;
}TEST_DATA, * PTEST_TATA;

//保护进程
typedef struct _PROTECT_PROCESS_DATA { 
	ULONG		PID;
}PROTECT_PROCESS_DATA, * PPROTECT_PROCESS_DATA;

//伪装进程并保进程主窗口
typedef struct _FAKE_PROCESS_DATA { 
	ULONG		FakePID;
	ULONG		PID; 
}FAKE_PROCESS_DATA,*PFAKE_PROCESS_DATA;

//读写内存
typedef struct _RW_MEM_DATA {
	ULONG		FakePID;
	ULONG		PID;
	PVOID		Address;
	ULONG		uDataSize;
	PVOID		pValBuffer;
}RW_MEM_DATA, * PRW_MEM_DATA;




//窗口保护
typedef struct _WND_PROTECT_DATA { 
	PULONG32		hwnds;
	ULONG32		Length;
}WND_PROTECT_DATA, * PWND_PROTECT_DATA;


//创建内存
typedef struct _CREATE_MEM_DATA {
	ULONG		PID;
	ULONG_PTR	uSize;
	PULONG64	pVAddress;
}CREATE_MEM_DATA, * PCREATE_MEM_DATA;

//修改内存属性为可执行
typedef struct _CHANGE_ATTRIBUTE_DATA {
	ULONG	PID;
	ULONG	uSize;
	ULONG64	Address;
}CHANGE_ATTRIBUTE_DATA, * PCHANGE_ATTRIBUTE_DATA;


//创建线程
typedef struct _CREATE_THREAD_DATA {
	ULONG PID;
	PVOID ShellCode;
	PVOID Argument;
}CREATE_THREAD_DATA, * PCREATE_THREAD_DATA;

//查询模块
typedef struct _QUERY_MODULE_DATA {
	ULONG PID;
	PCHAR pcModuleName;
	ULONG_PTR pModuleBase;
	PULONG pModuleSize;
	USHORT type;
}QUERY_MODULE_DATA, * PQUERY_MODULE_DATA;

//特征搜索
typedef struct _PATTEERN_DATA {
	ULONG PID;
	PCHAR pcModuleName;
	PCHAR pattern;
	PCHAR mask;
	ULONGLONG addr;
}PATTEERN_DATA,*PPATTEERN_DATA;

//注入dll
typedef struct _INJECT_DLL_DATA {
	ULONG PID;
	PCHAR dllFilePath; 
}INJECT_DLL_DATA,*PINJECT_DLL_DATA;


//写入dll
typedef struct _WRITE_DLL_DATA {
	ULONG PID;
	PCHAR dllFilePath;
	ULONG64 imageBase;
	ULONG64 entryPoint;
	ULONG64 kimageBase;
}WRITE_DLL_DATA, *PWRITE_DLL_DATA;

//远程call
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