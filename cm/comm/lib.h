#include "CommR3.h"
#include <stdio.h>
#include <windows.h>
#include <string.h>

#ifdef __cplusplus
extern "C" {
#endif

BOOL InitDriver();
ULONG init(char* regCode);

BOOL FakeReadMemory(ULONG PID, ULONG fakePid, PVOID Address, PVOID buffer, ULONG uDataSize);
BOOL FakeWriteMemory(ULONG		PID, ULONG fakePid, PVOID	Address, PUCHAR pValBuffer,ULONG length);
BOOL PhyReadMemory(ULONG PID, PVOID Address, PVOID buffer, ULONG uDataSize);
BOOL PhyWriteMemory(ULONG		PID, PVOID	Address, PUCHAR		pValBuffer, ULONG length);

//进程伪装 
//protectPid 自身进程id
//fakePid 要伪装的进程id
BOOL ProtectProcess(ULONG protectPid, ULONG fakePid);

//窗口保护
//hwnd 自身主窗口句柄
BOOL ProtectWindow(ULONG32 hwnd);


//从PEB 中查询模块 基址大小
//pid 进程名
//szModuleName 模块名  （不区分大小写）
BOOL QueryModule(ULONG pid, PCHAR szModuleName, PULONGLONG pModuleBase, PULONG pModuleSize);


//从VAD 中查询模块 基址大小
//pid 进程名
//szModuleName 模块名  （严格区分大小写）
BOOL QueryVADModule(ULONG pid, PCHAR szModuleName, PULONGLONG pModuleBase, PULONG pModuleSize);


//申请隐藏内存
//pid 进程名
//uDataSize 申请内存大小
PUCHAR AllocateMem(ULONG PID, ULONG uDataSize);


//创建线程
//pid 进程名
//shellcode （shellcode 的内容）
//len （shellcode 字节长度）
//Argument (线程启动 参数 可为NULL)
BOOL CreateMyThread(ULONG PID, PVOID address, PVOID Argument);


//保护进程
//pid 进程名
//isProcect  设置是否保护
BOOL ProtectProcessR3(ULONG pid, BOOLEAN isProcect);
#ifdef __cplusplus
}
#endif
