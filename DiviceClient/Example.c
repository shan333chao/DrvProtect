#pragma once
#define _CRT_SECURE_NO_WARNINGS
#include "Example.h"
#include <stdio.h>
#include <ntstatus.h>
#include <stdio.h>
#include <string.h>
#include "aes.h"
#include <time.h>
#include "Comm/Caller.h"
#include "../SSS_Drivers/ERROR_CODE.h"
#include "log.h"
BOOL IsMainWindow(HWND handle)
{
	return GetWindow(handle, GW_OWNER) == (HWND)0 && IsWindowVisible(handle);
}

BOOL CALLBACK EnumWindowsProc(HWND hwnd, PVOID lParam) {
	DWORD dwProcessId;
	DWORD threadid = GetWindowThreadProcessId(hwnd, &dwProcessId);
	PFWindowInfo windowInfo = (PFWindowInfo)lParam;
	if (dwProcessId == windowInfo->pid) {
		if (IsMainWindow(hwnd))
		{
			// 找到进程的主窗口句柄
			windowInfo->wndHw = hwnd;
			windowInfo->tid = threadid;
			return FALSE; // 返回 FALSE 停止枚举
		}
	}
	return TRUE; // 返回 TRUE 继续枚举
}

#include <windows.h>




//-------------------测试通讯
void TestComm(PVOID regCode)
{
	DWORD status_code = _InitReg(regCode);
	switch (status_code)
	{
	case STATUS_TEST_COMM_SUCCESS:
		Logp("测试通讯成功！\n");
		break;
	case STATUS_TEST_COMM_REG_EXPIRED:
		Logp("卡密过期！\n");
		break;
	case STATUS_TEST_COMM_REG_INVALID:
		Logp("无效卡密！\n");
		break;
	case STATUS_TEST_COMM_UNREG_OR_EXPIRED:
		Logp("未注册卡密或取消卡密");
		break;
	case STATUS_TEST_COMM_MISS_DRIVE_FILE:
		Logp("驱动丢失");
		break;
	case STATUS_TEST_COMM_CREATE_SERVICE_KEY:
		Logp("创建注册表失败");
		break;
	case STATUS_TEST_COMM_GETMODULEHANDLEA:
		Logp("获取模块失败");
		break;
	case STATUS_TEST_COMM_SE_LOAD_DRIVER_PRIVILEGE:
		Logp("提权失败");
		break;
	case STATUS_TEST_COMM_CREATE_SERVICE:
		Logp("创建驱动服务失败, %d");
		break;
	case STATUS_TEST_COMM_OPEN_SCMANAGER:
		Logp("OpenSCManagerW 失败, %d\n", GetLastError());
		break;
	default:
		Logp("未知错误");
		break;
	}


}
 

void PhyReadMemory(ULONG PID, PVOID Address, ULONG uDataSize)
{
	RW_MEM_DATA TestMEM = { 0 };
	PUCHAR data = VirtualAlloc(NULL, uDataSize, MEM_COMMIT, PAGE_READWRITE);
	memset(data, 0, uDataSize);

	DWORD status_code = _PhyReadMemory(PID, Address, data, uDataSize);
	if (status_code)
	{
		VirtualFree(TestMEM.pValBuffer, 0, MEM_RELEASE);
		Logp("读取出错  错误码%08x:\n", status_code);
		return;
	}
	Logp("读到的数据:\n");
	for (size_t i = 0; i < uDataSize; i++)
	{
		if (!(i % 16))
		{
			Logp("\n");
		}
		printf("%02x ", data[i]);
	}
	Logp("\n");
	VirtualFree(TestMEM.pValBuffer, 0, MEM_RELEASE);
}

BOOL PhyWriteMemory(ULONG PID, PVOID Address, PUCHAR pValBuffer, ULONG length)
{

	DWORD status_code = _PhyWriteMemory(PID, Address, pValBuffer, length);
	if (!status_code)
	{
		Logp("写入成功:\n");
	}
	else {
		Logp("写入失败 %08x:\n", status_code);
	}
	return !status_code;
}

void ProtectProcessR3(ULONG pid, BOOLEAN isProcect)
{

	DWORD status_code = 0;
	if (isProcect)
	{
		status_code = _ProtectProcessR3_Add(pid);
	}
	else
	{
		status_code = _ProtectProcessR3_Remove(pid);
	}
}

//-------------------保护进程-------------
//protectPid  要保护的进程id
//fakePid	要伪装的进程id
//返回值无
void ProtectProcess(ULONG protectPid, ULONG fakePid) {
	if (!protectPid)
	{
		Logp("要保护的进程PID 为空\n");
		return;
	}
	if (!fakePid)
	{
		Logp("要伪装的进程PID 为空\n");
		return;
	}
	FWindowInfo winfo = { 0 };
	winfo.pid = protectPid;
	EnumWindows(EnumWindowsProc, &winfo);
	if (winfo.wndHw)
	{
		char className[256] = { 0 };
		char windowTitle[256] = { 0 };
		GetWindowTextA(winfo.wndHw, windowTitle, sizeof(windowTitle));  // 获取窗口标题
		GetClassNameA(winfo.wndHw, className, sizeof(className));
		Logp("窗口线程: %d \n 窗口句柄： %d \n 窗口类名:%s  \n 窗口标题:%s \n", winfo.tid, winfo.wndHw, className, windowTitle);
	}
	DWORD status_code = _ProtectProcess(protectPid, fakePid);
	if (status_code > 0)
	{
		Logp("%d \r\n", status_code);
		Logp("执行失败 错误码 %08x\n", status_code);
		return;
	}
	Logp("执行成功\n");
}

void ProtectWindow(ULONG32 hwnd)
{

	DWORD status_code = _ProtectWindow(hwnd);
	if (status_code > 0)
	{
		Logp("保护失败 错误码 %08x\n", status_code);
		return;
	}
	Logp("保护成功\n");
}
void AntiSnapShotWindow(ULONG32 hwnd)
{

	DWORD status_code = _AntiSnapShotWindow(hwnd);
	if (status_code > 0)
	{
		Logp("保护失败 错误码 %08x\n", status_code);
		return;
	}
	Logp("保护成功\n");
}
void QueryModule(ULONG pid, PCHAR szModuleName, UCHAR type)
{
	ULONG uModuleSize = 0;
	ULONG64 moduleBase = 0;
	printf("szModuleName %s \n", szModuleName);
	DWORD status_code = _QueryModule(pid, szModuleName, &moduleBase, &uModuleSize, type);
	if (status_code)
	{
		Logp("查询模块失败 错误码 %08x\n", status_code);
		return;
	}
	Logp("\n模块名: %s \n 模块基址: 0x%llx \n 模块大小: 0x%08x\n", szModuleName, moduleBase, uModuleSize);
}

void QueryVADModule(ULONG pid, PCHAR szModuleName)
{

	ULONG uModuleSize = 0;
	ULONG64 moduleBase = 0;

	DWORD status_code = _QueryVADModule(pid, szModuleName, &moduleBase, &uModuleSize);
	if (status_code)
	{
		Logp("查询模块失败 错误码 %08x\n", status_code);
		return;
	}
	Logp("\n模块名: %s \n 模块基址: 0x%llx \n 模块大小: 0x%08x\n", szModuleName, moduleBase, uModuleSize);
}

PUCHAR AllocateMem(ULONG PID, ULONG uDataSize)
{

	ULONG64 Addr = 0;
	DWORD status_code = _AllocateMem(PID, uDataSize, &Addr);
	if (status_code > 0)
	{
		Logp("申请内存失败 错误码 %08x\n", status_code);
		return;
	}
	Logp("申请到的内存地址:0x%llx\n", Addr);
	return Addr;
}

void CreateMyThread(ULONG PID, PUCHAR shellcode, ULONG len)
{
	ULONG64 address = 0;
	ULONG status = _AllocateMem(PID, len, &address);
	if (status)
	{
		return;
	}
	status = _PhyWriteMemory(PID, address, shellcode, len);
	if (status)
	{
		return;
	}


	status = _CreateMyThread(PID, address, NULL);
	if (status)
	{
		Logp("创建线程 错误码 %08x\n", status);
		return;
	}
	Logp("创建线程成功\n");

}

void SearchPattern(ULONG pid, PCHAR szModuleName, PCHAR pattern, PCHAR mask)
{
	UCHAR upattern[0x100] = { 0 };
	ConvertString2Pattern(pattern, mask, upattern);
	ULONG64 addr = 0;
	DWORD status_code = _SearchPattern(pid, szModuleName, upattern, mask, &addr);
	if (status_code)
	{
		Logp("SearchPattern 错误码 %08x\n", status_code);
		return;
	}
	Logp("SearchPattern 成功\n");
	Logp("特征地址： 0x%llx \r\n", addr);
	getchar();
}

void InjectX64DLL(ULONG pid, PCHAR dllFilePath,UCHAR type) {
 
	DWORD status_code =_InjectX64DLL(pid, dllFilePath,type);
	if (status_code > 0)
	{
		Logp("注入出错 错误码 %08x\n", status_code);
		return;
	}
}

void WriteX64DLL(ULONG PID, PCHAR dllFilePath)
{
 
	ULONG64 entryPoint = 0;
	ULONG64 imageBase = 0;
	ULONG64 kimageBase = 0;

	DWORD status_code =_WriteDLL(PID, dllFilePath,&entryPoint,&imageBase,&kimageBase);
 	if (status_code > 0)
	{
		Logp("写入DLL 出错 %08x\n", status_code);
		return;
	}
	Logp("写入DLL 成功 ");
	Logp("entryPoint 0x%llx \r\n", entryPoint);
	Logp("imageBase 0x%llx \r\n", imageBase);
	Logp("kimageBase 0x%llx \r\n",kimageBase);

}


void CALL_MAIN_THREAD(ULONG PID, ULONG64 shellcodeAddr, ULONG shellcodeLen) { 
	DWORD status_code = _CALL_MAIN_THREAD(PID, shellcodeAddr, shellcodeLen);
	if (status_code > 0)
	{
		Logp("写入DLL 出错 %08x\n", status_code);
		return;
	}
	Logp("执行成功");
}


void GetModuleExportAddr(ULONG pid, PCHAR ModuleName, PCHAR ExportFuncName) {

	ULONG64 FuncAddr;
 
	DWORD status_code = _GetModuleExportAddr2(pid, ModuleName, ExportFuncName,&FuncAddr);
	if (status_code > 0)
	{
		Logp("读取导出表方法 出错 %08x\n", status_code);
		return;
	}
	Logp("函数 %s ->  %s  :  0x%llx \r\n", ModuleName, ExportFuncName,  FuncAddr);

}

ULONG CHANGE_MEMORY_ATTR(ULONG PID, ULONG64 address, ULONG length) {

	DWORD status_code = _CHANGE_MEMORY_ATTR(PID, address, length);
	if (status_code > 0)
	{
		Logp("执行失败 %08x\n", status_code);
		return;
	}
	Logp("执行成功");
}
 