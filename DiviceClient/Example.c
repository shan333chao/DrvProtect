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
			// �ҵ����̵������ھ��
			windowInfo->wndHw = hwnd;
			windowInfo->tid = threadid;
			return FALSE; // ���� FALSE ֹͣö��
		}
	}
	return TRUE; // ���� TRUE ����ö��
}

#include <windows.h>




//-------------------����ͨѶ
void TestComm(PVOID regCode)
{
	DWORD status_code = _InitReg(regCode);
	switch (status_code)
	{
	case STATUS_TEST_COMM_SUCCESS:
		Logp("����ͨѶ�ɹ���\n");
		break;
	case STATUS_TEST_COMM_REG_EXPIRED:
		Logp("���ܹ��ڣ�\n");
		break;
	case STATUS_TEST_COMM_REG_INVALID:
		Logp("��Ч���ܣ�\n");
		break;
	case STATUS_TEST_COMM_UNREG_OR_EXPIRED:
		Logp("δע�Ῠ�ܻ�ȡ������");
		break;
	case STATUS_TEST_COMM_MISS_DRIVE_FILE:
		Logp("������ʧ");
		break;
	case STATUS_TEST_COMM_CREATE_SERVICE_KEY:
		Logp("����ע���ʧ��");
		break;
	case STATUS_TEST_COMM_GETMODULEHANDLEA:
		Logp("��ȡģ��ʧ��");
		break;
	case STATUS_TEST_COMM_SE_LOAD_DRIVER_PRIVILEGE:
		Logp("��Ȩʧ��");
		break;
	case STATUS_TEST_COMM_CREATE_SERVICE:
		Logp("������������ʧ��, %d");
		break;
	case STATUS_TEST_COMM_OPEN_SCMANAGER:
		Logp("OpenSCManagerW ʧ��, %d\n", GetLastError());
		break;
	default:
		Logp("δ֪����");
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
		Logp("��ȡ����  ������%08x:\n", status_code);
		return;
	}
	Logp("����������:\n");
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
		Logp("д��ɹ�:\n");
	}
	else {
		Logp("д��ʧ�� %08x:\n", status_code);
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

//-------------------��������-------------
//protectPid  Ҫ�����Ľ���id
//fakePid	Ҫαװ�Ľ���id
//����ֵ��
void ProtectProcess(ULONG protectPid, ULONG fakePid) {
	if (!protectPid)
	{
		Logp("Ҫ�����Ľ���PID Ϊ��\n");
		return;
	}
	if (!fakePid)
	{
		Logp("Ҫαװ�Ľ���PID Ϊ��\n");
		return;
	}
	FWindowInfo winfo = { 0 };
	winfo.pid = protectPid;
	EnumWindows(EnumWindowsProc, &winfo);
	if (winfo.wndHw)
	{
		char className[256] = { 0 };
		char windowTitle[256] = { 0 };
		GetWindowTextA(winfo.wndHw, windowTitle, sizeof(windowTitle));  // ��ȡ���ڱ���
		GetClassNameA(winfo.wndHw, className, sizeof(className));
		Logp("�����߳�: %d \n ���ھ���� %d \n ��������:%s  \n ���ڱ���:%s \n", winfo.tid, winfo.wndHw, className, windowTitle);
	}
	DWORD status_code = _ProtectProcess(protectPid, fakePid);
	if (status_code > 0)
	{
		Logp("%d \r\n", status_code);
		Logp("ִ��ʧ�� ������ %08x\n", status_code);
		return;
	}
	Logp("ִ�гɹ�\n");
}

void ProtectWindow(ULONG32 hwnd)
{

	DWORD status_code = _ProtectWindow(hwnd);
	if (status_code > 0)
	{
		Logp("����ʧ�� ������ %08x\n", status_code);
		return;
	}
	Logp("�����ɹ�\n");
}
void AntiSnapShotWindow(ULONG32 hwnd)
{

	DWORD status_code = _AntiSnapShotWindow(hwnd);
	if (status_code > 0)
	{
		Logp("����ʧ�� ������ %08x\n", status_code);
		return;
	}
	Logp("�����ɹ�\n");
}
void QueryModule(ULONG pid, PCHAR szModuleName, UCHAR type)
{
	ULONG uModuleSize = 0;
	ULONG64 moduleBase = 0;
	printf("szModuleName %s \n", szModuleName);
	DWORD status_code = _QueryModule(pid, szModuleName, &moduleBase, &uModuleSize, type);
	if (status_code)
	{
		Logp("��ѯģ��ʧ�� ������ %08x\n", status_code);
		return;
	}
	Logp("\nģ����: %s \n ģ���ַ: 0x%llx \n ģ���С: 0x%08x\n", szModuleName, moduleBase, uModuleSize);
}

void QueryVADModule(ULONG pid, PCHAR szModuleName)
{

	ULONG uModuleSize = 0;
	ULONG64 moduleBase = 0;

	DWORD status_code = _QueryVADModule(pid, szModuleName, &moduleBase, &uModuleSize);
	if (status_code)
	{
		Logp("��ѯģ��ʧ�� ������ %08x\n", status_code);
		return;
	}
	Logp("\nģ����: %s \n ģ���ַ: 0x%llx \n ģ���С: 0x%08x\n", szModuleName, moduleBase, uModuleSize);
}

PUCHAR AllocateMem(ULONG PID, ULONG uDataSize)
{

	ULONG64 Addr = 0;
	DWORD status_code = _AllocateMem(PID, uDataSize, &Addr);
	if (status_code > 0)
	{
		Logp("�����ڴ�ʧ�� ������ %08x\n", status_code);
		return;
	}
	Logp("���뵽���ڴ��ַ:0x%llx\n", Addr);
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
		Logp("�����߳� ������ %08x\n", status);
		return;
	}
	Logp("�����̳߳ɹ�\n");

}

void SearchPattern(ULONG pid, PCHAR szModuleName, PCHAR pattern, PCHAR mask)
{
	UCHAR upattern[0x100] = { 0 };
	ConvertString2Pattern(pattern, mask, upattern);
	ULONG64 addr = 0;
	DWORD status_code = _SearchPattern(pid, szModuleName, upattern, mask, &addr);
	if (status_code)
	{
		Logp("SearchPattern ������ %08x\n", status_code);
		return;
	}
	Logp("SearchPattern �ɹ�\n");
	Logp("������ַ�� 0x%llx \r\n", addr);
	getchar();
}

void InjectX64DLL(ULONG pid, PCHAR dllFilePath,UCHAR type) {
 
	DWORD status_code =_InjectX64DLL(pid, dllFilePath,type);
	if (status_code > 0)
	{
		Logp("ע����� ������ %08x\n", status_code);
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
		Logp("д��DLL ���� %08x\n", status_code);
		return;
	}
	Logp("д��DLL �ɹ� ");
	Logp("entryPoint 0x%llx \r\n", entryPoint);
	Logp("imageBase 0x%llx \r\n", imageBase);
	Logp("kimageBase 0x%llx \r\n",kimageBase);

}


void CALL_MAIN_THREAD(ULONG PID, ULONG64 shellcodeAddr, ULONG shellcodeLen) { 
	DWORD status_code = _CALL_MAIN_THREAD(PID, shellcodeAddr, shellcodeLen);
	if (status_code > 0)
	{
		Logp("д��DLL ���� %08x\n", status_code);
		return;
	}
	Logp("ִ�гɹ�");
}


void GetModuleExportAddr(ULONG pid, PCHAR ModuleName, PCHAR ExportFuncName) {

	ULONG64 FuncAddr;
 
	DWORD status_code = _GetModuleExportAddr2(pid, ModuleName, ExportFuncName,&FuncAddr);
	if (status_code > 0)
	{
		Logp("��ȡ�������� ���� %08x\n", status_code);
		return;
	}
	Logp("���� %s ->  %s  :  0x%llx \r\n", ModuleName, ExportFuncName,  FuncAddr);

}

ULONG CHANGE_MEMORY_ATTR(ULONG PID, ULONG64 address, ULONG length) {

	DWORD status_code = _CHANGE_MEMORY_ATTR(PID, address, length);
	if (status_code > 0)
	{
		Logp("ִ��ʧ�� %08x\n", status_code);
		return;
	}
	Logp("ִ�гɹ�");
}
 