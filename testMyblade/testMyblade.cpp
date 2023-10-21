// testMyblade.cpp : 此文件包含 "main" 函数。程序执行将在此处开始并结束。
//

#include <iostream>
#include <Windows.h>
#include "../SSS_Drivers/ERROR_CODE.h"



HMODULE dllModule = LoadLibraryA("C:\\DriverCodes\\HideDriver\\NickolasZhao\\x64\\Release\\SSS_dll_x64.dll");




/// <summary>
/// 反截图
/// hwnd 窗口句柄
/// </summary>
typedef ULONG(*AntiSnapShotWindow) (ULONG32 hwnd);
/// <summary>
/// 保护窗口
/// hwnd 窗口句柄
/// </summary>
typedef ULONG(*ProtectWindow) (ULONG32 hwnd);
/// <summary>
/// r3保护进程
/// hwnd 进程id
/// </summary>
typedef ULONG(*AddProtectProcessR3)(ULONG pid);

/// <summary>
/// 进程伪装
/// protectPid  自己的进程id
/// fakePid  要伪装的进程id
/// </summary>
typedef ULONG(*FakeProcess)(ULONG protectPid, ULONG fakePid);

/// <summary>
/// 
/// </summary> 


typedef ULONG(*ReadMemory)(ULONG PID, PVOID Address, PVOID buffer, ULONG length);
VOID ReadMemExample() { 

	ReadMemory read_memory = (ReadMemory)GetProcAddress(dllModule, "_PhyReadMemory"); 
	ULONG pid = 7816;
	PVOID address = (PVOID)0x400000;
	ULONG length = sizeof(ULONG);
	ULONG buffer = 0;
	ULONG ret = read_memory(pid, address, (PVOID)&buffer, length);
	if (!ret)
	{
		printf("读到的数据 %08x \n", buffer);

	}
	else {
		printf("读取出错 错误码%08x \n", ret);
		return;
	} 
}


typedef ULONG(*WriteMemory)(ULONG PID, PVOID Address, PVOID pValBuffer, ULONG length);
VOID WriteMemExample() {
	WriteMemory write_memory=(WriteMemory)GetProcAddress(dllModule, "_PhyWriteMemory");
	ULONG pid = 7816;
	PVOID address = (PVOID)0x400000;
	ULONG length = sizeof(ULONG);
	ULONG buffer = 0xcc;

	ULONG ret= write_memory(pid,address,(PVOID)buffer,length);
	if (!ret)
	{
		printf("写入成功 \n");
	}



}

//注册并初始化 
typedef ULONG(*InitReg)(PCHAR regCode);
void RegExample() {
	InitReg reg = (InitReg)GetProcAddress(dllModule, "_InitReg");

	AntiSnapShotWindow antiSnapshot = (AntiSnapShotWindow)GetProcAddress(dllModule, "_AntiSnapShotWindow");

	ProtectWindow protectWindow = (ProtectWindow)GetProcAddress(dllModule, "_ProtectWindow");

	AddProtectProcessR3  r3ProcessDeny = (AddProtectProcessR3)GetProcAddress(dllModule, "_ProtectProcessR3_Add");

	FakeProcess  fakeProcess = (FakeProcess)GetProcAddress(dllModule, "_ProtectProcess");


	char code[] = "e120c826168d9828624d13355aa5b9ce8959ed0698ff16efc56ef05388356c1fe6cb16a48afe3a01ba021bb1bd9465b48f96";
	//该方法仅需调用一次
	ULONG ret = reg(code);
	if (ret == STATUS_TEST_COMM_SUCCESS)
	{
		printf("初始化成功");
	}
	else
	{
		printf("初始化失败 %08x \n", ret);
		return;
	}

}

int main()
{
	RegExample();
	WriteMemExample();
	ReadMemExample();


 




	getchar();

 
}

