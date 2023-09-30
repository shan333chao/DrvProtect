#pragma once
#define _CRT_SECURE_NO_WARNINGS
#include "Example.h"
#include <stdio.h>
#include <ntstatus.h>
#include <stdio.h>
#include <string.h>
#include "aes.h"
#include <time.h>
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



void SearchFiles(const char* path, const char* fileName, const char* pattern)
{
	WIN32_FIND_DATAA searchData;
	HANDLE hFind;

	// 构建搜索模式
	char searchPattern[MAX_PATH];
	sprintf(searchPattern, "%s\\*", path);

	// 开始搜索
	hFind = FindFirstFileA(searchPattern, &searchData);
	if (hFind != INVALID_HANDLE_VALUE)
	{
		do
		{
			// 检查文件类型
			if (!(searchData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY))
			{
				// 检查文件名是否包含目标字符串
				char* found = strstr(searchData.cFileName, pattern);
				if (found != NULL)
				{
					// 构建完整路径
					//char filePath[MAX_PATH];
					sprintf(path, "%s\\%s", path, searchData.cFileName);
					sprintf(fileName, "%s", searchData.cFileName);

				}
			}
		} while (FindNextFileA(hFind, &searchData) != 0);

		// 关闭句柄
		FindClose(hFind);
	}
}

void writeFile(char* filename, unsigned char* content, size_t bufferSize) {
	HANDLE hFile;
	DWORD dwBytesWritten = 0;
	BOOL bErrorFlag = FALSE;

	hFile = CreateFileA((LPCSTR)filename, // name of the file
		GENERIC_WRITE,                    // open for writing
		0,                                // do not share
		NULL,                             // default security
		CREATE_ALWAYS,                    // always override file
		FILE_ATTRIBUTE_NORMAL,            // normal file
		NULL);                            // no attr. template

	if (hFile == INVALID_HANDLE_VALUE) {
		printf("[-] Failed to access: %s\n", (char*)filename);
		return;
	}

	bErrorFlag = WriteFile(
		hFile,           // open file handle
		content,         // start of data to write
		(DWORD)bufferSize,      // number of bytes to write
		&dwBytesWritten, // number of bytes that were written
		NULL);           // no overlapped structure

	if (FALSE == bErrorFlag) {
		printf("[-] Unable to write into file.\n");
	}

	CloseHandle(hFile);
	printf("[*] %s file created.\n", filename);
}
char* GenerateRandomString(int length) {
	char* randomString = (char*)malloc((length + 1) * sizeof(char));
	if (randomString == NULL) {
		return NULL;
	}

	char characters[] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";

	srand((unsigned int)time(NULL));

	for (int i = 0; i < length; i++) {
		int randomIndex = rand() % (sizeof(characters) - 1);
		randomString[i] = characters[randomIndex];
	}

	randomString[length] = '\0';

	return randomString;
}

void InitDriver()
{


	//char currentPath[MAX_PATH] = { 0 };
	//GetCurrentDirectoryA(MAX_PATH, currentPath);
	//char szDriverName[20] = "ProxyDrv_nodbg";
	//char szDriverPath[20] = "ProxyDrv_nodbg.sys"; 
	////1.获取驱动文件全路径名
	//CHAR szDriverFullPath[MAX_PATH] = { 0 };		//MAX_PATH 0x260
	//GetFullPathNameA(szDriverPath, MAX_PATH, szDriverFullPath, NULL);

	char szDriverFullPath[MAX_PATH];
	GetCurrentDirectoryA(MAX_PATH, szDriverFullPath);
	char szDriverName[MAX_PATH] = { 0 };
	SearchFiles(szDriverFullPath, szDriverName, ".png");


	FILE* pfile = NULL;
	long lFileSize = 0;
	unsigned char* pFileData = NULL;
	fopen_s(&pfile, szDriverFullPath, "rb");
	if (!pfile)
	{
		printf("fopen_s file failed 1");
		return 0;
	}

	//获取文件长度
	fseek(pfile, 0, SEEK_END);
	lFileSize = ftell(pfile);
	fseek(pfile, 0, SEEK_SET);
	//获取文件数据
	pFileData = malloc(lFileSize);
	if (!pFileData)
	{
		fclose(pfile);
		printf("malloc failed \r\n");
		return 0;
	}
	memset(pFileData, 0, lFileSize);
	fread_s(pFileData, lFileSize, lFileSize, 1, pfile);
	//关闭文件
	fclose(pfile);
	unsigned char key[17] = { 0 };
	unsigned char iv[17] = { 0 };
	memcpy(key, pFileData + 4, 17);
	memcpy(iv, pFileData + 4 + 17, 17);

	PUCHAR mfile = pFileData + 4 + 17 + 17;
	struct AES_ctx ctx = { 0 };
	AES_init_ctx_iv(&ctx, key, iv);
	int dumpFileLen = lFileSize - 4 - 17 - 17;
	AES_CTR_xcrypt_buffer(&ctx, (uint8_t*)mfile, dumpFileLen);

	PCHAR loadFileName = GenerateRandomString(10);
	writeFile(loadFileName, mfile, dumpFileLen);

	memset(szDriverFullPath, 0, MAX_PATH);
	GetCurrentDirectoryA(MAX_PATH, szDriverFullPath);
	memset(szDriverName, 0, MAX_PATH);
	SearchFiles(szDriverFullPath, szDriverName, loadFileName);

	//2.打开服务控制管理器
	SC_HANDLE hServiceMgr = OpenSCManagerW(NULL, NULL, SC_MANAGER_ALL_ACCESS); // SCM管理器句柄	
	if (!hServiceMgr)
	{
		printf("OpenSCManagerW 失败, %d\n", GetLastError());
		return FALSE;
	}
	printf("打开服务控制管理器成功.\n");


	//3.创建驱动服务
	SC_HANDLE hServiceDDK = NULL; // NT驱动程序服务句柄
	//创建驱动服务
	hServiceDDK = CreateServiceA(
		hServiceMgr,
		szDriverName,//驱动程序注册表中的名字
		szDriverName,//注册表中驱动程序的 DisPlayName 的值
		SERVICE_ALL_ACCESS,//加载驱动的访问权限 SERVICE_START 或 SERVICE_ALL_ACCESS
		SERVICE_KERNEL_DRIVER,//表示加载服务是驱动程序
		SERVICE_DEMAND_START,//注册表驱动程序的 Start 值
		SERVICE_ERROR_IGNORE,//注册表程序的 ErrorControl 值
		szDriverFullPath,
		NULL, NULL, NULL, NULL, NULL
	);

	if (!hServiceDDK)
	{
		DWORD dwErr = GetLastError();
		if (dwErr != ERROR_IO_PENDING && dwErr != ERROR_SERVICE_EXISTS)
		{
			printf("创建驱动服务失败, %d\n", dwErr);
			return FALSE;
		}
	}
	printf("创建驱动服务成功.\n");
	// 驱动服务已经创建，打开服务
	hServiceDDK = OpenServiceA(hServiceMgr, szDriverName, SERVICE_ALL_ACCESS);
	if (!StartService(hServiceDDK, NULL, NULL))
	{
		DWORD dwErr = GetLastError();
		if (dwErr != 23)
		{
			printf("运行驱动服务失败, %d\n", dwErr);
			if (hServiceDDK)
			{
				CloseServiceHandle(hServiceDDK);
			}
			if (hServiceMgr)
			{
				CloseServiceHandle(hServiceMgr);
			}
			return FALSE;
		}
	}
	printf("运行驱动服务成功.\n");
	if (hServiceDDK)
	{
		CloseServiceHandle(hServiceDDK);
	}
	if (hServiceMgr)
	{
		CloseServiceHandle(hServiceMgr);
	}
	//清理驱动在r3的加载痕迹
	//clear_trace(L"DisapperDriver.sys", driverStamp);
	return TRUE;


}

//-------------------测试通讯
void TestComm(PVOID regCode, ULONG size)
{
	TEST_DATA testData = { 0 };
	testData.uTest = 0;
	testData.regCode = regCode;
	testData.size = size;
	testData.time = time(NULL);
	DWORD status_code = DriverComm(TEST_COMM, &testData, sizeof(TEST_DATA));
	if (testData.uTest == 0x100000)
	{
		printf("测试通讯成功！\n");
	}
	else if (testData.uTest == 0x100003)
	{
		printf("卡密过期！\n");
	}
	else {
		printf("测试通讯失败 正在安裝驱动！\n");
		InitDriver();
	}

}

void FakeReadMemory(ULONG PID, ULONG fakePid, PVOID Address, ULONG uDataSize)
{
	RW_MEM_DATA TestMEM = { 0 };
	TestMEM.pValBuffer = VirtualAlloc(NULL, uDataSize, MEM_COMMIT, PAGE_READWRITE);
	memset(TestMEM.pValBuffer, 0, uDataSize);
	TestMEM.uDataSize = uDataSize;
	TestMEM.PID = PID;
	TestMEM.FakePID = fakePid;
	TestMEM.Address = Address;
	DWORD status_code = DriverComm(FAKE_READ_MEMORY, &TestMEM, sizeof(RW_MEM_DATA));
	PUCHAR data = TestMEM.pValBuffer;
	printf("读到的数据:\n");
	for (size_t i = 0; i < uDataSize; i++)
	{
		if (!(i % 16))
		{
			printf("\n");
		}
		printf("%02x ", data[i]);
	}
	printf("\n");
	VirtualFree(TestMEM.pValBuffer, 0, MEM_RELEASE);

}

void FakeWriteMemory(ULONG PID, ULONG fakePid, PVOID Address, PUCHAR pValBuffer, ULONG length)
{
	RW_MEM_DATA TestMEM = { 0 };
	TestMEM.pValBuffer = pValBuffer;
	TestMEM.uDataSize = length;
	TestMEM.PID = PID;
	TestMEM.FakePID = fakePid;
	TestMEM.Address = Address;

	DWORD status_code = DriverComm(FAKE_WRITE_MEMORY, &TestMEM, sizeof(RW_MEM_DATA));
	if (!status_code)
	{
		printf("写入成功:\n");
	}
	else {
		printf("写入失败 %08x:\n", status_code);
	}


}

void PhyReadMemory(ULONG PID, PVOID Address, ULONG uDataSize)
{
	RW_MEM_DATA TestMEM = { 0 };
	PUCHAR data = VirtualAlloc(NULL, uDataSize, MEM_COMMIT, PAGE_READWRITE);
	memset(data, 0, uDataSize);
	TestMEM.pValBuffer = data;
	TestMEM.uDataSize = uDataSize;
	TestMEM.PID = PID;
	TestMEM.Address = Address;
	DWORD status_code = DriverComm(PHY_READ_MEMORY, &TestMEM, sizeof(RW_MEM_DATA));
	if (status_code)
	{
		VirtualFree(TestMEM.pValBuffer, 0, MEM_RELEASE);
		printf("读取出错  错误码%08x:\n", status_code);
		return;
	}
	printf("读到的数据:\n");
	for (size_t i = 0; i < uDataSize; i++)
	{
		if (!(i % 16))
		{
			printf("\n");
		}
		printf("%02x ", data[i]);
	}
	printf("\n");
	VirtualFree(TestMEM.pValBuffer, 0, MEM_RELEASE);
}

BOOL PhyWriteMemory(ULONG PID, PVOID Address, PUCHAR pValBuffer, ULONG length)
{
	RW_MEM_DATA TestMEM = { 0 };
	TestMEM.pValBuffer = pValBuffer;
	TestMEM.uDataSize = length;
	TestMEM.PID = PID;
	TestMEM.Address = Address;
	DWORD status_code = DriverComm(PHY_WRITE_MEMORY, &TestMEM, sizeof(RW_MEM_DATA));
	if (!status_code)
	{
		printf("写入成功:\n");
	}
	else {
		printf("写入失败 %08x:\n", status_code);
	}
	return !status_code;
}

//-------------------保护进程-------------
//protectPid  要保护的进程id
//fakePid	要伪装的进程id
//返回值无
void ProtectProcess(ULONG protectPid, ULONG fakePid) {
	if (!protectPid)
	{
		printf("要保护的进程PID 为空\n");
		return;
	}
	if (!fakePid)
	{
		printf("要伪装的进程PID 为空\n");
		return;
	}
	FAKE_PROCESS_DATA protectProcess = { 0 };
	protectProcess.PID = protectPid;
	protectProcess.FakePID = fakePid;
	printf("保护进程： %d \n  \n", protectProcess.PID);
	FWindowInfo winfo = { 0 };
	winfo.pid = protectPid;

	EnumWindows(EnumWindowsProc, &winfo);
	if (winfo.wndHw)
	{
		char className[256] = { 0 };
		char windowTitle[256] = { 0 };
		GetWindowTextA(winfo.wndHw, windowTitle, sizeof(windowTitle));  // 获取窗口标题
		GetClassNameA(winfo.wndHw, className, sizeof(className));
		printf("窗口线程: %d \n 窗口句柄： %d \n 窗口类名:%s  \n 窗口标题:%s \n", winfo.tid, winfo.wndHw, className, windowTitle);
	}
	DWORD status_code = DriverComm(PROTECT_PROCESS, &protectProcess, sizeof(FAKE_PROCESS_DATA));
	if (status_code > 0)
	{
		printf("%d \r\n", status_code);
		printf("执行失败 错误码 %08x\n", status_code);
		return;
	}
	printf("执行成功\n");
}

void ProtectWindow(ULONG32 hwnd)
{
	WND_PROTECT_DATA WND_DATA = { 0 };
	ULONG32 hwnds[10] = { 0 };
	hwnds[0] = hwnd;
	WND_DATA.hwnds = hwnds;
	WND_DATA.Length = 1;
	DWORD status_code = DriverComm(WND_PROTECT, &WND_DATA, sizeof(WND_PROTECT_DATA));
	if (status_code > 0)
	{
		printf("保护失败 错误码 %08x\n", status_code);
		return;
	}
	printf("保护成功\n");
}

void QueryModule(ULONG pid, PCHAR szModuleName)
{
	QUERY_MODULE_DATA moduleData = { 0 };
	moduleData.PID = pid;

	moduleData.pcModuleName = szModuleName;
	ULONG uModuleSize = 0;
	moduleData.pModuleSize = &uModuleSize;
	DWORD status_code = DriverComm(QUERY_MODULE, &moduleData, sizeof(QUERY_MODULE_DATA));
	if (status_code)
	{
		printf("查询模块失败 错误码 %08x\n", status_code);
		return;
	}
	printf("\n模块名: %s \n 模块基址: 0x%p \n 模块大小: 0x%08x\n", szModuleName, moduleData.pModuleBase, uModuleSize);

}

void QueryVADModule(ULONG pid, PCHAR szModuleName)
{
	QUERY_MODULE_DATA moduleData = { 0 };
	moduleData.PID = pid;

	moduleData.pcModuleName = szModuleName;
	ULONG uModuleSize = 0;
	moduleData.pModuleSize = &uModuleSize;
	DWORD status_code = DriverComm(QUERY_VAD_MODULE, &moduleData, sizeof(QUERY_MODULE_DATA));
	if (status_code)
	{
		printf("查询模块失败 错误码 %08x\n", status_code);
		return;
	}
	printf("\n模块名: %s \n 模块基址: 0x%p \n 模块大小: 0x%08x\n", szModuleName, moduleData.pModuleBase, uModuleSize);
}

PUCHAR AllocateMem(ULONG PID, ULONG uDataSize)
{

	PVOID Addr = 0;
	CREATE_MEM_DATA CreateMemData = { 0 };
	CreateMemData.PID = PID;

	CreateMemData.pVAddress = &Addr;
	CreateMemData.uSize = uDataSize;

	DWORD status_code = DriverComm(CREATE_MEMORY, &CreateMemData, sizeof(CREATE_MEM_DATA));
	if (status_code > 0)
	{
		printf("申请内存失败 错误码 %08x\n", status_code);
		return;
	}
	printf("申请到的内存地址:0x%p\n", Addr);
	return Addr;
}

void CreateMyThread(ULONG PID, PUCHAR shellcode, ULONG len)
{

	PUCHAR address = AllocateMem(PID, len);
	if (!address)
	{
		return;
	}
	BOOL isok = PhyWriteMemory(PID, address, shellcode, len);
	if (!isok)
	{
		return;
	}

	CREATE_THREAD_DATA THREAD_DATA = { 0 };
	THREAD_DATA.PID = PID;
	THREAD_DATA.Argument = NULL;
	THREAD_DATA.ShellCode = address;
	DWORD status_code = DriverComm(CREATE_THREAD, &THREAD_DATA, sizeof(CREATE_THREAD_DATA));
	if (status_code > 0)
	{
		printf("创建线程 错误码 %08x\n", status_code);
		return;
	}
	printf("创建线程成功\n");

}
