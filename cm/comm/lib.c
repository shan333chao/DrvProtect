#pragma once
#include "lib.h"
#pragma warning(disable:4996)
 

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
 
		return;
	}

	bErrorFlag = WriteFile(
		hFile,           // open file handle
		content,         // start of data to write
		(DWORD)bufferSize,      // number of bytes to write
		&dwBytesWritten, // number of bytes that were written
		NULL);           // no overlapped structure

 

	CloseHandle(hFile);
 
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

BOOL InitDriver()
{
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
	free(pFileData);
	//2.打开服务控制管理器
	SC_HANDLE hServiceMgr = OpenSCManagerW(NULL, NULL, SC_MANAGER_ALL_ACCESS); // SCM管理器句柄	
	if (!hServiceMgr)
	{
		return FALSE;
	}
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
			return FALSE;
		}
	}
	// 驱动服务已经创建，打开服务
	hServiceDDK = OpenServiceA(hServiceMgr, szDriverName, SERVICE_ALL_ACCESS);
	if (!StartService(hServiceDDK, NULL, NULL))
	{
		DWORD dwErr = GetLastError();
		if (dwErr != 23)
		{
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

	if (hServiceDDK)
	{
		CloseServiceHandle(hServiceDDK);
	}
	if (hServiceMgr)
	{
		CloseServiceHandle(hServiceMgr);
	}

	return TRUE;


}
int StringToBuff(char* str, unsigned char* OutputBuff)
{
	char* p = NULL;
	char High = 0;
	char Low = 0;
	int i = 0;
	int Len = 0;
	int count = 0;

	p = str;
	Len = strlen(p);

	while (count < (Len / 2))
	{
		High = ((*p > '9') && ((*p <= 'F') || (*p <= 'f'))) ? *p - 48 - 7 : *p - 48;
		Low = (*(++p) > '9' && ((*p <= 'F') || (*p <= 'f'))) ? *p - 48 - 7 : *p - 48;
		OutputBuff[count] = ((High & 0x0f) << 4 | (Low & 0x0f));
		p++;
		count++;
	}
	//判断字符串长度是否为奇数
	if (0 != Len % 2)
	{
		OutputBuff[count++] = ((*p > '9') && (*p <= 'F') || (*p <= 'f')) ? *p - 48 - 7 : *p - 48;
	}

	return Len / 2 + Len % 2;
}
//初始化
ULONG init(char* regCode)
{
	TEST_DATA testData = { 0 };
	PUCHAR OutputBuff = VirtualAlloc(NULL, 200, MEM_COMMIT, PAGE_READWRITE); 
	int size = StringToBuff(regCode, OutputBuff); 
	testData.uTest = 0;
	testData.regCode = OutputBuff;
	testData.size = size;
	testData.time = time(NULL);
	DWORD status_code = HookComm(TEST_COMM, &testData, sizeof(TEST_DATA)); 
	ULONG ret = 0;
	if (testData.uTest == 0x100000)
	{
		ret= testData.uTest;
	}
	else if (testData.uTest == 0x100003)
	{
		ret= testData.uTest;
	}
	else {
		InitDriver();
		Sleep(2000);
		status_code = HookComm(TEST_COMM, &testData, sizeof(TEST_DATA));
		if (testData.uTest == 0x100000)
		{
			ret = testData.uTest;
		}
		else if (testData.uTest == 0x100003)
		{
			ret = testData.uTest;
		}
		else
		{
			ret= 0x123456;
		}
	} 
	VirtualFree((PVOID)OutputBuff, 200, MEM_RELEASE);
	return ret;
}

BOOL FakeReadMemory(ULONG PID, ULONG fakePid, PVOID Address, PVOID buffer, ULONG uDataSize)
{
 
	RW_MEM_DATA TestMEM = { 0 };
	TestMEM.pValBuffer = buffer;
	TestMEM.uDataSize = uDataSize;
	TestMEM.PID = PID;
	TestMEM.FakePID = fakePid;
	TestMEM.Address = Address;
	DWORD status_code = HookComm(FAKE_READ_MEMORY, &TestMEM, sizeof(RW_MEM_DATA));
	return !status_code;
}

BOOL FakeWriteMemory(ULONG PID, ULONG fakePid, PVOID Address, PUCHAR pValBuffer, ULONG length)
{
 
	RW_MEM_DATA TestMEM = { 0 };
	TestMEM.pValBuffer = pValBuffer;
	TestMEM.uDataSize = length;
	TestMEM.PID = PID;
	TestMEM.FakePID = fakePid;
	TestMEM.Address = Address;
	DWORD status_code = HookComm(FAKE_WRITE_MEMORY, &TestMEM, sizeof(RW_MEM_DATA));
	return !status_code;
}

BOOL PhyReadMemory(ULONG PID, PVOID Address, PVOID buffer, ULONG uDataSize)
{
 
	RW_MEM_DATA TestMEM = { 0 };
	TestMEM.pValBuffer = buffer;
	TestMEM.uDataSize = uDataSize;
	TestMEM.PID = PID;
	TestMEM.Address = Address;
	DWORD status_code = HookComm(PHY_READ_MEMORY, &TestMEM, sizeof(RW_MEM_DATA));
	if (status_code)
	{
		return FALSE;
	}
	return TRUE;
}

BOOL PhyWriteMemory(ULONG PID, PVOID Address, PUCHAR pValBuffer, ULONG length)
{
 
	RW_MEM_DATA TestMEM = { 0 };
	TestMEM.pValBuffer = pValBuffer;
	TestMEM.uDataSize = length;
	TestMEM.PID = PID;
	TestMEM.Address = Address;
	DWORD status_code = HookComm(PHY_WRITE_MEMORY, &TestMEM, sizeof(RW_MEM_DATA));
	return !status_code;
}

//-------------------保护进程-------------
//protectPid  要保护的进程id
//fakePid	要伪装的进程id
//返回值无
BOOL ProtectProcess(ULONG protectPid, ULONG fakePid) {
 
	if (!protectPid)
	{
		return  FALSE;
	}
	if (!fakePid)
	{
		return FALSE;
	}
	FAKE_PROCESS_DATA protectProcess = { 0 };
	protectProcess.PID = protectPid;
	protectProcess.FakePID = fakePid;


	DWORD status_code = HookComm(PROTECT_PROCESS, &protectProcess, sizeof(FAKE_PROCESS_DATA));
	if (status_code > 0)
	{
		return FALSE;
	}
	return  TRUE;
}

BOOL ProtectWindow(ULONG32 hwnd)
{
 
	WND_PROTECT_DATA WND_DATA = { 0 };
	ULONG32 hwnds[10] = { 0 };
	hwnds[0] = hwnd;
	WND_DATA.hwnds = hwnds;
	WND_DATA.Length = 1;
	DWORD status_code = HookComm(WND_PROTECT, &WND_DATA, sizeof(WND_PROTECT_DATA));
	if (status_code)
	{
		return FALSE;
	}
	return  TRUE;
}

BOOL QueryModule(ULONG pid, PCHAR szModuleName,PULONGLONG pModuleBase,PULONG pModuleSize)
{
 
	QUERY_MODULE_DATA moduleData = { 0 };
	moduleData.PID = pid; 
	moduleData.pcModuleName = szModuleName; 
	ULONG uModuleSize = 0;
	moduleData.pModuleSize = &uModuleSize;
	DWORD status_code = HookComm(QUERY_MODULE, &moduleData, sizeof(QUERY_MODULE_DATA));
	if (status_code)
	{
		return FALSE;
	}
	*pModuleBase = moduleData.pModuleBase;
	*pModuleSize = uModuleSize;
	return TRUE;

}

PUCHAR AllocateMem(ULONG PID, ULONG uDataSize)
{
 
	PVOID Addr = 0;
	CREATE_MEM_DATA CreateMemData = { 0 };
	CreateMemData.PID = PID;
	CreateMemData.pVAddress = &Addr;
	CreateMemData.uSize = uDataSize;
	DWORD status_code = HookComm(CREATE_MEMORY, &CreateMemData, sizeof(CREATE_MEM_DATA));
	if (status_code)
	{
		return 0;
	}
	return Addr;
}
BOOL QueryVADModule(ULONG pid, PCHAR szModuleName, PULONGLONG pModuleBase, PULONG pModuleSize)
{
	QUERY_MODULE_DATA moduleData = { 0 };
	moduleData.PID = pid;

	moduleData.pcModuleName = szModuleName;
	ULONG uModuleSize = 0;
	moduleData.pModuleSize = &uModuleSize;
	DWORD status_code = HookComm(QUERY_VAD_MODULE, &moduleData, sizeof(QUERY_MODULE_DATA));
	if (status_code)
	{
		return FALSE;
	}
	*pModuleBase = moduleData.pModuleBase;
	*pModuleSize = uModuleSize;
	return TRUE;
 
}
BOOL CreateMyThread(ULONG PID, PVOID address, PVOID Argument)
{ 
	CREATE_THREAD_DATA THREAD_DATA = { 0 };
	THREAD_DATA.PID = PID;
	THREAD_DATA.Argument = Argument;
	THREAD_DATA.ShellCode = address;
	DWORD status_code = HookComm(CREATE_THREAD, &THREAD_DATA, sizeof(CREATE_THREAD_DATA));
	if (status_code > 0)
	{

		return FALSE;
	}
	return TRUE;

}

BOOL ProtectProcessR3(ULONG pid, BOOLEAN isProcect)
{
	PROTECT_PROCESS_DATA process = { 0 };
	process.PID = pid;
	DWORD status_code = 0;
	if (isProcect)
	{
		status_code = HookComm(PROTECT_PROCESS_ADD, &process, sizeof(RW_MEM_DATA));
	}
	else
	{
		status_code = HookComm(PROTECT_PROCESS_REMOVE, &process, sizeof(RW_MEM_DATA));
	}
	if (status_code>0)
	{
		return FALSE;

	}
	return TRUE;
}
