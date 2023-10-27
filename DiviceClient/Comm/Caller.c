#pragma once
#include "Caller.h"
#include "CommR3.h"
#include <stdio.h>
#include "../aes.h"
#include "../../SSS_Drivers/ERROR_CODE.h"
#include "../driver_shellcode.h"
#include "../log.h"
#pragma warning(disable:4996)
#include "../service/Service.h"
#include "../ntp_client/ntp_client.h"
#include "../service/CreateThread64.h"

ULONG writeFile2(char* filename, unsigned char* content, size_t bufferSize) {
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
		Logp("[-] Failed to access: %s\n", (char*)filename);
		return STATUS_TEST_COMM_MISS_DRIVE_FILE;
	}

	bErrorFlag = WriteFile(
		hFile,           // open file handle
		content,         // start of data to write
		(DWORD)bufferSize,      // number of bytes to write
		&dwBytesWritten, // number of bytes that were written
		NULL);           // no overlapped structure
	CloseHandle(hFile);
	if (FALSE == bErrorFlag) {
		return STATUS_TEST_COMM_MISS_DRIVE_FILE;
	}
	Logp("[*] %s file created.\n", filename);
	return STATUS_OP_SUCCESS;
}

//生成随机字符串
void GenerateRandomString2(PCHAR randomString, int length) {
	char characters[] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
	srand((unsigned int)time(NULL));
	for (int i = 0; i < length; i++) {
		int randomIndex = rand() % (sizeof(characters) - 1);
		randomString[i] = characters[randomIndex];
	}
	randomString[length] = '\0';

}


//安装驱动
ULONG InstallDriver2()
{
	ULONG status = 0;
	unsigned char key[17] = { 0 };
	unsigned char iv[17] = { 0 };

	memcpy(key, fileData + 4, 17);
	memcpy(iv, fileData + 4 + 17, 17);
	PUCHAR mfile = fileData + 4 + 17 + 17;
	struct AES_ctx ctx = { 0 };
	AES_init_ctx_iv(&ctx, key, iv);
	int dumpFileLen = FILE_LEN - 4 - 17 - 17;
	AES_CTR_xcrypt_buffer(&ctx, (uint8_t*)mfile, dumpFileLen);
	int namelen = 10;
	char* szDriverName = (char*)malloc((namelen + 1) * sizeof(char));
	memset(szDriverName, 0, namelen);
	GenerateRandomString2(szDriverName, namelen);
	char szDriverFullPath[MAX_PATH];
	GetCurrentDirectoryA(MAX_PATH, szDriverFullPath);
	sprintf(szDriverFullPath, "%s\\%s", szDriverFullPath, szDriverName);
	status = writeFile2(szDriverFullPath, mfile, dumpFileLen);

	if (status > 0)
	{
		free(szDriverName);
		return status;
	}

#ifdef _X86
	status = CreateServiceAndStartX86(szDriverFullPath, szDriverName);
#else
	status = CreateServiceAndStartX64(szDriverFullPath, szDriverName);
#endif // _X64
	free(szDriverName);
	if (status > 0)
	{
		return status;
	}

	return STATUS_TEST_COMM_DRIVER_STARTED;
}

ULONG InstallDriver3(DWORD pid) {
	ULONG status = 0;
	unsigned char key[17] = { 0 };
	unsigned char iv[17] = { 0 };

	memcpy(key, fileData + 4, 17);
	memcpy(iv, fileData + 4 + 17, 17);
	PUCHAR mfile = fileData + 4 + 17 + 17;
	struct AES_ctx ctx = { 0 };
	AES_init_ctx_iv(&ctx, key, iv);
	int dumpFileLen = FILE_LEN - 4 - 17 - 17;
	AES_CTR_xcrypt_buffer(&ctx, (uint8_t*)mfile, dumpFileLen);
	//enableDebugPriv();
	HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
	if (hProcess == NULL) {
		Logp("[ERROR] Could not open process :  %08x ", GetLastError());
		return STATUS_TEST_OPEN_PROCESS;
	}
	LPVOID remote_buf = VirtualAllocEx(hProcess, NULL, dumpFileLen, (MEM_RESERVE | MEM_COMMIT), PAGE_EXECUTE_READWRITE);
	if (remote_buf == NULL) {
		Logp("[ERROR] Could not allocate a remote buffer :  %08x ", GetLastError());
		CloseHandle(hProcess);
		return STATUS_TEST_VIRTUAL_ALLOCEX;
	}
	if (!WriteProcessMemory(hProcess, remote_buf, mfile, dumpFileLen, NULL)) {
		Logp("[ERROR] WriteProcessMemory failed, status :  %08x ", GetLastError());
		CloseHandle(hProcess);
		return STATUS_TEST_WRITEPROCESSMEMORY;
	}
	HANDLE hMyThread = NULL;
	DWORD threadId = 0;



#ifdef _X86
	pCreateRemoteThread64 CreateRemoteThread64 = (pCreateRemoteThread64)init_func(CREATETHREADPIC, CREATETHREADPIC_SIZE);
	CreateRemoteThread64(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)remote_buf, NULL, 0, 0, &threadId);
	if (!threadId)
	{
		Logp("[ERROR] CreateRemoteThread failed, status :   %08x ", GetLastError());
		CloseHandle(hProcess);
		return STATUS_TEST_CREATEREMOTETHREAD;
	}
#else

	if ((hMyThread = CreateRemoteThread(hProcess, NULL, NULL, (LPTHREAD_START_ROUTINE)remote_buf, NULL, 0, &threadId)) == NULL) {
		Logp("[ERROR] CreateRemoteThread failed, status :   %08x ", GetLastError());
		CloseHandle(hProcess);
		return STATUS_TEST_CREATEREMOTETHREAD;
	}

#endif // _X86





	Logp("Injected, created Thread, id =   :   %d    imageBase: %llx", threadId, remote_buf);
	Sleep(5000);
	if (!VirtualFreeEx(hProcess, remote_buf, 0, MEM_RELEASE))
	{
		Logp("[ERROR] VirtualFreeEx failed, status :   %08x ", GetLastError());
	}
	CloseHandle(hMyThread);
	CloseHandle(hProcess);
	return STATUS_OP_SUCCESS;
}

//字符串转字节
int StringToBuff2(char* str, unsigned char* OutputBuff)
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
ULONG _InitReg(PCHAR regCode)
{
	TEST_DATA testData = { 0 };
	PUCHAR OutputBuff = (PUCHAR)VirtualAlloc(NULL, 200, MEM_COMMIT, PAGE_READWRITE);
	if (!OutputBuff)
	{
		return STATUS_TEST_COMM_ALLOC_FAIL;
	}
	int size = StringToBuff2(regCode, OutputBuff);
	testData.uTest = STATUS_TEST_COMM_INIT;
	testData.regCode = OutputBuff;
	testData.size = size;
	//testData.time = time(NULL);
	testData.time = get_time();
	DWORD status_code = HookComm(TEST_COMM, &testData, sizeof(TEST_DATA));
	ULONG ret = 0;
	if (testData.uTest == STATUS_TEST_COMM_SUCCESS || testData.uTest == STATUS_TEST_COMM_REG_EXPIRED || testData.uTest == STATUS_TEST_COMM_REG_INVALID || testData.uTest == STATUS_TEST_COMM_UNREG_OR_EXPIRED)
	{
		Logp("第一次通讯成功 %08x  ", testData.uTest);
		ret = testData.uTest;
	}
	else {
		Logp("第一次通讯失败 开始加载驱动  \r\n");
		HWND exploreHwnd = FindWindowA(NULL, "Program Manager");
		if (!exploreHwnd)
		{
			Logp("FolderView Window not found %d", exploreHwnd);
			return STATUS_TEST_FINDWINDOWA;
		}
		DWORD pid = 0;
		GetWindowThreadProcessId(exploreHwnd, &pid);
		if (!pid)
		{
			Logp("process id NotFound ");
			return STATUS_TEST_GETWINDOWTHREADPROCESSID;
		}

		ret = InstallDriver3(pid);
		if (ret == 0)
		{
			for (size_t i = 2; i < 40; i++)
			{
				Logp("加载驱动成功，尝试第%d次重新测试通讯  \r\n", i);
				Sleep(500);
				testData.uTest = STATUS_TEST_COMM_INIT;
				status_code = HookComm(TEST_COMM, &testData, sizeof(TEST_DATA));
				if (testData.uTest == STATUS_TEST_COMM_SUCCESS || testData.uTest == STATUS_TEST_COMM_REG_EXPIRED || testData.uTest == STATUS_TEST_COMM_REG_INVALID || testData.uTest == STATUS_TEST_COMM_UNREG_OR_EXPIRED)
				{
					Logp("通讯成功 \r\n");
					break;
				}
				Logp("%d  \r\n", ret);
			}
		}
	}
	VirtualFree((PVOID)OutputBuff, 200, MEM_RELEASE);
	return testData.uTest;
}


ULONG _PhyReadMemory(ULONG PID, PVOID Address, PVOID buffer, ULONG uDataSize)
{

	RW_MEM_DATA TestMEM = { 0 };
	TestMEM.pValBuffer = buffer;
	TestMEM.uDataSize = uDataSize;
	TestMEM.PID = PID;
	TestMEM.Address = Address;
	DWORD status_code = HookComm(PHY_READ_MEMORY, &TestMEM, sizeof(RW_MEM_DATA));
	return status_code;
}

ULONG _PhyWriteMemory(ULONG PID, PVOID Address, PVOID pValBuffer, ULONG length)
{

	RW_MEM_DATA TestMEM = { 0 };
	TestMEM.pValBuffer = pValBuffer;
	TestMEM.uDataSize = length;
	TestMEM.PID = PID;
	TestMEM.Address = Address;
	DWORD status_code = HookComm(PHY_WRITE_MEMORY, &TestMEM, sizeof(RW_MEM_DATA));
	return status_code;
}

ULONG _ProtectProcess(ULONG protectPid, ULONG fakePid) {

	if (!protectPid)
	{
		return  STATUS_COMMON_PARAM_1;
	}
	if (!fakePid)
	{
		return STATUS_COMMON_PARAM_2;
	}
	FAKE_PROCESS_DATA protectProcess = { 0 };
	protectProcess.PID = protectPid;
	protectProcess.FakePID = fakePid;
	DWORD status_code = HookComm(PROTECT_PROCESS, &protectProcess, sizeof(FAKE_PROCESS_DATA));
	return  status_code;
}

ULONG _AntiSnapShotWindow(ULONG32 hwnd)
{
	WND_PROTECT_DATA WND_DATA = { 0 };
	WND_DATA.hwnd = hwnd;

	DWORD status_code = HookComm(ANTI_SNAPSHOT, &WND_DATA, sizeof(WND_PROTECT_DATA));
	return  status_code;
}
ULONG _ProtectWindow(ULONG32 hwnd)
{
	WND_PROTECT_DATA WND_DATA = { 0 };
	WND_DATA.hwnd = hwnd;

	DWORD status_code = HookComm(WND_PROTECT, &WND_DATA, sizeof(WND_PROTECT_DATA));
	return  status_code;
}
ULONG _QueryModule(ULONG pid, PCHAR szModuleName, PULONGLONG pModuleBase, PULONG pModuleSize, USHORT type)
{

	QUERY_MODULE_DATA moduleData = { 0 };
	moduleData.PID = pid;
	moduleData.pcModuleName = szModuleName;
	ULONG uModuleSize = 0;
	moduleData.pModuleSize = &uModuleSize;
	moduleData.type = type;
	DWORD status_code = HookComm(QUERY_MODULE, &moduleData, sizeof(QUERY_MODULE_DATA));
	if (status_code == STATUS_OP_SUCCESS)
	{
		*pModuleBase = moduleData.pModuleBase;
		*pModuleSize = uModuleSize;
	}
	return status_code;
}

ULONG _AllocateMem(ULONG PID, ULONG uDataSize, PULONG64 pAddr)
{
	ULONG64 Addr = 0;
	CREATE_MEM_DATA CreateMemData = { 0 };
	CreateMemData.PID = PID;
	CreateMemData.pVAddress = &Addr;
	CreateMemData.uSize = uDataSize;
	DWORD status_code = HookComm(CREATE_MEMORY, &CreateMemData, sizeof(CREATE_MEM_DATA));
	if (status_code == STATUS_OP_SUCCESS)
	{
		*pAddr = Addr;

	}

	return status_code;
}
ULONG _QueryVADModule(ULONG pid, PCHAR szModuleName, PULONGLONG pModuleBase, PULONG pModuleSize)
{
	if (strlen(szModuleName) < 4)
	{
		return STATUS_QUERY_VAD_MODULE_MODULE_NAME;
	}
	QUERY_MODULE_DATA moduleData = { 0 };
	moduleData.PID = pid;
	moduleData.pcModuleName = szModuleName;
	ULONG uModuleSize = 0;
	moduleData.pModuleSize = &uModuleSize;
	DWORD status_code = HookComm(QUERY_VAD_MODULE, &moduleData, sizeof(QUERY_MODULE_DATA));
	if (status_code == STATUS_OP_SUCCESS)
	{

		*pModuleBase = moduleData.pModuleBase;
		*pModuleSize = uModuleSize;
	}

	return status_code;

}
ULONG _CreateMyThread(ULONG PID, PVOID address, PVOID Argument)
{
	CREATE_THREAD_DATA THREAD_DATA = { 0 };
	THREAD_DATA.PID = PID;
	THREAD_DATA.Argument = Argument;
	THREAD_DATA.ShellCode = address;
	DWORD status_code = HookComm(CREATE_THREAD, &THREAD_DATA, sizeof(CREATE_THREAD_DATA));
	return status_code;

}

ULONG _ProtectProcessR3_Add(ULONG pid)
{
	PROTECT_PROCESS_DATA process = { 0 };
	process.PID = pid;
	DWORD status_code = 0;
	status_code = HookComm(PROTECT_PROCESS_ADD, &process, sizeof(RW_MEM_DATA));
	return status_code;
}

ULONG _ProtectProcessR3_Remove(ULONG pid) {
	PROTECT_PROCESS_DATA process = { 0 };
	process.PID = pid;
	DWORD status_code = 0;
	status_code = HookComm(PROTECT_PROCESS_REMOVE, &process, sizeof(RW_MEM_DATA));
	return status_code;
}

VOID ConvertString2Pattern(PCHAR pattern, PCHAR mask, PCHAR outPattern) {
	int len = strlen(mask);
	if (!len)
	{
		return STATUS_PATTERN_SEARCH_MASK;
	}
	char byte_str[3];
	byte_str[2] = '\0';  // 作为字符串结尾的 null 字符
	for (int i = 0; i < len * 4; i += 4) {
		byte_str[0] = pattern[i + 2];
		byte_str[1] = pattern[i + 3];
		unsigned char byte = (unsigned char)strtoul(byte_str, NULL, 16);
		outPattern[i / 4] = byte;
	}
}
VOID ConvertCEPattern(PCHAR CE_XDBG_pattern, PCHAR mask, PCHAR outPattern)
{
	return;
}
ULONG _SearchPattern(ULONG pid, PCHAR szModuleName, PCHAR pattern, PCHAR mask, PULONG64 retAddr)
{

	PATTEERN_DATA patternData = { 0 };
	patternData.PID = pid;
	patternData.mask = mask;
	patternData.pattern = pattern;
	patternData.pcModuleName = szModuleName;
	patternData.addr = 0;
	DWORD status_code = HookComm(PATTERN_SEARCH, &patternData, sizeof(PATTEERN_DATA));
	if (status_code == STATUS_OP_SUCCESS)
	{
		*retAddr = patternData.addr;
	}
	return status_code;
}


ULONG _InjectX64DLL(ULONG pid, PCHAR dllFilePath, UCHAR type) {
	char prefix[] = "\\??\\";
	int totalLen = sizeof(prefix) + strlen(dllFilePath) * sizeof(char);
	PCHAR dosPath = (PCHAR)VirtualAlloc(NULL, USN_PAGE_SIZE, MEM_COMMIT, PAGE_READWRITE);
	if (!dosPath)
	{
		return STATUS_INJECT_DLL_ALLOC_FAILED;
	}
	strcat(dosPath, prefix);
	strcat(dosPath, dllFilePath);
	INJECT_DLL_DATA injectDLL = { 0 };
	injectDLL.PID = pid;
	injectDLL.dllFilePath = dosPath;
	injectDLL.type = type;
	DWORD status_code = HookComm(INJECT_DLL, &injectDLL, sizeof(INJECT_DLL_DATA));
	VirtualFree(dosPath, USN_PAGE_SIZE, MEM_RELEASE);
	return status_code;
}

ULONG _WriteDLL(ULONG PID, PCHAR dllFilePath, PULONG64 entryPoint, PULONG64 R3_ImageBase, PULONG64 R0_ImageBase) {
	char prefix[] = "\\??\\";
	int totalLen = sizeof(prefix) + strlen(dllFilePath) * sizeof(char);
	PCHAR dosPath = VirtualAlloc(NULL, USN_PAGE_SIZE, MEM_COMMIT, PAGE_READWRITE);
	strcat(dosPath, prefix);
	strcat(dosPath, dllFilePath);
	WRITE_DLL_DATA writeDll = { 0 };
	writeDll.PID = PID;
	writeDll.dllFilePath = dosPath;
	writeDll.entryPoint = 0;
	writeDll.imageBase = 0;
	writeDll.kimageBase = 0;
	DWORD status_code = HookComm(WRITE_DLL, &writeDll, sizeof(WRITE_DLL_DATA));
	if (status_code == STATUS_OP_SUCCESS)
	{
		*entryPoint = writeDll.entryPoint;
		*R3_ImageBase = writeDll.imageBase;
		*R0_ImageBase = writeDll.kimageBase;
	}
	VirtualFree(dosPath, USN_PAGE_SIZE, MEM_RELEASE);
	return  status_code;
};
ULONG _GetModuleExportAddr2(ULONG pid, ULONG64 ModuleBase, PCHAR ExportFuncName, PULONG64 funcAddr) {
	MODULE_BASE_EXPORT_DATA expoetData = { 0 };
	expoetData.PID = pid;
	expoetData.ModuleBase = ModuleBase;
	expoetData.ExportFuncName = ExportFuncName;
	expoetData.FuncAddr = 0;
	DWORD status_code = HookComm(MODULE_NAME_EXPORT, &expoetData, sizeof(MODULE_BASE_EXPORT_DATA));
	if (status_code == STATUS_OP_SUCCESS)
	{
		*funcAddr = expoetData.FuncAddr;
	}
	return status_code;

}

ULONG _CALL_MAIN_THREAD(ULONG PID, ULONG64 shellcodeAddr, ULONG shellcodeLen) {

	CALL_DATA callData = { 0 };
	callData.PID = PID;
	callData.shellcodeAddr = shellcodeAddr;
	callData.shellcodeLen = shellcodeLen;
	DWORD status_code = HookComm(CALL_MAIN, &callData, sizeof(WRITE_DLL_DATA));
	return status_code;

}


ULONG _CHANGE_MEMORY_ATTR(ULONG PID, ULONG64 address, ULONG length) {
	CHANGE_ATTRIBUTE_DATA data = { 0 };
	data.PID = PID;
	data.Address = address;
	data.uSize = length;
	DWORD status_code = HookComm(MEMORY_ATTRIBUTE, &data, sizeof(CHANGE_ATTRIBUTE_DATA));
	return status_code;

}