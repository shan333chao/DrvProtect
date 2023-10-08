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
			// �ҵ����̵������ھ��
			windowInfo->wndHw = hwnd;
			windowInfo->tid = threadid;
			return FALSE; // ���� FALSE ֹͣö��
		}
	}
	return TRUE; // ���� TRUE ����ö��
}

#include <windows.h>



void SearchFiles(const char* path, const char* fileName, const char* pattern)
{
	WIN32_FIND_DATAA searchData;
	HANDLE hFind;

	// ��������ģʽ
	char searchPattern[MAX_PATH];
	sprintf(searchPattern, "%s\\*", path);

	// ��ʼ����
	hFind = FindFirstFileA(searchPattern, &searchData);
	if (hFind != INVALID_HANDLE_VALUE)
	{
		do
		{
			// ����ļ�����
			if (!(searchData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY))
			{
				// ����ļ����Ƿ����Ŀ���ַ���
				char* found = strstr(searchData.cFileName, pattern);
				if (found != NULL)
				{
					// ��������·��
					//char filePath[MAX_PATH];
					sprintf(path, "%s\\%s", path, searchData.cFileName);
					sprintf(fileName, "%s", searchData.cFileName);

				}
			}
		} while (FindNextFileA(hFind, &searchData) != 0);

		// �رվ��
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
	////1.��ȡ�����ļ�ȫ·����
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

	//��ȡ�ļ�����
	fseek(pfile, 0, SEEK_END);
	lFileSize = ftell(pfile);
	fseek(pfile, 0, SEEK_SET);
	//��ȡ�ļ�����
	pFileData = malloc(lFileSize);
	if (!pFileData)
	{
		fclose(pfile);
		printf("malloc failed \r\n");
		return 0;
	}
	memset(pFileData, 0, lFileSize);
	fread_s(pFileData, lFileSize, lFileSize, 1, pfile);
	//�ر��ļ�
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

	//2.�򿪷�����ƹ�����
	SC_HANDLE hServiceMgr = OpenSCManagerW(NULL, NULL, SC_MANAGER_ALL_ACCESS); // SCM���������	
	if (!hServiceMgr)
	{
		printf("OpenSCManagerW ʧ��, %d\n", GetLastError());
		return FALSE;
	}
	printf("�򿪷�����ƹ������ɹ�.\n");


	//3.������������
	SC_HANDLE hServiceDDK = NULL; // NT�������������
	//������������
	hServiceDDK = CreateServiceA(
		hServiceMgr,
		szDriverName,//��������ע����е�����
		szDriverName,//ע�������������� DisPlayName ��ֵ
		SERVICE_ALL_ACCESS,//���������ķ���Ȩ�� SERVICE_START �� SERVICE_ALL_ACCESS
		SERVICE_KERNEL_DRIVER,//��ʾ���ط�������������
		SERVICE_DEMAND_START,//ע������������ Start ֵ
		SERVICE_ERROR_IGNORE,//ע������� ErrorControl ֵ
		szDriverFullPath,
		NULL, NULL, NULL, NULL, NULL
	);

	if (!hServiceDDK)
	{
		DWORD dwErr = GetLastError();
		if (dwErr != ERROR_IO_PENDING && dwErr != ERROR_SERVICE_EXISTS)
		{
			printf("������������ʧ��, %d\n", dwErr);
			return FALSE;
		}
	}
	printf("������������ɹ�.\n");
	// ���������Ѿ��������򿪷���
	hServiceDDK = OpenServiceA(hServiceMgr, szDriverName, SERVICE_ALL_ACCESS);
	if (!StartService(hServiceDDK, NULL, NULL))
	{
		DWORD dwErr = GetLastError();
		if (dwErr != 23)
		{
			printf("������������ʧ��, %d\n", dwErr);
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
	printf("������������ɹ�.\n");
	if (hServiceDDK)
	{
		CloseServiceHandle(hServiceDDK);
	}
	if (hServiceMgr)
	{
		CloseServiceHandle(hServiceMgr);
	}
	//����������r3�ļ��غۼ�
	//clear_trace(L"DisapperDriver.sys", driverStamp);
	return TRUE;


}

//-------------------����ͨѶ
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
		printf("����ͨѶ�ɹ���\n");
	}
	else if (testData.uTest == 0x100003)
	{
		printf("���ܹ��ڣ�\n");
	}
	else {
		printf("����ͨѶʧ�� ���ڰ��b������\n");
		InitDriver();
		Sleep(2000);
		status_code = DriverComm(TEST_COMM, &testData, sizeof(TEST_DATA));
		if (testData.uTest == 0x100000)
		{
			printf("����ͨѶ�ɹ���\n");
		}
		else if (testData.uTest == 0x100003)
		{
			printf("���ܹ��ڣ�\n");
		}
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
	printf("����������:\n");
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
		printf("д��ɹ�:\n");
	}
	else {
		printf("д��ʧ�� %08x:\n", status_code);
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
		printf("��ȡ����  ������%08x:\n", status_code);
		return;
	}
	printf("����������:\n");
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
		printf("д��ɹ�:\n");
	}
	else {
		printf("д��ʧ�� %08x:\n", status_code);
	}
	return !status_code;
}

void ProtectProcessR3(ULONG pid, BOOLEAN isProcect)
{
	PROTECT_PROCESS_DATA process = { 0 };
	process.PID = pid;
	DWORD status_code = 0;
	if (isProcect)
	{
		status_code = DriverComm(PROTECT_PROCESS_ADD, &process, sizeof(RW_MEM_DATA));
	}
	else
	{
		status_code = DriverComm(PROTECT_PROCESS_REMOVE, &process, sizeof(RW_MEM_DATA));
	}
}

//-------------------��������-------------
//protectPid  Ҫ�����Ľ���id
//fakePid	Ҫαװ�Ľ���id
//����ֵ��
void ProtectProcess(ULONG protectPid, ULONG fakePid) {
	if (!protectPid)
	{
		printf("Ҫ�����Ľ���PID Ϊ��\n");
		return;
	}
	if (!fakePid)
	{
		printf("Ҫαװ�Ľ���PID Ϊ��\n");
		return;
	}
	FAKE_PROCESS_DATA protectProcess = { 0 };
	protectProcess.PID = protectPid;
	protectProcess.FakePID = fakePid;
	printf("�������̣� %d \n  \n", protectProcess.PID);
	FWindowInfo winfo = { 0 };
	winfo.pid = protectPid;

	EnumWindows(EnumWindowsProc, &winfo);
	if (winfo.wndHw)
	{
		char className[256] = { 0 };
		char windowTitle[256] = { 0 };
		GetWindowTextA(winfo.wndHw, windowTitle, sizeof(windowTitle));  // ��ȡ���ڱ���
		GetClassNameA(winfo.wndHw, className, sizeof(className));
		printf("�����߳�: %d \n ���ھ���� %d \n ��������:%s  \n ���ڱ���:%s \n", winfo.tid, winfo.wndHw, className, windowTitle);
	}
	DWORD status_code = DriverComm(PROTECT_PROCESS, &protectProcess, sizeof(FAKE_PROCESS_DATA));
	if (status_code > 0)
	{
		printf("%d \r\n", status_code);
		printf("ִ��ʧ�� ������ %08x\n", status_code);
		return;
	}
	printf("ִ�гɹ�\n");
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
		printf("����ʧ�� ������ %08x\n", status_code);
		return;
	}
	printf("�����ɹ�\n");
}

void QueryModule(ULONG pid, PCHAR szModuleName, UCHAR type)
{
	QUERY_MODULE_DATA moduleData = { 0 };
	moduleData.PID = pid;

	moduleData.pcModuleName = szModuleName;
	ULONG uModuleSize = 0;
	moduleData.pModuleSize = &uModuleSize;
	moduleData.type = type;
	DWORD status_code = DriverComm(QUERY_MODULE, &moduleData, sizeof(QUERY_MODULE_DATA));
	if (status_code)
	{
		printf("��ѯģ��ʧ�� ������ %08x\n", status_code);
		return;
	}
	printf("\nģ����: %s \n ģ���ַ: 0x%p \n ģ���С: 0x%08x\n", szModuleName, moduleData.pModuleBase, uModuleSize);

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
		printf("��ѯģ��ʧ�� ������ %08x\n", status_code);
		return;
	}
	printf("\nģ����: %s \n ģ���ַ: 0x%p \n ģ���С: 0x%08x\n", szModuleName, moduleData.pModuleBase, uModuleSize);
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
		printf("�����ڴ�ʧ�� ������ %08x\n", status_code);
		return;
	}
	printf("���뵽���ڴ��ַ:0x%p\n", Addr);
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
		printf("�����߳� ������ %08x\n", status_code);
		return;
	}
	printf("�����̳߳ɹ�\n");

}

void SearchPattern(ULONG pid, PCHAR szModuleName, PCHAR pattern, PCHAR mask)
{

	PATTEERN_DATA patternData = { 0 };
	patternData.PID = pid;
	patternData.mask = mask;
	char* testPattern = "\x48\x83\xEC\x50\x48\x89\xD6\x48\x8B\x05\x36\x1C\x18\x00\x48\x31";
	int len = strlen(mask);

	UCHAR upattern[0x100] = { 0 };

	char byte_str[3];
	byte_str[2] = '\0';  // ��Ϊ�ַ�����β�� null �ַ�

	for (int i = 0; i < len * 4; i += 4) {
		byte_str[0] = pattern[i + 2];
		byte_str[1] = pattern[i + 3];
		unsigned char byte = (unsigned char)strtoul(byte_str, NULL, 16);
		upattern[i / 4] = byte;
	}

	printf("------------------ \r\n ");


	for (int i = 0; i < len; i++) {
		unsigned char byte = (unsigned char)upattern[i];
		upattern[i] = byte;
		printf("%02X ", upattern[i]);
	}
	printf("------------------ \r\n ");
	patternData.pattern = upattern;
	patternData.pcModuleName = szModuleName;
	patternData.addr = 0;
	DWORD status_code = DriverComm(PATTERN_SEARCH, &patternData, sizeof(PATTEERN_DATA));
	if (status_code > 0)
	{
		printf("SearchPattern ������ %08x\n", status_code);
		return;
	}
	printf("SearchPattern �ɹ�\n");
	printf("������ַ�� %p \r\n", patternData.addr);
	getchar();

}

void InjectX64DLL(ULONG pid, PCHAR dllFilePath) {
	char prefix[] = "\\??\\";
	int totalLen = sizeof(prefix) + strlen(dllFilePath) * sizeof(char);
	PCHAR dosPath = VirtualAlloc(NULL, USN_PAGE_SIZE, MEM_COMMIT, PAGE_READWRITE);
	strcat(dosPath, prefix);
	strcat(dosPath, dllFilePath);
	INJECT_DLL_DATA injectDLL = { 0 };
	injectDLL.PID = pid;
	injectDLL.dllFilePath = dosPath;
	DWORD status_code = DriverComm(INJECT_DLL, &injectDLL, sizeof(INJECT_DLL_DATA));
	if (status_code > 0)
	{
		printf("ע����� ������ %08x\n", status_code);
		return;
	}
}

void WriteX64DLL(ULONG PID, PCHAR dllFilePath)
{
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

	DWORD status_code = DriverComm(WRITE_DLL, &writeDll, sizeof(WRITE_DLL_DATA));
	VirtualFree(dosPath, USN_PAGE_SIZE, MEM_RELEASE);
	if (status_code > 0)
	{
		printf("д��DLL ���� %08x\n", status_code);
		return;
	}
	printf("д��DLL �ɹ� ");
	printf("entryPoint %p \r\n", writeDll.entryPoint);
	printf("imageBase %p \r\n", writeDll.imageBase);
	printf("kimageBase %p \r\n", writeDll.kimageBase);

}


void CALL_MAIN_THREAD(ULONG PID, ULONG64 shellcodeAddr, ULONG shellcodeLen) {

	CALL_DATA callData = { 0 };
	callData.PID = PID;
	callData.shellcodeAddr = shellcodeAddr;
	callData.shellcodeLen = shellcodeLen;
	DWORD status_code = DriverComm(CALL_MAIN, &callData, sizeof(WRITE_DLL_DATA));
	if (status_code > 0)
	{
		printf("д��DLL ���� %08x\n", status_code);
		return;
	}
	printf("д��DLL �ɹ� ");



}