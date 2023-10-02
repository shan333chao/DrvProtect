#pragma once
#include "lib.h"
#pragma warning(disable:4996)
 

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

	//��ȡ�ļ�����
	fseek(pfile, 0, SEEK_END);
	lFileSize = ftell(pfile);
	fseek(pfile, 0, SEEK_SET);
	//��ȡ�ļ�����
	pFileData = malloc(lFileSize);
	if (!pFileData)
	{
		fclose(pfile);
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
	free(pFileData);
	//2.�򿪷�����ƹ�����
	SC_HANDLE hServiceMgr = OpenSCManagerW(NULL, NULL, SC_MANAGER_ALL_ACCESS); // SCM���������	
	if (!hServiceMgr)
	{
		return FALSE;
	}
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
			return FALSE;
		}
	}
	// ���������Ѿ��������򿪷���
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
	//�ж��ַ��������Ƿ�Ϊ����
	if (0 != Len % 2)
	{
		OutputBuff[count++] = ((*p > '9') && (*p <= 'F') || (*p <= 'f')) ? *p - 48 - 7 : *p - 48;
	}

	return Len / 2 + Len % 2;
}
//��ʼ��
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

//-------------------��������-------------
//protectPid  Ҫ�����Ľ���id
//fakePid	Ҫαװ�Ľ���id
//����ֵ��
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
