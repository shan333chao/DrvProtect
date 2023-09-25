#pragma once
#include "lib.h"
#pragma warning(disable:4996)
static BOOL isInit = FALSE;

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

//��ʼ��
BOOL init()
{
	TEST_DATA testData = { 0 };
	testData.uTest = 0;
	DWORD status_code = DriverComm(TEST_COMM, &testData, sizeof(TEST_DATA));
	if (testData.uTest > 0)
	{
		isInit = TRUE;
		return TRUE;
	}
	else
	{
		BOOL isok = InitDriver();
		Sleep(5000);
		return isok;
	}
}

BOOL FakeReadMemory(ULONG PID, ULONG fakePid, PVOID Address, PVOID buffer, ULONG uDataSize)
{
	if (!isInit)
	{
		init();
	}
	RW_MEM_DATA TestMEM = { 0 };
	TestMEM.pValBuffer = buffer;
	TestMEM.uDataSize = uDataSize;
	TestMEM.PID = PID;
	TestMEM.FakePID = fakePid;
	TestMEM.Address = Address;
	DWORD status_code = DriverComm(FAKE_READ_MEMORY, &TestMEM, sizeof(RW_MEM_DATA));
	return !status_code;
}

BOOL FakeWriteMemory(ULONG PID, ULONG fakePid, PVOID Address, PUCHAR pValBuffer, ULONG length)
{
	if (!isInit)
	{
		init();
	}
	RW_MEM_DATA TestMEM = { 0 };
	TestMEM.pValBuffer = pValBuffer;
	TestMEM.uDataSize = length;
	TestMEM.PID = PID;
	TestMEM.FakePID = fakePid;
	TestMEM.Address = Address;
	DWORD status_code = DriverComm(FAKE_WRITE_MEMORY, &TestMEM, sizeof(RW_MEM_DATA));
	return !status_code;
}

BOOL PhyReadMemory(ULONG PID, PVOID Address, PVOID buffer, ULONG uDataSize)
{
	if (!isInit)
	{
		init();
	}
	RW_MEM_DATA TestMEM = { 0 };
	TestMEM.pValBuffer = buffer;
	TestMEM.uDataSize = uDataSize;
	TestMEM.PID = PID;
	TestMEM.Address = Address;
	DWORD status_code = DriverComm(PHY_READ_MEMORY, &TestMEM, sizeof(RW_MEM_DATA));
	if (status_code)
	{
		return FALSE;
	}
	return TRUE;
}

BOOL PhyWriteMemory(ULONG PID, PVOID Address, PUCHAR pValBuffer, ULONG length)
{
	if (!isInit)
	{
		init();
	}
	RW_MEM_DATA TestMEM = { 0 };
	TestMEM.pValBuffer = pValBuffer;
	TestMEM.uDataSize = length;
	TestMEM.PID = PID;
	TestMEM.Address = Address;
	DWORD status_code = DriverComm(PHY_WRITE_MEMORY, &TestMEM, sizeof(RW_MEM_DATA));
	return !status_code;
}

//-------------------��������-------------
//protectPid  Ҫ�����Ľ���id
//fakePid	Ҫαװ�Ľ���id
//����ֵ��
BOOL ProtectProcess(ULONG protectPid, ULONG fakePid) {
	if (!isInit)
	{
		init();
	}
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


	DWORD status_code = DriverComm(PROTECT_PROCESS, &protectProcess, sizeof(FAKE_PROCESS_DATA));
	if (status_code > 0)
	{
		return FALSE;
	}
	return  TRUE;
}

BOOL ProtectWindow(ULONG32 hwnd)
{
	if (!isInit)
	{
		init();
	}
	WND_PROTECT_DATA WND_DATA = { 0 };
	ULONG32 hwnds[10] = { 0 };
	hwnds[0] = hwnd;
	WND_DATA.hwnds = hwnds;
	WND_DATA.Length = 1;
	DWORD status_code = DriverComm(WND_PROTECT, &WND_DATA, sizeof(WND_PROTECT_DATA));
	if (status_code > 0)
	{
		return FALSE;
	}
	return  TRUE;
}

BOOL QueryModule(ULONG pid, PCHAR szModuleName)
{
	if (!isInit)
	{
		init();
	}
	QUERY_MODULE_DATA moduleData = { 0 };
	moduleData.PID = pid;

	moduleData.pcModuleName = szModuleName;
	ULONG uModuleSize = 0;
	moduleData.pModuleSize = &uModuleSize;
	DWORD status_code = DriverComm(QUERY_MODULE, &moduleData, sizeof(QUERY_MODULE_DATA));
	if (status_code)
	{
		return FALSE;
	}
	return TRUE;

}

PUCHAR AllocateMem(ULONG PID, ULONG uDataSize)
{
	if (!isInit)
	{
		init();
	}
	PVOID Addr = 0;
	CREATE_MEM_DATA CreateMemData = { 0 };
	CreateMemData.PID = PID;
	CreateMemData.pVAddress = &Addr;
	CreateMemData.uSize = uDataSize;
	DWORD status_code = DriverComm(CREATE_MEMORY, &CreateMemData, sizeof(CREATE_MEM_DATA));
	if (status_code > 0)
	{
		return 0;
	}
	return Addr;
}

BOOL CreateMyThread(ULONG PID, PUCHAR shellcode, ULONG len)
{
	if (!isInit)
	{
		init();
	}
	PUCHAR address = AllocateMem(PID, len);
	if (!address)
	{
		return FALSE;
	}
	BOOL isok = PhyWriteMemory(PID, address, shellcode, len);
	if (!isok)
	{
		return FALSE;
	}

	CREATE_THREAD_DATA THREAD_DATA = { 0 };
	THREAD_DATA.PID = PID;
	THREAD_DATA.Argument = NULL;
	THREAD_DATA.ShellCode = address;
	DWORD status_code = DriverComm(CREATE_THREAD, &THREAD_DATA, sizeof(CREATE_THREAD_DATA));
	if (status_code > 0)
	{

		return FALSE;
	}
	return TRUE;

}
