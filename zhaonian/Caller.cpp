#pragma once
#include "Caller.h"
#include "CommR3.h"
#include <stdio.h>
using namespace std;
#include <random>
#include <iostream>
#include <filesystem>
#include <vector>
#include <string>
#include <filesystem>
#include <string.h>
#include "lib/aes.h"
#include "lib/structs.h"
#include "ntp_client/ntp_client.h"
#include "lib/utils.hpp"
#include "../SSS_Drivers/ERROR_CODE.h"
#include "lib/service.hpp"
#include "driver_shellcode.h"
#pragma warning(disable:4996)


namespace caller {
	void SearchFiles(char* path, char* fileName, const char* pattern)
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

	//生成随机字符串
	void GenerateRandomString(PCHAR randomString, int length) {
		char characters[] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
		// 创建随机数生成器
		std::random_device rd;
		std::mt19937 gen(rd());
		// 创建均匀分布对象，指定随机数范围
		std::uniform_int_distribution<> dis(0, 62);
		for (int i = 0; i < length; i++) {
			int randomIndex = dis(gen);
			randomString[i] = characters[randomIndex];
		}
		randomString[length] = '\0';

	}
	//安装驱动
	ULONG InstallDriver()
	{
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
		GenerateRandomString(szDriverName, namelen);
		char szDriverFullPath[MAX_PATH];
		GetCurrentDirectoryA(MAX_PATH, szDriverFullPath);
		sprintf(szDriverFullPath, "%s\\%s", szDriverFullPath, szDriverName);
		utils::CreateFileFromMemory(utils::char2wchar(szDriverFullPath), (PCHAR)mfile, dumpFileLen);
		return service::RegisterAndStart(utils::char2wchar(szDriverFullPath), utils::char2wchar(szDriverName));
	}
	//字符串转字节
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
		PUCHAR OutputBuff = (PUCHAR)VirtualAlloc(NULL, 200, MEM_COMMIT, PAGE_READWRITE);
		if (!OutputBuff)
		{
			return 0x19999;
		}
		int size = StringToBuff(regCode, OutputBuff);
		testData.uTest = 0;
		testData.regCode = OutputBuff;
		testData.size = size;
		testData.time = ntp_client::get_time();
		DWORD status_code = comm_r3::HookComm(TEST_COMM, &testData, sizeof(TEST_DATA));
		ULONG ret = 0;
		if (testData.uTest == 0x100000)
		{
			ret = testData.uTest;
		}
		else if (testData.uTest == 0x100003)
		{
			ret = testData.uTest;
		}
		else {
			InstallDriver();
			Sleep(2000);
			status_code = comm_r3::HookComm(TEST_COMM, &testData, sizeof(TEST_DATA));
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
				ret = 0x123456;
			}
		}
		VirtualFree((PVOID)OutputBuff, 200, MEM_RELEASE);
		return ret;
	}

	ULONG FakeReadMemory(ULONG PID, ULONG fakePid, PVOID Address, PVOID buffer, ULONG uDataSize)
	{
		if (!PID)
		{
			return  STATUS_COMMON_PARAM1;
		}
		if (!fakePid)
		{
			return STATUS_COMMON_PARAM2;
		}
		RW_MEM_DATA TestMEM = { 0 };
		TestMEM.pValBuffer = buffer;
		TestMEM.uDataSize = uDataSize;
		TestMEM.PID = PID;
		TestMEM.FakePID = fakePid;
		TestMEM.Address = Address;
		DWORD status_code = comm_r3::HookComm(FAKE_READ_MEMORY, &TestMEM, sizeof(RW_MEM_DATA));
		return status_code;
	}

	ULONG FakeWriteMemory(ULONG PID, ULONG fakePid, ULONG64 Address, PVOID pValBuffer, ULONG length)
	{
		if (!PID)
		{
			return  STATUS_COMMON_PARAM1;
		}
		if (!fakePid)
		{
			return STATUS_COMMON_PARAM2;
		}
		RW_MEM_DATA TestMEM = { 0 };
		TestMEM.pValBuffer = pValBuffer;
		TestMEM.uDataSize = length;
		TestMEM.PID = PID;
		TestMEM.FakePID = fakePid;
		TestMEM.Address = (PVOID)Address;
		DWORD status_code = comm_r3::HookComm(FAKE_WRITE_MEMORY, &TestMEM, sizeof(RW_MEM_DATA));
		return status_code;
	}

	ULONG PhyReadMemory(ULONG PID, PVOID Address, PVOID buffer, ULONG uDataSize)
	{

		RW_MEM_DATA TestMEM = { 0 };
		TestMEM.pValBuffer = buffer;
		TestMEM.uDataSize = uDataSize;
		TestMEM.PID = PID;
		TestMEM.Address = Address;
		DWORD status_code = comm_r3::HookComm(PHY_READ_MEMORY, &TestMEM, sizeof(RW_MEM_DATA));
		return status_code;
	}

	ULONG PhyWriteMemory(ULONG PID, PVOID Address, PVOID pValBuffer, ULONG length)
	{

		RW_MEM_DATA TestMEM = { 0 };
		TestMEM.pValBuffer = pValBuffer;
		TestMEM.uDataSize = length;
		TestMEM.PID = PID;
		TestMEM.Address = Address;
		DWORD status_code = comm_r3::HookComm(PHY_WRITE_MEMORY, &TestMEM, sizeof(RW_MEM_DATA));
		return status_code;
	}


	ULONG ProtectProcess(ULONG protectPid, ULONG fakePid) {

		if (!protectPid)
		{
			return  STATUS_COMMON_PARAM1;
		}
		if (!fakePid)
		{
			return STATUS_COMMON_PARAM2;
		}
		FAKE_PROCESS_DATA protectProcess = { 0 };
		protectProcess.PID = protectPid;
		protectProcess.FakePID = fakePid;
		DWORD status_code = comm_r3::HookComm(PROTECT_PROCESS, &protectProcess, sizeof(FAKE_PROCESS_DATA));
		return  status_code;
	}

	ULONG ProtectWindow(ULONG32 hwnd)
	{

		WND_PROTECT_DATA WND_DATA = { 0 };
		ULONG32 hwnds[10] = { 0 };
		hwnds[0] = hwnd;
		WND_DATA.hwnds = hwnds;
		WND_DATA.Length = 1;
		DWORD status_code = comm_r3::HookComm(WND_PROTECT, &WND_DATA, sizeof(WND_PROTECT_DATA));
		return  status_code;
	}

	ULONG QueryModule(ULONG pid, PCHAR szModuleName, PULONGLONG pModuleBase, PULONG pModuleSize)
	{

		QUERY_MODULE_DATA moduleData = { 0 };
		moduleData.PID = pid;
		moduleData.pcModuleName = szModuleName;
		ULONG uModuleSize = 0;
		moduleData.pModuleSize = &uModuleSize;
		DWORD status_code = comm_r3::HookComm(QUERY_MODULE, &moduleData, sizeof(QUERY_MODULE_DATA));
		*pModuleBase = moduleData.pModuleBase;
		*pModuleSize = uModuleSize;
		return status_code;

	}

	ULONG AllocateMem(ULONG PID, ULONG uDataSize, PULONG64 pAddr)
	{
		ULONG64 Addr = 0;
		CREATE_MEM_DATA CreateMemData = { 0 };
		CreateMemData.PID = PID;
		CreateMemData.pVAddress = &Addr;
		CreateMemData.uSize = uDataSize;
		DWORD status_code = comm_r3::HookComm(CREATE_MEMORY, &CreateMemData, sizeof(CREATE_MEM_DATA));
		*pAddr = Addr;
		return status_code;
	}
	ULONG QueryVADModule(ULONG pid, PCHAR szModuleName, PULONGLONG pModuleBase, PULONG pModuleSize)
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
		DWORD status_code = comm_r3::HookComm(QUERY_VAD_MODULE, &moduleData, sizeof(QUERY_MODULE_DATA));
		*pModuleBase = moduleData.pModuleBase;
		*pModuleSize = uModuleSize;
		return status_code;

	}
	ULONG CreateMyThread(ULONG PID, PVOID address, PVOID Argument)
	{
		CREATE_THREAD_DATA THREAD_DATA = { 0 };
		THREAD_DATA.PID = PID;
		THREAD_DATA.Argument = Argument;
		THREAD_DATA.ShellCode = address;
		DWORD status_code = comm_r3::HookComm(CREATE_THREAD, &THREAD_DATA, sizeof(CREATE_THREAD_DATA));
		return status_code;

	}

	ULONG ProtectProcessR3_Add(ULONG pid)
	{
		PROTECT_PROCESS_DATA process = { 0 };
		process.PID = pid;
		DWORD status_code = 0;
		status_code = comm_r3::HookComm(PROTECT_PROCESS_ADD, &process, sizeof(RW_MEM_DATA));
		return status_code;
	}

	ULONG ProtectProcessR3_Remove(ULONG pid) {
		PROTECT_PROCESS_DATA process = { 0 };
		process.PID = pid;
		DWORD status_code = 0;
		status_code = comm_r3::HookComm(PROTECT_PROCESS_REMOVE, &process, sizeof(RW_MEM_DATA));
		return status_code;
	}

	ULONG SearchPattern(ULONG pid, PCHAR szModuleName, PCHAR pattern, PCHAR mask, PULONG64 retAddr)
	{

		PATTEERN_DATA patternData = { 0 };
		patternData.PID = pid;
		patternData.mask = mask;
		int len = strlen(mask);
		if (!len)
		{
			return STATUS_PATTERN_SEARCH_MASK;
		}
		UCHAR upattern[0x100] = { 0 };
		char byte_str[3];
		byte_str[2] = '\0';  // 作为字符串结尾的 null 字符
		for (int i = 0; i < len * 4; i += 4) {
			byte_str[0] = pattern[i + 2];
			byte_str[1] = pattern[i + 3];
			unsigned char byte = (unsigned char)strtoul(byte_str, NULL, 16);
			upattern[i / 4] = byte;
		}
		patternData.pattern = (PCHAR)upattern;
		patternData.pcModuleName = szModuleName;
		patternData.addr = 0;
		DWORD status_code = comm_r3::HookComm(PATTERN_SEARCH, &patternData, sizeof(PATTEERN_DATA));
		*retAddr = patternData.addr;
		return status_code;

	}


	ULONG InjectX64DLL(ULONG pid, PCHAR dllFilePath) {
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
		DWORD status_code = comm_r3::HookComm(INJECT_DLL, &injectDLL, sizeof(INJECT_DLL_DATA));
		return status_code;
	}
}