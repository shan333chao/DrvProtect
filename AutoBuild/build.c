#include <stdio.h>
#include <stdlib.h>
#include <malloc.h>
#include <memory.h>
#include <time.h>
#include <Windows.h>
#include "aes.h"
//#include  "../ProxyDrv/MyDriver.h"
//#include "../ProxyDrv/MyDriver2.h"
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
void GetCurrentTimeStr(char* timestrBuffer) {
	time_t currentTime;
	struct tm localTime;
	// 获取当前时间
	time(&currentTime);
	// 转换为本地时间
	localtime_s(&localTime, &currentTime);
	// 格式化时间为字符串
	strftime(timestrBuffer, 20, "%Y-%m-%d %H:%M:%S", &localTime);
}
DWORD rav2Fov(char* pFileBuffer, DWORD dwRav) {
	PIMAGE_DOS_HEADER pDosHeader = pFileBuffer;
	PIMAGE_NT_HEADERS pNTHeader = pFileBuffer + pDosHeader->e_lfanew;
	PIMAGE_FILE_HEADER pFileHeader = (PIMAGE_FILE_HEADER)((PCHAR)pNTHeader + 4);
	PIMAGE_OPTIONAL_HEADER pOptionalHeader = (PIMAGE_OPTIONAL_HEADER)((PCHAR)pFileHeader + IMAGE_SIZEOF_FILE_HEADER);
	PIMAGE_SECTION_HEADER pSectionHeader = (PIMAGE_SECTION_HEADER)((PCHAR)pOptionalHeader + pFileHeader->SizeOfOptionalHeader);
	if (dwRav == 0x0)
	{
		return 0;
	}
	if (dwRav > pOptionalHeader->ImageBase)
	{
		dwRav = dwRav - pOptionalHeader->ImageBase;
	}
	for (size_t i = 0; i < pFileHeader->NumberOfSections; i++)
	{
		if (dwRav >= pSectionHeader[i].VirtualAddress && (dwRav < pSectionHeader[i].VirtualAddress + pSectionHeader[i].Misc.VirtualSize))
		{
			return dwRav - pSectionHeader[i].VirtualAddress + pSectionHeader[i].PointerToRawData;
		}
	}
}
void encryptData() {
	struct AES_ctx ctx;
	unsigned char key[] = "\xde\xad\xbe\xef\xca\xfe\xba\xbe\xde\xad\xbe\xef\xca\xfe\xba\xbe";
	unsigned char iv[] = "\xf0\xf1\xf2\xf3\xf4\xf5\xf6\xf7\xf8\xf9\xfa\xfb\xfc\xfd\xfe\xff";
	srand(time(NULL));
	for (size_t i = 0; i < sizeof(key); i++)
	{
		key[i] = rand() % 0x100; 
		iv[i] = rand() % 0x100;
	}

	FILE* pfile = NULL;
	long lFileSize = 0;
	unsigned char* pFileData = NULL;
	unsigned char pSzOutData[0x100] = { 0 };
	//文件生成时间
	char formattedTime[22] = { 0 };

	char currentPath[MAX_PATH] = { 0 };
	GetCurrentDirectoryA(MAX_PATH, currentPath);
	char fileName[15] = "SSS_Drivers.sys";
	char gang[5] = "\\";
	char currentPath2[MAX_PATH] = { 0 };
	memcpy(currentPath2, currentPath, sizeof(currentPath));
	memcpy(currentPath2 + strlen(currentPath) * sizeof(char), gang, sizeof(gang));
	memcpy(currentPath2 + strlen(currentPath2) * sizeof(char), fileName, sizeof(fileName));
	printf("%s \r\n", currentPath2);
	fopen_s(&pfile, currentPath2, "rb");
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
	pfile = NULL;

	//写出文件
	fopen_s(&pfile, "C:\\DriverCodes\\HideDriver\\NickolasZhao\\NewLoader\\MyDriver.h", "w");
	if (!pfile)
	{
		printf("写出文件失败");
		return 0;
	}

	//remove debug
	PIMAGE_DOS_HEADER pDosImage = (PIMAGE_DOS_HEADER)pFileData;
	PIMAGE_NT_HEADERS pNtsImage = (PIMAGE_NT_HEADERS)(pFileData + pDosImage->e_lfanew);

	//删除调试信息
	DWORD _PE_DEBUG = pNtsImage->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG].VirtualAddress;
	DWORD addr = rav2Fov(pFileData, _PE_DEBUG);
	ULONG dbgDirCount = pNtsImage->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG].Size / sizeof(IMAGE_DEBUG_DIRECTORY);
	PIMAGE_DEBUG_DIRECTORY pDEBUG = (PIMAGE_DEBUG_DIRECTORY)(addr + pFileData);
	for (size_t i = 0; i < dbgDirCount; i++)
	{
		memset(pDEBUG[i].PointerToRawData + pFileData, 0x00, pDEBUG[i].SizeOfData);
	}
	memset(addr + pFileData, 0xcc, pNtsImage->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG].Size);
	pNtsImage->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG].VirtualAddress = 0;
	pNtsImage->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG].Size = 0;



	//填写文件数据 
	GetCurrentTimeStr(formattedTime);
	sprintf_s(pSzOutData, 0x100, "//%s\r\n#pragma once\r\n", formattedTime);
	fputs(pSzOutData, pfile);
	sprintf_s(pSzOutData, 0x100, "//%s\r\n", currentPath2);
	fputs(pSzOutData, pfile);


	//生成key
	sprintf_s(pSzOutData, 0x100, "unsigned char key[] ={");
	fputs(pSzOutData, pfile);
	for (size_t i = 0; i < sizeof(key); i++)
	{
		sprintf_s(pSzOutData, 0x100, "0x%02x, ", key[i]);
		fputs(pSzOutData, pfile);
	}
	fputs("};\r\n", pfile);

	//生成IV
	sprintf_s(pSzOutData, 0x100, "unsigned char iv[] ={");
	fputs(pSzOutData, pfile);
	for (size_t i = 0; i < sizeof(iv); i++)
	{
		sprintf_s(pSzOutData, 0x100, "0x%02x, ", iv[i]);
		fputs(pSzOutData, pfile);
	}
	fputs("};\r\n", pfile);


	sprintf_s(pSzOutData, 0x100, "#define FILE_LEN %d \r\n", lFileSize);
	fputs(pSzOutData, pfile);
	sprintf_s(pSzOutData, 0x100, "unsigned char fileData[FILE_LEN]={", lFileSize);
	fputs(pSzOutData, pfile);


	AES_init_ctx_iv(&ctx, key, iv);
	AES_CTR_xcrypt_buffer(&ctx, (uint8_t*)pFileData, lFileSize);


	unsigned char magic[] = "\x89\x50\x4e\x47";
	unsigned char prebuff[17 + 17 + 4] = { 0 };
	memcpy(prebuff, magic, 4);
	memcpy(prebuff + 4, key, 17);
	memcpy(prebuff + 4 + 17, iv, 17);
	int encryptSize = lFileSize + sizeof(prebuff);
	PCHAR encryptData = (PCHAR)malloc(encryptSize);
	memset(encryptData, 0, encryptSize);
	memcpy(encryptData, prebuff, sizeof(prebuff));
	memcpy(encryptData + sizeof(prebuff), pFileData, lFileSize);

	char nencryptfileName[20] = "banner.png";
	writeFile(nencryptfileName, (PUCHAR)encryptData, encryptSize);

 




	for (size_t i = 0; i < lFileSize; i++)
	{
		//换行输出
		if (i % 16 == 0)
		{
			fputs("\r\n", pfile);
		}
		sprintf_s(pSzOutData, 0x100, "0x%02x, ", pFileData[i]);
		fputs(pSzOutData, pfile);
	}
	fputs("\r\n};\r\n", pfile);

	free(pFileData);
	fclose(pfile);
	pfile = NULL;


}
void NoEncryptData() {

	FILE* pfile = NULL;
	long lFileSize = 0;
	unsigned char* pFileData = NULL;
	unsigned char pSzOutData[0x100] = { 0 };
	//文件生成时间
	char formattedTime[22] = { 0 };

	char currentPath[MAX_PATH] = { 0 };
	GetCurrentDirectoryA(MAX_PATH, currentPath);
	char fileName[15] = "SSS_Drivers.sys";
	char gang[5] = "\\";
	char currentPath2[MAX_PATH] = { 0 };
	memcpy(currentPath2, currentPath, sizeof(currentPath));
	memcpy(currentPath2 + strlen(currentPath) * sizeof(char), gang, sizeof(gang));
	memcpy(currentPath2 + strlen(currentPath2) * sizeof(char), fileName, sizeof(fileName));
	printf("%s \r\n", currentPath2);
	fopen_s(&pfile, currentPath2, "rb");
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
	pfile = NULL;

	//写出文件
	fopen_s(&pfile, "C:\\DriverCodes\\HideDriver\\NickolasZhao\\NewLoader\\MyDriver2.h", "w");
	if (!pfile)
	{
		printf("写出文件失败");
		return 0;
	}
	//填写文件数据 
	GetCurrentTimeStr(formattedTime);
	sprintf_s(pSzOutData, 0x100, "//%s\r\n#pragma once\r\n", formattedTime);
	fputs(pSzOutData, pfile);
	sprintf_s(pSzOutData, 0x100, "//%s\r\n", currentPath2);
	fputs(pSzOutData, pfile);
	fputs("#define COUNT1 0x6C\r\n", pfile);
	fputs("#define COUNT2 0x7D\r\n", pfile);
	sprintf_s(pSzOutData, 0x100, "#define FILE_LEN2 %d \r\n", lFileSize);
	fputs(pSzOutData, pfile);
	sprintf_s(pSzOutData, 0x100, "unsigned char fileData2[FILE_LEN2]={", lFileSize);
	fputs(pSzOutData, pfile);
	////抹除mz标记
	//*(unsigned short*)(pFileData) = 0;
	////抹除PE标记
	//*(unsigned int*)(pFileData + *(unsigned short*)(pFileData + 0x3c)) = 0;

	for (size_t i = 0; i < lFileSize; i++)
	{
		//换行输出
		if (i % 16 == 0)
		{
			fputs("\r\n", pfile);
		}
		sprintf_s(pSzOutData, 0x100, "0x%02X, ", pFileData[i]);
		fputs(pSzOutData, pfile);
	}
	fputs("\r\n};\r\n", pfile);

	free(pFileData);
	fclose(pfile);
	pfile = NULL;


}
//
//void validate_data() {
//
//	for (size_t i = 0; i < FILE_LEN; i++)
//	{
//		//换行输出
//		if (fileData[i] == fileData2[i])
//		{
//			printf("0x%02X, 0x%02X \r\n", fileData[i],fileData2[i]);
//		}
//	}
//
//}

int main(int args, char* argv[], char** env) {
	encryptData();

	return 0;
}