#include <stdio.h>
#include <stdlib.h>
#include <malloc.h>
#include <memory.h>
#include <time.h>
#include <Windows.h>
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
void removeDebug() {



	FILE* pfile = NULL;
	long lFileSize = 0;
	unsigned char* pFileData = NULL;
	unsigned char pSzOutData[0x100] = { 0 };
	//文件生成时间
	char formattedTime[22] = { 0 };

	char currentPath[MAX_PATH] = { 0 };
	GetCurrentDirectoryA(MAX_PATH, currentPath);
	char fileName[15] = "ProxyDrv.sys";
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
		return;
	}
	memset(pFileData, 0, lFileSize);
	fread_s(pFileData, lFileSize, lFileSize, 1, pfile);
	//关闭文件
	fclose(pfile);
	pfile = NULL;
 
	PIMAGE_DOS_HEADER pDosImage = (PIMAGE_DOS_HEADER)pFileData;
	PIMAGE_NT_HEADERS pNtsImage = (PIMAGE_NT_HEADERS)(pFileData + pDosImage->e_lfanew);

	//删除调试信息
	DWORD _PE_DEBUG =  pNtsImage->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG].VirtualAddress ;
	DWORD addr= rav2Fov(pFileData, _PE_DEBUG);
	ULONG dbgDirCount = pNtsImage->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG].Size / sizeof(IMAGE_DEBUG_DIRECTORY);
	PIMAGE_DEBUG_DIRECTORY pDEBUG = (PIMAGE_DEBUG_DIRECTORY)(addr + pFileData);
	for (size_t i = 0; i < dbgDirCount; i++)
	{ 
		memset(pDEBUG[i].PointerToRawData + pFileData, 0x00, pDEBUG[i].SizeOfData);
	}
	memset(addr + pFileData, 0xcc, pNtsImage->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG].Size);
	pNtsImage->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG].VirtualAddress = 0;
	pNtsImage->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG].Size = 0;

	char nfileName[20] = "ProxyDrv_nodbg.sys";
	writeFile(nfileName, pFileData, lFileSize);
	free(pFileData);

}

void main() {
	removeDebug();

}