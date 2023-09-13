#include <stdio.h>
#include <stdlib.h>
#include <malloc.h>
#include <memory.h>
#include <time.h>
#include <Windows.h>
#include "aes.h"
//#include "../DisapperDriver/MyDriver.h"
//#include "../DisapperDriver/MyDriver2.h"
#define COUNT1 0x6C
#define COUNT2 0x7D
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

void encryptData() {

	FILE* pfile = NULL;
	long lFileSize = 0;
	unsigned char* pFileData = NULL;
	unsigned char pSzOutData[0x100] = { 0 };
	//文件生成时间
	char formattedTime[22] = { 0 };

	char currentPath[MAX_PATH] = { 0 };
	GetCurrentDirectoryA(MAX_PATH, currentPath);
	char fileName[15] = "SSS_Driver.sys";
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
	fopen_s(&pfile, "C:\\DriverCodes\\HideDriver\\驱动隐藏\\DisapperDriver\\MyDriver.h", "w");
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
	sprintf_s(pSzOutData, 0x100, "#define FILE_LEN %d \r\n", lFileSize);
	fputs(pSzOutData, pfile);
	sprintf_s(pSzOutData, 0x100, "unsigned char fileData[FILE_LEN]={", lFileSize);
	fputs(pSzOutData, pfile);
	//抹除mz标记
	*(unsigned short*)(pFileData) = 0;
	//抹除PE标记
	*(unsigned int*)(pFileData + *(unsigned short*)(pFileData + 0x3c)) = 0;
	int count = COUNT1;
	for (size_t i = 0; i < lFileSize; i++)
	{
		//换行输出
		if (i % 16 == 0)
		{
			fputs("\r\n", pfile);
		}
		if (pFileData[i] != 0)
		{
			if (i % 2 == 0)
			{
				count = COUNT2;
			}
			for (size_t t = 11; t < count; t++)
			{
				if (pFileData[i] != t)
				{
					pFileData[i] ^= t;
				}
			}
		}
		count = COUNT1;
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
	char fileName[15] = "SS_Driver.sys";
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
	fopen_s(&pfile, "C:\\DriverCodes\\HideDriver\\驱动隐藏\\DisapperDriver\\MyDriver.h", "w");
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
	sprintf_s(pSzOutData, 0x100, "#define FILE_LEN %d \r\n", lFileSize);
	fputs(pSzOutData, pfile);
	sprintf_s(pSzOutData, 0x100, "unsigned char fileData[FILE_LEN]={", lFileSize);
	fputs(pSzOutData, pfile);
	////抹除mz标记
	//*(unsigned short*)(pFileData) = 0;
	////抹除PE标记
	//*(unsigned int*)(pFileData + *(unsigned short*)(pFileData + 0x3c)) = 0;
	int count = COUNT1;
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


int main(int args, char* argv[], char** env) {
 
	NoEncryptData();
 
	return 0;
}