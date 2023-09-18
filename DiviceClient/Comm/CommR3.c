#include "CommR3.h"
#include <stdio.h>

#include <stdlib.h>
#include <time.h>

static HANDLE   gDeviceHandle;
static FNtUserGetWindowPlacement  g_NtUserGetWindowPlacement = 0;
static FNtUserGetTitleBarInfo   g_NtUserGetTitleBarInfo = 0;
static FNtUserGetScrollBarInfo  g_NtUserGetScrollBarInfo = 0;
static FNtUserGetPointerProprietaryId g_NtUserGetPointerProprietaryId = 0;


BOOLEAN DriverInit() {
	gDeviceHandle = CreateFileA(SYMBOL_NAME,
		FILE_GENERIC_READ | FILE_GENERIC_WRITE,
		FILE_SHARE_READ | FILE_SHARE_WRITE,
		NULL,
		OPEN_EXISTING,
		FILE_ATTRIBUTE_NORMAL,
		0
	);
	if (gDeviceHandle == NULL || gDeviceHandle == INVALID_HANDLE_VALUE)
	{
		gDeviceHandle = NULL;
		printf("CreateFileW error 0x%08x \r\n", GetLastError());
		return FALSE;
	}
	//printf("CreateFileW success 0x%p \r\n", &gDeviceHandle);
	return TRUE;
}

DWORD DriverComm(ULONG type, PVOID inData, ULONG inSize) {
	return HookComm(type, inData, inSize);
}

//设备通讯
BOOLEAN DeviceComm(ULONG type, PVOID inData, ULONG inSize) {

	if (!gDeviceHandle || gDeviceHandle == INVALID_HANDLE_VALUE)
	{
		DriverInit();
	}
	if (gDeviceHandle)
	{
		COMM_DATA commData = { 0 };
		commData.Type = type;
		commData.InData = (ULONG64)inData;
		commData.InDataLen = inSize;
		commData.ID = COMM_ID;
		SIZE_T dwSize = 0;
		BOOL res = DeviceIoControl(gDeviceHandle, NULL, &commData, sizeof(COMM_DATA), &commData, sizeof(COMM_DATA), &dwSize, NULL);
		printf("通讯结果 %08x \n", commData.status);
		return res ? commData.status : 1;
	}
	return FALSE;

}

BOOL DriverHookInit()
{
	g_NtUserGetWindowPlacement = (FNtUserGetWindowPlacement)GetProcAddress(LoadLibraryA("win32u.dll"), "NtUserGetWindowPlacement");
	g_NtUserGetTitleBarInfo = (FNtUserGetTitleBarInfo)GetProcAddress(LoadLibraryA("win32u.dll"), "NtUserGetTitleBarInfo");
	g_NtUserGetScrollBarInfo = (FNtUserGetScrollBarInfo)GetProcAddress(LoadLibraryA("win32u.dll"), "NtUserGetScrollBarInfo");
	g_NtUserGetPointerProprietaryId = (FNtUserGetPointerProprietaryId)GetProcAddress(LoadLibraryA("win32u.dll"), "NtUserGetPointerProprietaryId");
	return TRUE;
}




BOOLEAN MyNtUserGetScrollBarInfo(HANDLE hWnd, LONG idObject, uintptr_t psbi)
{


	return g_NtUserGetScrollBarInfo(hWnd, idObject, psbi);
}
//hook通讯
DWORD HookComm(ULONG type, PVOID inData, ULONG inSize)
{
	if (!g_NtUserGetScrollBarInfo || !g_NtUserGetWindowPlacement || !g_NtUserGetTitleBarInfo)
	{
		DriverHookInit();

	}
	srand(time(NULL));
	int seed = rand() % 4;
	COMM_DATA commData = { 0 };
	commData.Type = type;
	commData.InData = (ULONG64)inData;
	commData.InDataLen = inSize;
	commData.ID = COMM_ID;
	SIZE_T dwSize = 0;
	BOOL res = FALSE;
	switch (seed)
	{

	case 0: {
		res = g_NtUserGetPointerProprietaryId((uintptr_t)(&commData));
		break;
	}
	case 1: {
		res = g_NtUserGetWindowPlacement((HANDLE)0x10010, (uintptr_t)(&commData));
		break;
	}
	case 2: {
		res = g_NtUserGetTitleBarInfo((HANDLE)0x10010, (uintptr_t)(&commData));
		break;
	}
	case 3: {
		res = g_NtUserGetScrollBarInfo((HANDLE)0x10010, 1, (uintptr_t)(&commData));
		break;
	}
	default:
		break;
	} 
	printf("hook %d 通讯结果 %08x \n", seed, commData.status);
	return res ? commData.status : 1;
}