#include "CommR3.h"
#include <stdio.h>


static HANDLE   gDeviceHandle;

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

DWORD DriverComm(ULONG type, PVOID inData, ULONG inSize, PVOID outData, ULONG outSize) {
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
		commData.OutData = (ULONG64)outData;
		commData.OutDataLen = outSize;
		commData.ID = COMM_ID;
		SIZE_T dwSize = 0;
		BOOL res=DeviceIoControl(gDeviceHandle, NULL, &commData, sizeof(COMM_DATA), &commData, sizeof(COMM_DATA), &dwSize, NULL);
		printf("通讯结果 %08x \n", commData.status);
		return res?commData.status:1;
	}
	return FALSE;
}