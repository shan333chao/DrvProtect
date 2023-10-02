#include "CommR3.h"
#include <time.h>

static HANDLE   gDeviceHandle;
static FNtUserGetWindowPlacement  g_NtUserGetWindowPlacement = 0;
static FNtUserGetTitleBarInfo   g_NtUserGetTitleBarInfo = 0;
static FNtUserGetScrollBarInfo  g_NtUserGetScrollBarInfo = 0;
static FNtUserGetPointerProprietaryId g_NtUserGetPointerProprietaryId = 0;


BOOL DriverHookInit()
{

	HMODULE win32udll = LoadLibraryA("win32u.dll");
	if (!win32udll)
	{
		return FALSE; 
	}
	g_NtUserGetWindowPlacement = (FNtUserGetWindowPlacement)GetProcAddress(win32udll, "NtUserGetWindowPlacement");
	g_NtUserGetTitleBarInfo = (FNtUserGetTitleBarInfo)GetProcAddress(win32udll, "NtUserGetTitleBarInfo");
	g_NtUserGetScrollBarInfo = (FNtUserGetScrollBarInfo)GetProcAddress(win32udll, "NtUserGetScrollBarInfo");
	g_NtUserGetPointerProprietaryId = (FNtUserGetPointerProprietaryId)GetProcAddress(win32udll, "NtUserGetPointerProprietaryId");
	FreeLibrary(win32udll);
	return TRUE;
}

//hookͨ
DWORD HookComm(ULONG type, PVOID inData, ULONG inSize)
{
	if (!g_NtUserGetScrollBarInfo && !g_NtUserGetWindowPlacement && !g_NtUserGetTitleBarInfo && !g_NtUserGetPointerProprietaryId)
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
	return res ? commData.status : 1;
}