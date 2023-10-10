#include "CommR3.h"
#include "lib/structs.h"
#include "lib/xor.h"
#include <random>
namespace comm_r3 {

	static HANDLE   gDeviceHandle;
	static FNtUserGetWindowPlacement  g_NtUserGetWindowPlacement = 0;
	static FNtUserGetTitleBarInfo   g_NtUserGetTitleBarInfo = 0;
	static FNtUserGetScrollBarInfo  g_NtUserGetScrollBarInfo = 0;
	static FNtUserGetPointerProprietaryId g_NtUserGetPointerProprietaryId = 0;


	BOOL DriverHookInit()
	{
		HMODULE win32udll = GetModuleHandleA(skCrypt("win32u.dll")); 
		if (!win32udll)
		{
			return FALSE;
		}
		g_NtUserGetWindowPlacement = (FNtUserGetWindowPlacement)GetProcAddress(win32udll, skCrypt("NtUserGetWindowPlacement"));
		g_NtUserGetTitleBarInfo = (FNtUserGetTitleBarInfo)GetProcAddress(win32udll, skCrypt("NtUserGetTitleBarInfo"));
		g_NtUserGetScrollBarInfo = (FNtUserGetScrollBarInfo)GetProcAddress(win32udll, skCrypt("NtUserGetScrollBarInfo"));
		g_NtUserGetPointerProprietaryId = (FNtUserGetPointerProprietaryId)GetProcAddress(win32udll, skCrypt("NtUserGetPointerProprietaryId"));
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
		// 创建随机数生成器
		std::random_device rd;
		std::mt19937 gen(rd());
		// 创建均匀分布对象，指定随机数范围
		std::uniform_int_distribution<> dis(0, 3);
		// 生成随机数
		int seed = dis(gen);
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
}