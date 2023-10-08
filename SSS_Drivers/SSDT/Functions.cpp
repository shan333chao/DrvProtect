#pragma once
#include "Functions.h"

namespace functions {

	PNtCreateThreadEx GetNtCreateThreadEx()
	{
		static PNtCreateThreadEx PNtCreateThreadExAddr = 0;
		if (PNtCreateThreadExAddr)
		{
			return PNtCreateThreadExAddr;
		}
		ULONG serviceNum = 0;
		UNICODE_STRING uFuncName = { 0 };
		imports::rtl_init_unicode_string(&uFuncName, skCrypt(L"ZwCreateSymbolicLinkObject"));
		serviceNum = GetNtFuncNumber(&uFuncName, 0x50u, 0xB8u);
		if (serviceNum)
		{
			PNtCreateThreadExAddr = (PNtCreateThreadEx)ssdt_serv::GetFunctionAddrInSSDT(serviceNum + 1);
		}
		return PNtCreateThreadExAddr;
	}
	PNtProtectVirtualMemory GetNtProtectVirtualMemory()
	{
		static PNtProtectVirtualMemory NtProtectVirtualMemoryAddr = 0;
		if (NtProtectVirtualMemoryAddr)
		{
			return NtProtectVirtualMemoryAddr;
		}
		NtProtectVirtualMemoryAddr = (PNtProtectVirtualMemory)ssdt_serv::GetFunctionAddrInSSDT(GetProtectVirtualMemoryIdx());

		return NtProtectVirtualMemoryAddr;
	}

	//设置先前模式 因为nt 开头的函数 会被etw记录
	MODE SetThreadPrevious(PETHREAD Thread, MODE mode)
	{

		MODE mRet = UserMode;
		static ULONG uOffset = 0;

		PUCHAR pFunc = (PUCHAR)imports::imported.ex_get_previous_mode;
		for (size_t i = 0; i < 0x25; i++)
		{
			if (pFunc[i] == 0xC3u)
			{
				uOffset = *(PULONG)(pFunc + i - 4);
				break;
			}
		}
		if (!uOffset) return UserMode;
		//备份默认模式
		mRet = (MODE) * (PUCHAR)((PUCHAR)Thread + uOffset);
		//设置先前模式
		*(PUCHAR)((PUCHAR)Thread + uOffset) = mode;
		return mRet;
	}
	ULONG GetNtFuncNumber(PUNICODE_STRING funcName, UCHAR sig1, UCHAR sig2)
	{
		ULONG serviceNum = 0;
		PUCHAR pFunc = (PUCHAR)imports::mm_get_system_routine_address(funcName);
		for (size_t i = 0; i < 0x50; i++)
		{
			if (pFunc[i] == sig1 && pFunc[i + 1] == sig2)
			{
				serviceNum = *(PLONG32)(pFunc + i + 2);
				break;
			}
		}
		return serviceNum;
	}

	ULONG GetNtFuncNoByStr(wchar_t* funcStr) {
		UNICODE_STRING funcName = { 0 };
		imports::rtl_init_unicode_string(&funcName, funcStr);
		return GetNtFuncNumber(&funcName, 0x50, 0xB8);
	}

	ULONG GetFunctionVariableOffset(PCWSTR funcName, ULONG asmOffset)
	{
		UNICODE_STRING uFuncName = { 0 };
		imports::rtl_init_unicode_string(&uFuncName, funcName);
		PUCHAR pFunc = (PUCHAR)imports::mm_get_system_routine_address(&uFuncName);
		ULONG offset = *(PULONG)(pFunc + asmOffset);

		return offset;
	}

	ULONG GetProtectVirtualMemoryIdx()
	{

		switch (Utils::InitOsVersion().dwBuildNumber)
		{
		case 7601:
			return 77;
		case 9200:
			return 78;
		case 9600:
			return 79;

		default:
			return 80;
			break;
		}


	}

	ULONG GetNtSuspendThreadServNo() {
		switch (Utils::InitOsVersion().dwBuildNumber)
		{
		case 10061:
			return 420;
		case 10240:
			return 416;
		case 10586:
			return 419;
		case 14393:
			return 425;
		case 15063:
			return 434;
		case 17134:
			return 436;
		case 17763:
			return 437;
		case 18362:
		case 18363:
			return 438;
		case 19041:
			return 445;
		case 20348:
			return 451;
		case 22000:
			return 455;
		case 22621:
		case 22622:
		case 22623:
		case 22645:
		case 23451:
		case 23481:
			return 460;
		case 25905:
		case 25936:
			return 462;
		default:
			return 0;
			break;
		}

	}

	ULONGLONG GetFuncAddrInAddr(PUCHAR pFunc, UCHAR sig1, UCHAR sig2) {
		LONG64 offset = 0;
		ULONGLONG funcAddr = 0;
		size_t i = 0;
		for (; i < 0x150; i++)
		{
			if (pFunc[i] == sig1 && pFunc[i + 1] == sig2)
			{
				offset = *(PLONG32)(pFunc + i + 2);
				break;
			}
		}
		if (offset)
		{
			funcAddr = (ULONGLONG)(pFunc + i + 2 + 4 + offset);
		}
		return funcAddr;

	}


}
