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



}
