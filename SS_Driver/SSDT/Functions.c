#pragma once
#include "Functions.h"
#include "ssdt.h"



PNtProtectVirtualMemory GetNtProtectVirtualMemory()
{
	static PNtProtectVirtualMemory NtProtectVirtualMemoryAddr = 0;
	if (NtProtectVirtualMemoryAddr)
	{
		return NtProtectVirtualMemoryAddr;
	}

	////.text : 00000001401BE203 50                            push    rax
	////.text : 00000001401BE204 B8 50 00 00 00                mov     eax, 50h; 'P'
	//ULONG serviceNum = 0;
	//UNICODE_STRING uFuncName = { 0 };
	//RtlInitUnicodeString(&uFuncName, L"ZwProtectVirtualMemory");
	//serviceNum = GetNtFuncNumber(uFuncName, 0x50u, 0xB8u);
	//if (serviceNum)
	//{

	//}
	NtProtectVirtualMemoryAddr = (PNtProtectVirtualMemory)GetFunctionAddrInSSDT(77);
	return NtProtectVirtualMemoryAddr;
}

PNtCreateThreadEx GetNtCreateThreadEx()
{
	static PNtCreateThreadEx PNtCreateThreadExAddr = 0;
	if (PNtCreateThreadExAddr)
	{
		return PNtCreateThreadExAddr;
	}
	ULONG serviceNum = 0;
	UNICODE_STRING uFuncName = { 0 };
	//NtCreateThreadEx 是未导出的函数  需要获取它的前一个函数的符号  然后加1
	RtlInitUnicodeString(&uFuncName, L"ZwCreateSymbolicLinkObject");
	serviceNum = GetNtFuncNumber(uFuncName, 0x50u, 0xB8u);
	if (serviceNum)
	{
		PNtCreateThreadExAddr = (PNtProtectVirtualMemory)GetFunctionAddrInSSDT(serviceNum + 1);
	}
	return PNtCreateThreadExAddr;

}

ULONG GetNtFuncNumber(UNICODE_STRING funcName, UCHAR sig1, UCHAR sig2)
{
	ULONG serviceNum = 0;
	PUCHAR pFunc = (PUCHAR)MmGetSystemRoutineAddress(&funcName);
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

//设置先前模式 因为nt 开头的函数 会被etw记录
MODE SetThreadPrevious(PETHREAD Thread, MODE mode)
{
	
	MODE mRet = -1;
	static ULONG uOffset = 0;
	UNICODE_STRING uFuncName = { 0 };
	RtlInitUnicodeString(&uFuncName, L"ExGetPreviousMode");
	PUCHAR pFunc = (PUCHAR)MmGetSystemRoutineAddress(&uFuncName);
	for (size_t i = 0; i < 0x25; i++)
	{
		if (pFunc[i] == 0xC3u)
		{
			uOffset = *(PULONG)(pFunc + i - 4);
			break;
		}
	}
	if (!uOffset) return -1;
	//备份默认模式
	mRet = *(PUCHAR)((PUCHAR)Thread + uOffset);
	//设置先前模式
	*(PUCHAR)((PUCHAR)Thread + uOffset) = mode;

	return mRet;
}

ULONG GetFunctionVariableOffset(PUCHAR funcName, ULONG asmOffset)
{
	UNICODE_STRING uFuncName = { 0 };
	RtlInitUnicodeString(&uFuncName, funcName);
	PUCHAR pFunc = (PUCHAR)MmGetSystemRoutineAddress(&uFuncName);
	ULONG offset = *(PULONG)(pFunc + asmOffset);

	return offset;
}
