
#ifndef  _FUNCIONS_H
#define _FUNCIONS_H
#pragma once 
#include "ssdt.h"

typedef  NTSTATUS(NTAPI* PNtProtectVirtualMemory)(__in HANDLE ProcessHandle, __inout PVOID* BaseAddress, __inout PSIZE_T RegionSize, __in ULONG NewProtectWin32, __out PULONG OldProtect);

typedef  NTSTATUS(NTAPI* PNtCreateThreadEx)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, HANDLE, PVOID, PVOID, ULONG, SIZE_T, SIZE_T, SIZE_T, PVOID);
namespace functions { 

	PNtCreateThreadEx GetNtCreateThreadEx(); 
	//设置先前模式 因为nt 开头的函数 会被etw记录
	MODE SetThreadPrevious(PETHREAD Thread, MODE mode); 
	PNtProtectVirtualMemory GetNtProtectVirtualMemory();
	ULONG GetNtFuncNumber(PUNICODE_STRING funcName, UCHAR sig1, UCHAR sig2);
	ULONG GetFunctionVariableOffset(PCWSTR funcName, ULONG asmOffset); 
	ULONG GetProtectVirtualMemoryIdx();
}
#endif // ! _FUNCIONS_H