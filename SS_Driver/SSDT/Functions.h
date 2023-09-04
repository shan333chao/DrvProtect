#pragma once
#include <ntifs.h>
#include "ssdt.h"

typedef  NTSTATUS(NTAPI* PNtProtectVirtualMemory)(__in HANDLE ProcessHandle, __inout PVOID* BaseAddress, __inout PSIZE_T RegionSize, __in ULONG NewProtectWin32, __out PULONG OldProtect);
PNtProtectVirtualMemory GetNtProtectVirtualMemory();
 

typedef  NTSTATUS(NTAPI* PNtCreateThreadEx)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, HANDLE, PVOID, PVOID, ULONG, SIZE_T, SIZE_T, SIZE_T, PVOID);
PNtCreateThreadEx GetNtCreateThreadEx();

ULONG GetNtFuncNumber(UNICODE_STRING funcName, UCHAR sig1, UCHAR sig2);
MODE SetThreadPrevious(PETHREAD Thread, MODE mode);
PPEB PsGetProcessPeb(__in PEPROCESS Process);
PVOID PsGetProcessWow64Process(__in PEPROCESS Process);
NTSTATUS MmCopyVirtualMemory(
    IN PEPROCESS FromProcess,
    IN CONST VOID* FromAddress,
    IN PEPROCESS ToProcess,
    OUT PVOID ToAddress,
    IN SIZE_T BufferSize,
    IN KPROCESSOR_MODE PreviousMode,
    OUT PSIZE_T NumberOfBytesCopied
);

ULONG GetFunctionVariableOffset(PUCHAR funcName, ULONG asmOffset);