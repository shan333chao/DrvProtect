#pragma once
#include "../../SSS_Drivers/Comm/CommStructs.h"


BOOLEAN DriverInit();
DWORD DriverComm(ULONG type, PVOID inData, ULONG inSize);


BOOL  DriverHookInit();

DWORD HookComm(ULONG type, PVOID inData, ULONG inSize);
BOOLEAN DeviceComm(ULONG type, PVOID inData, ULONG inSize);

#ifdef _X86
#define CALL_TYPE __stdcall
#else
#define CALL_TYPE __fastcall
#endif // _X

 
typedef INT64(CALL_TYPE*FNtUserGetPointerProprietaryId)(uintptr_t);
typedef BOOLEAN(CALL_TYPE* FNtUserGetWindowPlacement)(HANDLE 	hWnd, uintptr_t lpwndpl);
typedef BOOLEAN(CALL_TYPE* FNtUserGetTitleBarInfo)(HANDLE 	hwnd, uintptr_t 	pti);
typedef BOOLEAN(CALL_TYPE* FNtUserGetScrollBarInfo)(HANDLE 	hWnd, LONG 	idObject, uintptr_t 	psbi);

 