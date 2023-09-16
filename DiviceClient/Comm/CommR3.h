#pragma once
#include "../../SSS_Drivers/Comm/CommStructs.h"


BOOLEAN DriverInit();
DWORD DriverComm(ULONG type, PVOID inData, ULONG inSize);


BOOL  DriverHookInit();

DWORD HookComm(ULONG type, PVOID inData, ULONG inSize);
BOOLEAN DeviceComm(ULONG type, PVOID inData, ULONG inSize);

 
typedef INT64(*FNtUserGetPointerProprietaryId)(uintptr_t);
typedef BOOLEAN(NTAPI* FNtUserGetWindowPlacement)(HANDLE 	hWnd, uintptr_t lpwndpl);
typedef BOOLEAN(NTAPI* FNtUserGetTitleBarInfo)(HANDLE 	hwnd, uintptr_t 	pti);
typedef BOOLEAN(NTAPI* FNtUserGetScrollBarInfo)(HANDLE 	hWnd, LONG 	idObject, uintptr_t 	psbi);

BOOLEAN MyNtUserGetWindowPlacement(HANDLE hWnd, uintptr_t lpwndpl);

BOOLEAN MyNtUserGetTitleBarInfo(HANDLE hwnd, uintptr_t pti);

BOOLEAN MyNtUserGetScrollBarInfo(HANDLE hWnd, LONG idObject, uintptr_t psbi);