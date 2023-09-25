#pragma once
#include "structs.h"
#include "aes.h"

 
 
BOOL  DriverHookInit();

DWORD HookComm(ULONG type, PVOID inData, ULONG inSize);

typedef INT64(*FNtUserGetPointerProprietaryId)(uintptr_t);
typedef BOOLEAN(NTAPI* FNtUserGetWindowPlacement)(HANDLE 	hWnd, uintptr_t lpwndpl);
typedef BOOLEAN(NTAPI* FNtUserGetTitleBarInfo)(HANDLE 	hwnd, uintptr_t 	pti);
typedef BOOLEAN(NTAPI* FNtUserGetScrollBarInfo)(HANDLE 	hWnd, LONG 	idObject, uintptr_t 	psbi);

 