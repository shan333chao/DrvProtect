#pragma once
#include <Windows.h>
typedef INT64(*FNtUserGetPointerProprietaryId)(uintptr_t);
typedef BOOLEAN(NTAPI* FNtUserGetWindowPlacement)(HANDLE 	hWnd, uintptr_t lpwndpl);
typedef BOOLEAN(NTAPI* FNtUserGetTitleBarInfo)(HANDLE 	hwnd, uintptr_t 	pti);
typedef BOOLEAN(NTAPI* FNtUserGetScrollBarInfo)(HANDLE 	hWnd, LONG 	idObject, uintptr_t 	psbi);

namespace comm_r3 {

	BOOL  DriverHookInit();

	DWORD HookComm(ULONG type, PVOID inData, ULONG inSize);



}
 


 