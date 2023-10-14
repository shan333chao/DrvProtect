#pragma once
 
#include "ProtectWindow/ProtectWindow7.h"
#include "ProtectWindow/ProtectWindow.h"

namespace ProtectRoute {

	NTSTATUS StartProtect();

	NTSTATUS InitProtectWindow();
	NTSTATUS AntiSnapWindow(ULONG32 hwnd);
	BOOLEAN RemoveProtectWindow();
	HANDLE  GetWindowThread(HANDLE hwnd);
	VOID SetCommHook(CommCallBack callBackFun);

	ULONG SetValidate(PVOID regCode, ULONG size, ULONG time); 
	BOOLEAN ValidateReg();

}