#pragma once
#include "ProtectWindow/ProtectWindow.h"
#include "ProtectWindow/ProtectWindow7.h"

namespace ProtectRoute {

	NTSTATUS StartProtect();

	NTSTATUS InitProtectWindow();
	NTSTATUS AntiSnapWindow(ULONG32 hwnd);
	BOOLEAN RemoveProtectWindow();
	HANDLE  GetWindowThread(HANDLE hwnd);


}