#pragma once
#include "../includes.h"

namespace win32k_service {

	extern   PUCHAR pImageBase;
	extern PUCHAR FileData = 0;
	extern ULONG FileSize = 0;
	NTSTATUS InitializeWin32uDLL();
	void DeinitializeWin32uDLL();
	ULONG_PTR GetFuncAddrByExportName(PCHAR funcName);

}

