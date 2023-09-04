#pragma once
#include <ntifs.h>
extern   PUCHAR pImageBase;
extern PUCHAR FileData = 0;
extern ULONG FileSize = 0;
NTSTATUS InitializeWin32uDLL();
void DeinitializeWin32uDLL();
ULONG_PTR GetFuncAddrByExportName(PCHAR funcName);