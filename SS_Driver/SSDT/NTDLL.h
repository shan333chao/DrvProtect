#pragma once
#include <ntifs.h>
NTSTATUS InitializeNTDLL();
void DeinitializeNTDLL();
int GetExportSsdtIndex(PCHAR ExportName);


static PUCHAR FileData;
static ULONG FileSize;