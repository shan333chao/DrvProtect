#pragma once
#include <ntifs.h>
#include <ntimage.h>
#define PE_ERROR_VALUE (ULONG)-1


PVOID GetPageBase(PVOID lpHeader, ULONG* Size, PVOID ptr);
ULONG GetExportOffset(const PUCHAR FileData, ULONG FileSize, const PCHAR ExportName);