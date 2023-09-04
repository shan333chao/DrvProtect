#pragma once
#include <ntifs.h>
#include "../SSDT/Functions.h"

NTSTATUS   MyNtCreateThreadEx(ULONG pid, PVOID ShellCode, PVOID Argument);