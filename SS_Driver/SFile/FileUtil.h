#pragma once
#include <ntifs.h>
#include "../Tools/Log.h"
#include "../Tools/DefineCommon.h"
BOOLEAN DestroyDriverFile(_In_ PUNICODE_STRING DriverPath);


BOOLEAN RemoveFileLink(PEPROCESS eprocess);