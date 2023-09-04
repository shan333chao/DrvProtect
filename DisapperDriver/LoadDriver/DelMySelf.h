#pragma once
#include <ntifs.h>


BOOLEAN DeleteMyself(PUNICODE_STRING filePath);

BOOLEAN DestroyDriverFile(_In_ PUNICODE_STRING DriverPath);