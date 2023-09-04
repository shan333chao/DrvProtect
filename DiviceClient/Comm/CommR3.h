#pragma once
#include "../../SS_Driver/Comm/CommStructs.h"


BOOLEAN DriverInit();
DWORD DriverComm(ULONG type, PVOID inData, ULONG inSize, PVOID outData, ULONG outSize);