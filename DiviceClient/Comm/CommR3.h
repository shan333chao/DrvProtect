#pragma once
#include "../../SSS_Drivers/Comm/CommStructs.h"


BOOLEAN DriverInit();
DWORD DriverComm(ULONG type, PVOID inData, ULONG inSize, PVOID outData, ULONG outSize);