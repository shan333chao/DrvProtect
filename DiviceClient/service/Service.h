#pragma once
#include <Windows.h>
ULONG CreateServiceAndStartX86(PCHAR driverPath,PCHAR driverName);
ULONG CreateServiceAndStartX64(PCHAR driverPath, PCHAR driverName);
