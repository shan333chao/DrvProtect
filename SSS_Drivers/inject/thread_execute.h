#include "../includes.h"
NTSTATUS   CreateInjectThread(PEPROCESS pEprocess, ULONG64 moduleBase, ULONG64 entryPoint, ULONG64 kernelModuleBase);