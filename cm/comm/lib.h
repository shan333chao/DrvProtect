#include "CommR3.h"
#include <stdio.h>
#include <windows.h>
#include <stdio.h>
#include <string.h>



BOOL InitDriver();
BOOL init();
BOOL FakeReadMemory(ULONG		PID, ULONG fakePid, PVOID	Address, ULONG		uDataSize);
BOOL FakeWriteMemory(ULONG		PID, ULONG fakePid, PVOID	Address, PUCHAR pValBuffer,ULONG length);
BOOL PhyReadMemory(ULONG		PID, PVOID	Address, ULONG		uDataSize);
BOOL PhyWriteMemory(ULONG		PID, PVOID	Address, PUCHAR		pValBuffer, ULONG length);


BOOL ProtectProcess(ULONG protectPid, ULONG fakePid);
BOOL ProtectWindow(ULONG32 hwnd);
BOOL QueryModule(ULONG pid, PCHAR szModuleName);

PUCHAR AllocateMem(ULONG PID, ULONG uDataSize);
BOOL CreateMyThread(ULONG PID, PUCHAR shellcode, ULONG len);
