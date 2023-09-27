#include "Comm/CommR3.h"

#include <windows.h>
typedef struct _handle_information
{
	wchar_t name[100];
	unsigned long stamp;
}handle_information, * phandle_information;
#define CLEAR_TRACE CTL_CODE(FILE_DEVICE_UNKNOWN, 0x810, METHOD_OUT_DIRECT, FILE_ANY_ACCESS)
typedef struct _FWindowInfo {
	ULONG pid;
	HWND wndHw;
	ULONG tid;
}FWindowInfo, * PFWindowInfo;




void InitDriver();
void TestComm(PVOID regCode, ULONG size);
void FakeReadMemory(ULONG		PID, ULONG fakePid, PVOID	Address, ULONG		uDataSize);
void FakeWriteMemory(ULONG		PID, ULONG fakePid, PVOID	Address, PUCHAR pValBuffer,ULONG length);
void PhyReadMemory(ULONG		PID, PVOID	Address, ULONG		uDataSize);
BOOL PhyWriteMemory(ULONG		PID, PVOID	Address, PUCHAR		pValBuffer, ULONG length);


void ProtectProcess(ULONG protectPid, ULONG fakePid);
void ProtectWindow(ULONG32 hwnd);
void QueryModule(ULONG pid, PCHAR szModuleName);

PUCHAR AllocateMem(ULONG PID, ULONG uDataSize);
void CreateMyThread(ULONG PID, PUCHAR shellcode, ULONG len);
