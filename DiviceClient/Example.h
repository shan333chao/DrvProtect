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



 
void TestComm(PVOID regCode);
void FakeReadMemory(ULONG		PID, ULONG fakePid, PVOID	Address, ULONG		uDataSize);
void FakeWriteMemory(ULONG		PID, ULONG fakePid, PVOID	Address, PUCHAR pValBuffer,ULONG length);
void PhyReadMemory(ULONG		PID, PVOID	Address, ULONG		uDataSize);
BOOL PhyWriteMemory(ULONG		PID, PVOID	Address, PUCHAR		pValBuffer, ULONG length);

void ProtectProcessR3(ULONG pid ,BOOLEAN isProcect);

void ProtectProcess(ULONG protectPid, ULONG fakePid);
void ProtectWindow(ULONG32 hwnd);
void QueryModule(ULONG pid, PCHAR szModuleName, UCHAR type);
void QueryVADModule(ULONG pid, PCHAR szModuleName);
PUCHAR AllocateMem(ULONG PID, ULONG uDataSize);
void CreateMyThread(ULONG PID, PUCHAR shellcode, ULONG len);

void SearchPattern(ULONG pid,PCHAR szModuleName, PCHAR pattern, PCHAR mask);

void InjectX64DLL(ULONG pid, PCHAR dllFilePath);

 
void WriteX64DLL(ULONG PID, PCHAR dllFilePath);
void CALL_MAIN_THREAD(ULONG PID, ULONG64 shellcodeAddr, ULONG shellcodeLen);
void GetModuleExportAddr(ULONG pid, PCHAR ModuleName, PCHAR ExportFuncName);
ULONG CHANGE_MEMORY_ATTR(ULONG PID, ULONG64 address, ULONG length);