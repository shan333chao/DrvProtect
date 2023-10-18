#pragma once
#include "Process.h"
#include "../SSDT/Functions.h"


//0x8 bytes (sizeof)
typedef struct _SE_AUDIT_PROCESS_CREATION_INFO
{
	POBJECT_NAME_INFORMATION ImageFileName;                         //0x0
}SE_AUDIT_PROCESS_CREATION_INFO, * PSE_AUDIT_PROCESS_CREATION_INFO;
 
namespace fuck_process {

	NTSTATUS FakeProcess(ULONG_PTR pid, ULONG_PTR fakePid);

	NTSTATUS RemoveProcessProtect(ULONG_PTR pid,BOOLEAN isProtect);
	bool  Unlock_File_Mode1(PEPROCESS eprocess);
}




 

