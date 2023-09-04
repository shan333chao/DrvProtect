#pragma once
#include <ntifs.h>
 

//structures
typedef  struct _SSDTStruct
{
	LONG* pServiceTable;
	PVOID pCounterTable;
#ifdef _WIN64
	ULONGLONG NumberOfServices;
#else
	ULONG NumberOfServices;
#endif
	PCHAR pArgumentTable;
}SSDTStruct,*PSSDTStruct;



PSSDTStruct InitSSDTAndShadow(BOOLEAN IsShadowSSDT);
//PVOID  GetSSDTFunctionAddress(ULONG serviceNum);
PVOID  GetFunctionAddrInSSDT(ULONG serviceNum);