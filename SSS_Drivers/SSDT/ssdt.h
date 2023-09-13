#ifndef _SSDT_H
#define _SSDT_H


#pragma once
#include "../includes.h"


namespace ssdt_serv {
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
	}SSDTStruct, * PSSDTStruct;
	PSSDTStruct InitSSDTAndShadow(BOOLEAN IsShadowSSDT);


	ULONG64 GetWin32kFunc10(PCHAR funcName);
	PVOID  GetFunctionAddrInSSDT(ULONG serviceNum);

}
#endif // !_SSDT_H