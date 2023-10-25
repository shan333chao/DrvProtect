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

inline int to_lower_imp(int c)
{
	if (c >= 'A' && c <= 'Z')
		return c + 'a' - 'A';
	else
		return c;
}
inline int strcmpi_imp(const char* s1, const char* s2)
{
	if (strlen(s1) != strlen(s2))
	{
		return 1;
	}
	while (*s1 && (to_lower_imp(*s1) == to_lower_imp(*s2)))
	{
		s1++;
		s2++;
	}
	return *(const unsigned char*)s1 - *(const unsigned char*)s2;
}
inline char* _strstr(const char* Str, const char* SubStr)
{
	char* v3; // r8
	char v5; // al
	signed __int64 i; // r9
	const char* v7; // rdx

	v3 = (char*)Str;
	if (!*SubStr)
		return (char*)Str;
	v5 = *Str;
	if (!*Str)
		return 0i64;
	for (i = Str - SubStr; ; ++i)
	{
		v7 = SubStr;
		if (v5)
			break;
	LABEL_9:
		if (!*v7)
			return v3;
		v5 = *++v3;
		if (!*v3)
			return 0i64;
	}
	while (*v7)
	{
		if (v7[i] == *v7)
		{
			++v7;
			if (v7[i])
				continue;
		}
		goto LABEL_9;
	}
	return v3;
}
PVOID  GetFuncExportName(_In_ PVOID ModuleBase, _In_ PCHAR FuncName);
PSSDTStruct InitSSDTAndShadow(BOOLEAN IsShadowSSDT);
//PVOID  GetSSDTFunctionAddress(ULONG serviceNum);
PVOID  GetFunctionAddrInSSDT(ULONG serviceNum);