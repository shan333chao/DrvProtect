#include "../../includes.h"

namespace pehelper86 {

	ULONG_PTR MyGetProcAddress(
		PVOID hModule,    // handle to DLL module  
		LPCSTR lpProcName,   // function name  
		PEPROCESS pEprocess
	);
	int DoRelocation(ULONG_PTR lpMemModule, PUCHAR virtualBase);
	ULONG GetImageSize(PUCHAR fileBuffer);
	VOID CleanPeHeader(PUCHAR base);
	BOOLEAN PELoaderDLL(PUCHAR fileBuffer, PUCHAR virtualBase, ULONG_PTR lpMemModule, PVOID* entrypoint, PEPROCESS pEprocess);
}