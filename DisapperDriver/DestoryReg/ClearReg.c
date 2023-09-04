#include "ClearReg.h"
#include <ntstrsafe.h>
BOOLEAN DeleteRegeditEntry(PUNICODE_STRING regpath) {
 
	PWCHAR szPath[0x256] = { 0 };
	UNICODE_STRING uPathEnum = { 0 };
	//RTL_REGISTRY_ABSOLUTE代表绝对路径
	RtlDeleteRegistryValue(RTL_REGISTRY_ABSOLUTE, regpath->Buffer, L"DispalyName");
	RtlDeleteRegistryValue(RTL_REGISTRY_ABSOLUTE, regpath->Buffer, L"ErrorControl");
	RtlDeleteRegistryValue(RTL_REGISTRY_ABSOLUTE, regpath->Buffer, L"ImagePath");
	RtlDeleteRegistryValue(RTL_REGISTRY_ABSOLUTE, regpath->Buffer, L"Start");
	RtlDeleteRegistryValue(RTL_REGISTRY_ABSOLUTE, regpath->Buffer, L"Type");
	RtlDeleteRegistryValue(RTL_REGISTRY_ABSOLUTE, regpath->Buffer, L"WOW64");
	//寻找内层目录
	RtlStringCbPrintfW(szPath, 0x256, L"%ws\\Enum", regpath->Buffer); 
	DbgPrintEx(77, 0, "[SSS] szPath  %ws \r\n", szPath); 
	RtlInitUnicodeString(&uPathEnum, szPath);
	DbgPrintEx(77, 0, "[SSS] suPath  %wZ \r\n", uPathEnum);


	
	RtlDeleteRegistryValue(RTL_REGISTRY_ABSOLUTE, szPath, L"Count");
	RtlDeleteRegistryValue(RTL_REGISTRY_ABSOLUTE, szPath, L"INISTARTFAILED");
	RtlDeleteRegistryValue(RTL_REGISTRY_ABSOLUTE, szPath, L"NextInstance");
	HANDLE hKey = NULL, hKey2 = NULL;
	OBJECT_ATTRIBUTES objAttr = { 0 }; 
	InitializeObjectAttributes(&objAttr, &uPathEnum, OBJ_CASE_INSENSITIVE, NULL, NULL);
	NTSTATUS st = ZwOpenKey(&hKey, KEY_ALL_ACCESS, &objAttr);
	if (!NT_SUCCESS(st))
	{
		DbgPrintEx(77, 0, "[SSS]ZwOpenKey  failed %x \r\n", st);
		return FALSE;
	}
	st = ZwDeleteKey(hKey);
	st = ZwClose(hKey);
 

	InitializeObjectAttributes(&objAttr, regpath, OBJ_CASE_INSENSITIVE, NULL, NULL);
	st = ZwOpenKey(&hKey2, KEY_ALL_ACCESS, &objAttr);
	if (!NT_SUCCESS(st))
	{
		DbgPrintEx(77, 0, "[SSS]ZwOpenKey2 failed %x \r\n", st);
		return FALSE;
	}
	st = ZwDeleteKey(hKey2);
	st = ZwClose(hKey2);
	DbgPrintEx(77, 0, "[SSS]Delete reg Success  %wZ \r\n", regpath);
	return TRUE;

}