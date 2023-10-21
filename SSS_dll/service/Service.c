#pragma once
#include "Service.h"
#include "../../SSS_Drivers/ERROR_CODE.h"
#include "../log.h"
#pragma warning(disable:4996)

typedef _Return_type_success_(return >= 0) LONG NTSTATUS;
/*lint -save -e624 */  // Don't complain about different typedefs.
typedef NTSTATUS* PNTSTATUS;
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)

typedef struct _UNICODE_STRING {
	USHORT Length;
	USHORT MaximumLength;
#ifdef MIDL_PASS
	[size_is(MaximumLength / 2), length_is((Length) / 2)] USHORT* Buffer;
#else // MIDL_PASS
	_Field_size_bytes_part_opt_(MaximumLength, Length) PWCH   Buffer;
#endif // MIDL_PASS
} UNICODE_STRING, * PUNICODE_STRING;
typedef VOID(NTAPI* RtlInitUnicodeString)(PUNICODE_STRING DestinationString, PCWSTR SourceString);
typedef NTSTATUS(*NtLoadDriver)(PUNICODE_STRING DriverServiceName);

typedef NTSTATUS(*RtlAdjustPrivilege)(_In_ ULONG Privilege, _In_ BOOLEAN Enable, _In_ BOOLEAN Client, _Out_ PBOOLEAN WasEnabled);
ULONG CreateServiceAndStartX86(PCHAR szDriverFullPath, PCHAR szDriverName)
{
	ULONG status = STATUS_OP_UNSUCCESS;
	//2.打开服务控制管理器
	SC_HANDLE hServiceMgr = OpenSCManagerW(NULL, NULL, SC_MANAGER_ALL_ACCESS); // SCM管理器句柄	
	if (!hServiceMgr)
	{

		Logp("OpenSCManagerW 失败, %d\n", GetLastError());
		return STATUS_TEST_COMM_OPEN_SCMANAGER;
	}
	Logp("打开服务控制管理器成功.\n");


	//3.创建驱动服务
	SC_HANDLE hServiceDDK = NULL; // NT驱动程序服务句柄
	//创建驱动服务
	hServiceDDK = CreateServiceA(
		hServiceMgr,
		szDriverName,//驱动程序注册表中的名字
		szDriverName,//注册表中驱动程序的 DisPlayName 的值
		SERVICE_ALL_ACCESS,//加载驱动的访问权限 SERVICE_START 或 SERVICE_ALL_ACCESS
		SERVICE_KERNEL_DRIVER,//表示加载服务是驱动程序
		SERVICE_DEMAND_START,//注册表驱动程序的 Start 值
		SERVICE_ERROR_IGNORE,//注册表程序的 ErrorControl 值
		szDriverFullPath,
		NULL, NULL, NULL, NULL, NULL
	);

	if (!hServiceDDK)
	{
		status = GetLastError();
		if (status != ERROR_IO_PENDING && status != ERROR_SERVICE_EXISTS)
		{
			Logp("创建驱动服务失败, %d\n", status);
			return STATUS_TEST_COMM_CREATE_SERVICE;
		}
	}
	Logp("创建驱动服务成功.\n");
	// 驱动服务已经创建，打开服务
	hServiceDDK = OpenServiceA(hServiceMgr, szDriverName, SERVICE_ALL_ACCESS);
	if (!StartService(hServiceDDK, NULL, NULL))
	{
		status = GetLastError();
		if (status != STATUS_TEST_COMM_DRIVER_STARTED  )
		{
			Logp("运行驱动服务失败, %08x\n", status);
			if (hServiceDDK)
			{
				CloseServiceHandle(hServiceDDK);
			}
			if (hServiceMgr)
			{
				CloseServiceHandle(hServiceMgr);
			}
			return STATUS_TEST_COMM_SE_LOAD_DRIVER_PRIVILEGE;
		}
	}
	Logp("运行驱动服务成功.\n");
	if (hServiceDDK)
	{
		CloseServiceHandle(hServiceDDK);
	}
	if (hServiceMgr)
	{
		CloseServiceHandle(hServiceMgr);
	}

	return STATUS_OP_SUCCESS;
}
int Char2Wchar(wchar_t* wcharStr, const char* charStr) {
	int len = MultiByteToWideChar(CP_ACP, 0, charStr, strlen(charStr), NULL, 0);

	MultiByteToWideChar(CP_ACP, 0, charStr, strlen(charStr), wcharStr, len);
	wcharStr[len] = '\0';
	return len;
}

ULONG CreateServiceAndStartX64(PCHAR driverPath, PCHAR driverName)
{
	const static DWORD ServiceTypeKernel = 1;
	char servicesPath[MAX_PATH] = "SYSTEM\\CurrentControlSet\\Services\\";
	strcat(servicesPath, driverName);
	char nPath[MAX_PATH] = "\\??\\";
	strcat(nPath, driverPath);

	HKEY dservice;
	LSTATUS status = RegCreateKeyA(HKEY_LOCAL_MACHINE, servicesPath, &dservice); //Returns Ok if already exists
	if (status != ERROR_SUCCESS) {
		Logp("[-] Can't create service key %08x", status);
		return STATUS_TEST_COMM_CREATE_SERVICE_KEY;
	}

	status = RegSetKeyValueA(dservice, NULL, "ImagePath", REG_EXPAND_SZ, nPath, (DWORD)(strlen(nPath) * sizeof(char)));
	if (status != ERROR_SUCCESS) {
		RegCloseKey(dservice);
		Logp("[-] Can't create 'ImagePath' registry value %08x", status);
		return STATUS_TEST_COMM_CREATE_SERVICE_KEY;
	}

	status = RegSetKeyValueA(dservice, NULL, "Type", REG_DWORD, &ServiceTypeKernel, sizeof(DWORD));
	if (status != ERROR_SUCCESS) {
		RegCloseKey(dservice);
		Logp("[-] Can't create 'Type' registry value %08x", status);
		return STATUS_TEST_COMM_CREATE_SERVICE_KEY;
	}

	RegCloseKey(dservice);

	HMODULE ntdll = GetModuleHandleA("ntdll.dll");
	if (ntdll == NULL) {
		return STATUS_TEST_COMM_GETMODULEHANDLEA;
	}

	RtlAdjustPrivilege  FRtlAdjustPrivilege = (RtlAdjustPrivilege)GetProcAddress(ntdll, "RtlAdjustPrivilege");
	NtLoadDriver FNtLoadDriver = (NtLoadDriver)GetProcAddress(ntdll, "NtLoadDriver");
	RtlInitUnicodeString FRtlInitUnicodeString = (RtlInitUnicodeString)GetProcAddress(ntdll, "RtlInitUnicodeString");
	ULONG SE_LOAD_DRIVER_PRIVILEGE = 10UL;
	BOOLEAN SeLoadDriverWasEnabled;

	NTSTATUS Status = FRtlAdjustPrivilege(SE_LOAD_DRIVER_PRIVILEGE, TRUE, FALSE, &SeLoadDriverWasEnabled);
	if (!NT_SUCCESS(Status)) {
		Logp("Fatal error: failed to acquire SE_LOAD_DRIVER_PRIVILEGE. Make sure you are running as administrator.");
		return STATUS_TEST_COMM_SE_LOAD_DRIVER_PRIVILEGE;
	}

	wchar_t wdriver_reg_path[MAX_PATH] = L"\\Registry\\Machine\\System\\CurrentControlSet\\Services\\";
	wchar_t DriverName[0x40] = { 0 };
	Char2Wchar(DriverName, driverName);
	wcscat(wdriver_reg_path, DriverName);
	UNICODE_STRING serviceStr;
	FRtlInitUnicodeString(&serviceStr, (PCWSTR)wdriver_reg_path);
	Status = FNtLoadDriver(&serviceStr);
	Logp("[+] NtLoadDriver Status %08x", Status);

	//Never should occur since kdmapper checks for "IsRunning" driver before
	//if (Status == 0xC000010E) {// STATUS_IMAGE_ALREADY_LOADED
	//	return true;
	//}

	return Status;
}
