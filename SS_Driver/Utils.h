

NTSTATUS NTAPI ZwQuerySystemInformation(
	__in SYSTEM_INFORMATION_CLASS SystemInformationClass,
	__out_bcount_opt(SystemInformationLength) PVOID SystemInformation,
	__in ULONG SystemInformationLength,
	__out_opt PULONG ReturnLength
);
PVOID GetSystemInformation(SYSTEM_INFORMATION_CLASS information_class);

VOID GetKernelModule(PUCHAR szModuleName, PRTL_PROCESS_MODULE_INFORMATION pModuleInfo);