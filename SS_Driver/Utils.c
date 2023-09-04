


PVOID GetSystemInformation(const SYSTEM_INFORMATION_CLASS information_class)
{
	PVOID Buffer;
	ULONG BufferSize = 4096;
	ULONG ReturnLength;
	NTSTATUS Status;

	Buffer = ExAllocatePool(NonPagedPool, BufferSize);

	if (!Buffer) {
		return STATUS_NO_MEMORY;
	}
retry:
	Status = ZwQuerySystemInformation(information_class,
		Buffer,
		BufferSize,
		&ReturnLength
	);

	if (Status == STATUS_INFO_LENGTH_MISMATCH) {
		ExFreePool(Buffer);
		BufferSize = ReturnLength;
		goto retry;
	}
	return Buffer;
}



VOID GetKernelModule(PUCHAR szModuleName, PRTL_PROCESS_MODULE_INFORMATION pModuleInfo)
{


	PRTL_PROCESS_MODULES Modules = (PRTL_PROCESS_MODULES)GetSystemInformation(system_module_information);
	if (Modules == NULL)
	{
		return NULL;
	}
	ULONG i;
	PRTL_PROCESS_MODULE_INFORMATION ModuleInfo;
	for (i = 0, ModuleInfo = &(Modules->Modules[0]);
		i < Modules->NumberOfModules;
		i++, ModuleInfo++) {
		ModuleInfo = &Modules->Modules[i];
		DbgPrint("%s \r\n", ModuleInfo->FullPathName);
		if (strstr(ModuleInfo->FullPathName, szModuleName) != 0)
		{
			memcpy(pModuleInfo, ModuleInfo, sizeof(RTL_PROCESS_MODULE_INFORMATION));
			break;
		}
	}
	ExFreePool(Modules);
	return;
}