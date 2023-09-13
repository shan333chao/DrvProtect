#include "SThread.h"

namespace sthread {


	NTSTATUS   MyNtCreateThreadEx(ULONG pid, PVOID ShellCodeAddr, PVOID Argument) {
		if (!ShellCodeAddr || (ULONG64)ShellCodeAddr >=imports::imported.mm_user_probe_address)
		{
			return STATUS_INVALID_PARAMETER_2;
		}
		NTSTATUS status;
		PEPROCESS pEprocess;
		KAPC_STATE apcState = { 0 };
 
		HANDLE hThread = NULL;
		PNtCreateThreadEx pNtCrteateThread =functions::GetNtCreateThreadEx();
		if (!pNtCrteateThread)
		{
			return STATUS_UNSUCCESSFUL;
		}
		status =imports::ps_lookup_process_by_process_id((HANDLE)pid, &pEprocess);
		if (!NT_SUCCESS(status))
		{
			return status;
		}
		if (imports::ps_get_process_exit_status(pEprocess) != STATUS_PENDING)
		{
			return STATUS_PENDING;
		}
		imports::ke_stack_attach_process(pEprocess, &apcState);
		MODE oldMode = functions::SetThreadPrevious(KeGetCurrentThread(), KernelMode);
		status = pNtCrteateThread(&hThread, THREAD_ALL_ACCESS, NULL, NtCurrentProcess(), ShellCodeAddr, Argument, NULL, NULL, NULL, NULL, NULL);
		functions::SetThreadPrevious(KeGetCurrentThread(), oldMode);
		imports::ke_unstack_detach_process(&apcState);
		return status;



	}
}