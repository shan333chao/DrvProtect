#include "SThread.h"


NTSTATUS   MyNtCreateThreadEx(ULONG pid, PVOID ShellCodeAddr, PVOID Argument) {
	if (!ShellCodeAddr || ShellCodeAddr >= MmUserProbeAddress)
	{
		return STATUS_INVALID_PARAMETER_2;
	}
	NTSTATUS status;
	PEPROCESS pEprocess;
	KAPC_STATE apcState = { 0 };
	MODE mode = 0;
	HANDLE hThread = NULL;
	PNtCreateThreadEx pNtCrteateThread = GetNtCreateThreadEx();
	if (!pNtCrteateThread)
	{
		return STATUS_UNSUCCESSFUL;
	}
	status = PsLookupProcessByProcessId(pid, &pEprocess);
	if (!NT_SUCCESS(status))
	{
		return status;
	}
	if (PsGetProcessExitStatus(pEprocess) != STATUS_PENDING)
	{
		return STATUS_PENDING;
	}
	KeStackAttachProcess(pEprocess, &apcState);
	MODE oldMode = SetThreadPrevious(KeGetCurrentThread(), KernelMode);
	status = pNtCrteateThread(&hThread, THREAD_ALL_ACCESS, NULL, NtCurrentProcess(), ShellCodeAddr, Argument, NULL, NULL, NULL, NULL, NULL);
	SetThreadPrevious(KeGetCurrentThread(), oldMode);
	KeUnstackDetachProcess(&apcState);
	return status;

}