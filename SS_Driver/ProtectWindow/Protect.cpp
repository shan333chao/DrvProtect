#include "Protect.hpp"

#define PROTECT_TAG 'pctp'

namespace Protect {


	EXTERN_C_START
		LIST_ENTRY ProtectProcesses = { 0 };
	LIST_ENTRY ProtectHWNDS = { 0 };
	KGUARDED_MUTEX ProtectMutex = { 0 };
	KGUARDED_MUTEX HwndMutex = { 0 };
	BOOLEAN IsInit = FALSE;
	EXTERN_C_END
		BOOLEAN Initialize()
	{
		if (!IsInit)
		{
			InitializeListHead(&ProtectProcesses);
			InitializeListHead(&ProtectHWNDS);
			KeInitializeGuardedMutex(&ProtectMutex);
			KeInitializeGuardedMutex(&HwndMutex);
		}
		return TRUE;
	}


	BOOLEAN IsProtectProcess(PEPROCESS TargetProcess)
	{
		BOOLEAN IsOk = FALSE;
		if (IsListEmpty(&ProtectProcesses))
		{
			return IsOk;
		}
		PPROTECT_PROCESS protect;
		KeAcquireGuardedMutex(&ProtectMutex);
		PLIST_ENTRY current = ProtectProcesses.Flink;
		while (current != &ProtectProcesses)
		{
			protect = (PPROTECT_PROCESS)CONTAINING_RECORD(current, PROTECT_PROCESS, ProtectProcesses);
			current = current->Flink;
			if (protect->Process == TargetProcess)
			{
				IsOk = TRUE;
				break;
			}
		}
		KeReleaseGuardedMutex(&ProtectMutex);
		return IsOk;
	}

	BOOLEAN IsProtectPID(HANDLE pid)
	{
		BOOLEAN IsOk = FALSE;
		if (IsListEmpty(&ProtectProcesses))
		{
			return IsOk;
		}
		KeAcquireGuardedMutex(&ProtectMutex);
		PLIST_ENTRY current = ProtectProcesses.Flink;
		while (current != &ProtectProcesses)
		{
			PPROTECT_PROCESS protect = (PPROTECT_PROCESS)CONTAINING_RECORD(current, PROTECT_PROCESS, ProtectProcesses);
			current = current->Flink;
			if (MmIsAddressValid(protect->Process))
			{
				if (protect->PID == pid)
				{
					IsOk = TRUE;
					break;
				}
			}
		}
		KeReleaseGuardedMutex(&ProtectMutex);
		return IsOk;
	}



	BOOLEAN AddProtectProcess(PEPROCESS TargetProcess, ULONG fakeID) {
		PPROTECT_PROCESS protect = (PPROTECT_PROCESS)ExAllocatePoolWithTag(NonPagedPool, sizeof(PROTECT_PROCESS), PROTECT_TAG);
		if (!protect)
		{
			Log("ExAllocatePoolWithTag failed");
			return FALSE;
		}
		memset(protect, 0, sizeof(PROTECT_PROCESS));
		protect->Process = TargetProcess;
		protect->PID = PsGetProcessId(TargetProcess);
		protect->FAKEID = (HANDLE)fakeID;
		KeAcquireGuardedMutex(&ProtectMutex);
		InsertTailList(&ProtectProcesses, &protect->ProtectProcesses);
		KeReleaseGuardedMutex(&ProtectMutex);
		return TRUE;
	}





	BOOLEAN AddProtectPid(ULONG PID, ULONG fakeID)
	{
		PEPROCESS TargetProcess = 0;
		NTSTATUS status = PsLookupProcessByProcessId((HANDLE)PID, &TargetProcess);
		if (!NT_SUCCESS(status))
		{
			return FALSE;
		}
		Initialize();

		return AddProtectProcess(TargetProcess, fakeID);
	}

	ULONG32 IsProtectWND(HWND hwnd, HWND child, HANDLE hwndThread, HANDLE currentThread)
	{
		ULONG32 check = 0;
		if (IsListEmpty(&ProtectHWNDS))
		{
			return check;
		}
		KeAcquireGuardedMutex(&HwndMutex);
		PLIST_ENTRY current = ProtectHWNDS.Flink;
		while (current != &ProtectHWNDS)
		{
			PPROTECT_HWND protect = (PPROTECT_HWND)CONTAINING_RECORD(current, PROTECT_HWND, ProtectHWNDS);
			current = current->Flink;
			if (protect->thread == currentThread)
			{
				check = 1;
				break;
			}
			if (protect->thread == hwndThread)
			{
				check = 2;
				break;
			}

			if (protect->hwnd == hwnd || protect->hwnd == child)
			{
				check = 3;
				break;
			}
		}
		KeReleaseGuardedMutex(&HwndMutex);
		return check;
	}

	BOOLEAN AddProtectWND(HWND hwnd, HANDLE threadId)
	{
		PPROTECT_HWND protect = (PPROTECT_HWND)ExAllocatePoolWithTag(NonPagedPool, sizeof(PROTECT_HWND), PROTECT_TAG);
		if (!protect)
		{
			Log("ExAllocatePoolWithTag PPROTECT_HWND failed");
			return FALSE;
		}

		memset(protect, 0, sizeof(PPROTECT_HWND));
		protect->hwnd = hwnd;
		protect->thread = threadId;
		KeAcquireGuardedMutex(&HwndMutex);
		InsertTailList(&ProtectHWNDS, &protect->ProtectHWNDS);
		KeReleaseGuardedMutex(&HwndMutex);
		return TRUE;
	}

	BOOLEAN AddProtectWNDBatch(PULONG32 hwnds, ULONG32 length, HANDLE threadId)
	{

		PPROTECT_HWND protect = (PPROTECT_HWND)ExAllocatePoolWithTag(NonPagedPool, sizeof(PROTECT_HWND) * length, PROTECT_TAG);
		if (!protect)
		{
			Log("ExAllocatePoolWithTag PPROTECT_HWND failed");
			return FALSE;
		}
		memset(protect, 0, sizeof(PPROTECT_HWND) * length);
		KeAcquireGuardedMutex(&HwndMutex);
		for (size_t i = 0; i < length; i++)
		{
			protect->hwnd = (HWND)hwnds[i];
			protect->thread = threadId;
			Log("hwnd %x \r\n", hwnds[i]);
			InsertTailList(&ProtectHWNDS, &protect->ProtectHWNDS);
			protect += i;
		}
		KeReleaseGuardedMutex(&HwndMutex);
		return TRUE;
	}


	BOOLEAN RemoveProtectProcess(PEPROCESS TargetProcess) {
		BOOLEAN isRemove = FALSE;
		KeAcquireGuardedMutex(&ProtectMutex);
		PLIST_ENTRY current = ProtectProcesses.Flink;

		while (current != &ProtectProcesses)
		{
			PPROTECT_PROCESS protect = (PPROTECT_PROCESS)CONTAINING_RECORD(current, PROTECT_PROCESS, ProtectProcesses);
			current = current->Flink;
			if (protect->Process == TargetProcess)
			{
				RemoveEntryList(current->Blink);
				ExFreePoolWithTag(protect, PROTECT_TAG);
				isRemove = TRUE;
			}
		}
		KeReleaseGuardedMutex(&ProtectMutex);
		return isRemove;
	}



}



