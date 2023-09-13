#pragma once

#include "Protect.h"

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
			imports::ke_initialize_guarded_mutex(&ProtectMutex);
			imports::ke_initialize_guarded_mutex(&HwndMutex);
			IsInit = TRUE;
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

		imports::ke_acquire_guarded_mutex(&ProtectMutex);
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

		imports::ke_release_guarded_mutex(&ProtectMutex);
		return IsOk;
	}

	BOOLEAN IsProtectPID(HANDLE pid)
	{
		BOOLEAN IsOk = FALSE;
		if (IsListEmpty(&ProtectProcesses))
		{
			return IsOk;
		}
		imports::ke_acquire_guarded_mutex(&ProtectMutex);
		PLIST_ENTRY current = ProtectProcesses.Flink;
		while (current != &ProtectProcesses)
		{
			PPROTECT_PROCESS protect = (PPROTECT_PROCESS)CONTAINING_RECORD(current, PROTECT_PROCESS, ProtectProcesses);
			current = current->Flink;
			if (imports::mm_is_address_valid(protect->Process))
			{
				if (protect->PID == pid)
				{
					IsOk = TRUE;
					break;
				}
			}
		}
		imports::ke_release_guarded_mutex(&ProtectMutex);
		return IsOk;
	}



	BOOLEAN AddProtectProcess(PEPROCESS TargetProcess, ULONG fakeID) {
		PPROTECT_PROCESS protect = (PPROTECT_PROCESS)imports::ex_allocate_pool_with_tag(NonPagedPool, sizeof(PROTECT_PROCESS), PROTECT_TAG);
		if (!protect)
		{
			Log("imports::ex_allocate_pool_with_tag failed");
			return FALSE;
		}

		Utils::kmemset(protect, 0, sizeof(PROTECT_PROCESS));
		protect->Process = TargetProcess;
		protect->PID = imports::ps_get_process_id(TargetProcess);
		protect->FAKEID = (HANDLE)fakeID;
		imports::ke_acquire_guarded_mutex(&ProtectMutex);
		InsertTailList(&ProtectProcesses, &protect->ProtectProcesses);
		imports::ke_release_guarded_mutex(&ProtectMutex);
		return TRUE;
	}





	BOOLEAN AddProtectPid(ULONG PID, ULONG fakeID)
	{
		PEPROCESS TargetProcess = 0;
		NTSTATUS status = imports::ps_lookup_process_by_process_id((HANDLE)PID, &TargetProcess);
		if (!NT_SUCCESS(status))
		{
			return FALSE;
		}
		Initialize();

		return AddProtectProcess(TargetProcess, fakeID);
	}

	ULONG32 IsProtectWND(HANDLE hwnd, HANDLE child, HANDLE hwndThread, HANDLE currentThread)
	{
		ULONG32 check = 0;
		if (IsListEmpty(&ProtectHWNDS))
		{
			return check;
		}
		imports::ke_acquire_guarded_mutex(&HwndMutex);
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
		imports::ke_release_guarded_mutex(&HwndMutex);
		return check;
	}

	BOOLEAN AddProtectWND(HANDLE hwnd, HANDLE threadId)
	{
		PPROTECT_HWND protect = (PPROTECT_HWND)imports::ex_allocate_pool_with_tag(NonPagedPool, sizeof(PROTECT_HWND), PROTECT_TAG);
		if (!protect)
		{
			Log("imports::ex_allocate_pool_with_tag PPROTECT_HWND failed");
			return FALSE;
		}

		Utils::kmemset(protect, 0, sizeof(PPROTECT_HWND));
		protect->hwnd = hwnd;
		protect->thread = threadId;
		imports::ke_acquire_guarded_mutex(&HwndMutex);
		InsertTailList(&ProtectHWNDS, &protect->ProtectHWNDS);
		imports::ke_release_guarded_mutex(&HwndMutex);
		return TRUE;
	}

	BOOLEAN AddProtectWNDBatch(PULONG32 hwnds, ULONG32 length, HANDLE threadId)
	{

		PPROTECT_HWND protect = (PPROTECT_HWND)imports::ex_allocate_pool_with_tag(NonPagedPool, sizeof(PROTECT_HWND) * length, PROTECT_TAG);
		if (!protect)
		{
			Log("imports::ex_allocate_pool_with_tag PPROTECT_HWND failed");
			return FALSE;
		}
		Utils::kmemset(protect, 0, sizeof(PPROTECT_HWND) * length);
		imports::ke_acquire_guarded_mutex(&HwndMutex);
		for (size_t i = 0; i < length; i++)
		{
			protect->hwnd = (HANDLE)hwnds[i];
			protect->thread = threadId;
			Log("hwnd %x \r\n", hwnds[i]);
			InsertTailList(&ProtectHWNDS, &protect->ProtectHWNDS);
			protect += i;
		}
		imports::ke_release_guarded_mutex(&HwndMutex);
		return TRUE;
	}


	BOOLEAN RemoveProtectProcess(PEPROCESS TargetProcess) {
		BOOLEAN isRemove = FALSE;
		imports::ke_acquire_guarded_mutex(&ProtectMutex);
		PLIST_ENTRY current = ProtectProcesses.Flink;

		while (current != &ProtectProcesses)
		{
			PPROTECT_PROCESS protect = (PPROTECT_PROCESS)CONTAINING_RECORD(current, PROTECT_PROCESS, ProtectProcesses);
			current = current->Flink;
			if (protect->Process == TargetProcess)
			{
				RemoveEntryList(current->Blink);
				imports::ex_free_pool_with_tag(protect, PROTECT_TAG);
				isRemove = TRUE;
			}
		}
		imports::ke_release_guarded_mutex(&ProtectMutex);
		return isRemove;
	}



}



