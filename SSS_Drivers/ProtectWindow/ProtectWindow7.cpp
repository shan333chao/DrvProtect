#pragma once
#include "ProtectWindow7.h"




namespace ProtectWindow7 {

	EXTERN_C_START
		BOOLEAN IsHookStarted7 = FALSE;
	FNtCreateFile7 g_NtCreateFile7 = (FNtCreateFile7)0x12345678;
	FNtUserFindWindowEx7	g_NtUserFindWindowEx7 = (FNtUserFindWindowEx7)0x12345678;
	FNtUserBuildHwndList7  g_NtUserBuildHwndList7 = (FNtUserBuildHwndList7)0x12345678;
	FNtUserQueryWindow7	g_NtUserQueryWindow7 = (FNtUserQueryWindow7)0x12345678;
	FNtUserGetForegroundWindow7	g_NtUserGetForegroundWindow7 = (FNtUserGetForegroundWindow7)0x12345678;
	FNtUserWindowFromPoint7	g_NtUserWindowFromPoint7 = (FNtUserWindowFromPoint7)0x12345678;
	FNtUserSetWindowDisplayAffinity7 g_NtUserSetWindowDisplayAffinity7 = (FNtUserSetWindowDisplayAffinity7)0x12345678;
	FNtUserGetWindowDisplayAffinity7 g_NtUserGetWindowDisplayAffinity7 = (FNtUserGetWindowDisplayAffinity7)0x12345678;
	FNtUserSetParent7 g_NtUserSetParent7 = (FNtUserSetParent7)0x12345678;
	FNtOpenProcess7 g_NtOpenProcess7 = (FNtOpenProcess7)0x12345678;
	FNtOpenThread7 g_NtOpenThread7 = (FNtOpenThread7)0x12345678;
	FNtUserSetLayeredWindowAttributes7 g_NtUserSetLayeredWindowAttributes7 = (FNtUserSetLayeredWindowAttributes7)0x12345678;
	FNtUserInternalGetWindowText7 g_NtUserInternalGetWindowText7;
	FNtUserPostMessage7 g_NtUserPostMessage7 = (FNtUserPostMessage7)0x12345678;
	FNtUserMessageCall7 g_NtUserMessageCall7 = (FNtUserMessageCall7)0x12345678;
	FNtUserGetClassName7 g_NtUserGetClassName7 = (FNtUserGetClassName7)0x12345678;
	FNtUserCallOneParam7 g_NtUserCallOneParam7 = (FNtUserCallOneParam7)0x12345678;
	FNtQueryInformationProcess7 g_NtQueryInformationProcess7 = (FNtQueryInformationProcess7)0x12345678;
	FNtUserCallHwndParam7 g_NtUserCallHwndParam7 = (FNtUserCallHwndParam7)0x12345678;
	FNtUserValidateHandleSecure7 g_NtUserValidateHandleSecure7 = (FNtUserValidateHandleSecure7)0x12345678;
	FNtUserCallHwnd7 g_NtUserCallHwnd7 = (FNtUserCallHwnd7)0x12345678;
 



	void __fastcall ssdt_call_back7(unsigned long ssdt_index, void** ssdt_address)
	{
		// https://hfiref0x.github.io/

		//if (*ssdt_address == g_NtQueryInformationProcess) { *ssdt_address = MyNtQueryInformationProcess; return; }
		//if (*ssdt_address == g_NtOpenThread) { *ssdt_address = MyNtOpenThread; return; }
		//if (*ssdt_address == g_NtOpenProcess) { *ssdt_address = MyNtOpenProcess; return; }
		//if (*ssdt_address == g_NtCreateFile7) { *ssdt_address = MyNtCreateFile7; return; }
		if (*ssdt_address == 0)
		{
			return;
		}
		if ((ssdt_index >> 12) > 0)
		{

			if (*ssdt_address == g_NtUserQueryWindow7) { *ssdt_address = MyNtUserQueryWindow7;			return; }
			if (*ssdt_address == g_NtUserCallHwndParam7) { *ssdt_address = MyNtUserCallHwndParam7; return; }//win7需要重新实现
			if (*ssdt_address == g_NtUserValidateHandleSecure7) { *ssdt_address = MyNtUserValidateHandleSecure7; return; }//win7需要重新实现
			if (*ssdt_address == g_NtUserCallHwnd7) { *ssdt_address = MyNtUserCallHwnd7; return; }//win7需要重新实现
 
			if (*ssdt_address == g_NtUserCallOneParam7) { *ssdt_address = MyNtUserCallOneParam7; return; }//win7需要重新实现
			if (*ssdt_address == g_NtUserInternalGetWindowText7) { *ssdt_address = MyNtUserInternalGetWindowText7; return; }
			if (*ssdt_address == g_NtUserPostMessage7) { *ssdt_address = MyNtUserPostMessage7; return; }//win7需要重新实现
			if (*ssdt_address == g_NtUserMessageCall7) { *ssdt_address = MyNtUserMessageCall7; return; }//win7需要重新实现
			if (*ssdt_address == g_NtUserFindWindowEx7) { *ssdt_address = MyNtUserFindWindowEx7; return; }//win7需要重新实现


			if (*ssdt_address == g_NtUserGetForegroundWindow7) { *ssdt_address = MyNtUserGetForegroundWindow7; return; }//win7需要重新实现

			if (*ssdt_address == g_NtUserSetWindowDisplayAffinity7) { *ssdt_address = MyNtUserSetWindowDisplayAffinity7; return; }
			if (*ssdt_address == g_NtUserGetWindowDisplayAffinity7) { *ssdt_address = MyNtUserGetWindowDisplayAffinity7; return; }
			if (*ssdt_address == g_NtUserGetClassName7) { *ssdt_address = MyNtUserGetClassName7; return; }//win7需要重新实现
			//if (g_NtUserBuildHwndList7 &&*ssdt_address == g_NtUserBuildHwndList7) {	Log("%04x \r\n", ssdt_index); *ssdt_address = MyNtUserBuildHwndList7;  return; }
		}


	}

	BOOLEAN MyNtUserGetWindowPlacement7(HANDLE hWnd, PVOID lpwndpl)
	{
		return BOOLEAN();
	}

	BOOLEAN MyNtUserGetTitleBarInfo7(HANDLE hwnd, PVOID pti)
	{
		return BOOLEAN();
	}

	BOOLEAN MyNtUserGetScrollBarInfo7(HANDLE hWnd, LONG idObject, PVOID psbi)
	{
		return BOOLEAN();
	}

	ULONG_PTR MyNtUserCallHwnd7(HANDLE hwnd, DWORD code)
	{

		if (Protect::IsProtectProcess(imports::io_get_current_process()))
		{
			return g_NtUserCallHwnd7(hwnd, code);
		}
		HANDLE handle = g_NtUserQueryWindow7(hwnd, WindowActiveWindow);
		if (handle)
		{
			Log("MyNtUserCallHwnd7  %04x \r\n", handle);
			int ret = Protect::IsProtectWND(hwnd, 0, handle, imports::ps_get_current_thread_id());
			if (ret == 1)
			{
				return g_NtUserCallHwnd7(hwnd, code);
			}
			else if (ret > 1) {
				return 0;
			}
			auto pid = g_NtUserQueryWindow7(hwnd, WindowProcess);
			if (Protect::IsProtectPID(pid)) {
				return 0;
			}
		}
		return g_NtUserCallHwnd7(hwnd, code);
	}

	ULONG_PTR MyNtUserCallHwndParam7(HANDLE hwnd, DWORD_PTR param, DWORD code)
	{

		if (Protect::IsProtectProcess(imports::io_get_current_process()))
		{
			return g_NtUserCallHwndParam7(hwnd, param, code);
		}
		HANDLE handle = g_NtUserQueryWindow7(hwnd, WindowActiveWindow);
		if (handle)
		{
			Log("MyNtUserCallHwndParam7  %04x \r\n", handle);
			int ret = Protect::IsProtectWND(hwnd, 0, handle, imports::ps_get_current_thread_id());
			if (ret == 1)
			{
				return g_NtUserCallHwndParam7(hwnd, param, code);
			}
			else if (ret > 1) {
				return 0;
			}
			auto pid = g_NtUserQueryWindow7(hwnd, WindowProcess);
			if (Protect::IsProtectPID(pid)) {
				return 0;
			}
		}
		return g_NtUserCallHwndParam7(hwnd, param, code);
	}

	BOOLEAN MyNtUserValidateHandleSecure7(HANDLE hHdl)
	{

		if (Protect::IsProtectProcess(imports::io_get_current_process()))
		{
			return g_NtUserValidateHandleSecure7(hHdl);
		}
		HANDLE handle = g_NtUserQueryWindow7((HANDLE)hHdl, WindowActiveWindow);
		if (handle)
		{
			Log("MyNtUserValidateHandleSecure7  %04x \r\n", handle);
			int ret = Protect::IsProtectWND((HANDLE)hHdl, 0, handle, imports::ps_get_current_thread_id());
			if (ret == 1)
			{
				return TRUE;
			}
			else if (ret > 1) {
				return FALSE;
			}
			auto pid = g_NtUserQueryWindow7((HANDLE)hHdl, WindowProcess);
			if (Protect::IsProtectPID(pid)) {
				return FALSE;
			}
		}
		return  g_NtUserValidateHandleSecure7(hHdl);
	}




 
	INT MyNtUserGetClassName7(HANDLE hWnd, BOOLEAN Ansi, PUNICODE_STRING ClassName)
	{

		if (Protect::IsProtectProcess(imports::io_get_current_process()))
		{
			return g_NtUserGetClassName7(hWnd, Ansi, ClassName);
		}
		HANDLE handle = g_NtUserQueryWindow7(hWnd, WindowActiveWindow);
		if (handle)
		{
			Log("MyNtUserGetClassName7  %04x \r\n", handle);
			int ret = Protect::IsProtectWND(hWnd, 0, handle, imports::ps_get_current_thread_id());
			if (ret == 1)
			{
				return g_NtUserGetClassName7(hWnd, Ansi, ClassName);
			}
			else if (ret > 1) {
				return FALSE;
			}
			auto pid = g_NtUserQueryWindow7(hWnd, WindowProcess);
			if (Protect::IsProtectPID(pid)) {
				return FALSE;
			}
		}
		return 	  g_NtUserGetClassName7(hWnd, Ansi, ClassName);
	}

	BOOLEAN MyNtUserPostMessage7(HANDLE hWnd, UINT Msg, ULONG wParam, __int64 lParam)
	{

		if (Msg == WM_GETTEXT)
		{

			if (Protect::IsProtectProcess(imports::io_get_current_process()))
			{
				return g_NtUserPostMessage7(hWnd, Msg, wParam, lParam);
			}
			HANDLE handle = g_NtUserQueryWindow7(hWnd, WindowActiveWindow);
			if (handle)
			{
				Log("MyNtUserPostMessage7----thread  %08x \r\n", handle);
				int ret = Protect::IsProtectWND(hWnd, 0, handle, imports::ps_get_current_thread_id());
				if (ret == 1)
				{
					return g_NtUserPostMessage7(hWnd, Msg, wParam, lParam);
				}
				else if (ret > 1) {
					return FALSE;
				}
				auto pid = g_NtUserQueryWindow7(hWnd, WindowProcess);
				if (Protect::IsProtectPID(pid)) {
					return FALSE;
				}
			}
		}
		return  g_NtUserPostMessage7(hWnd, Msg, wParam, lParam);
	}

	BOOLEAN MyNtUserMessageCall7(HANDLE hWnd, UINT Msg, ULONG wParam, ULONG lParam, ULONG_PTR ResultInfo, DWORD dwType, BOOLEAN Ansi)
	{
		if (KeGetCurrentIrql() != PASSIVE_LEVEL)
			return  g_NtUserMessageCall7(hWnd, Msg, wParam, lParam, ResultInfo, dwType, Ansi);

		if (Msg == WM_GETTEXT)
		{

			if (Protect::IsProtectProcess(imports::io_get_current_process()))
			{
				return g_NtUserMessageCall7(hWnd, Msg, wParam, lParam, ResultInfo, dwType, Ansi);
			}
			HANDLE handle = g_NtUserQueryWindow7(hWnd, WindowActiveWindow);
			if (handle)
			{

				Log("MyNtUserMessageCall7  thread  %04x \r\n", handle);
				int ret = Protect::IsProtectWND(hWnd, 0, handle, imports::ps_get_current_thread_id());
				if (ret == 1)
				{
					return g_NtUserMessageCall7(hWnd, Msg, wParam, lParam, ResultInfo, dwType, Ansi);
				}
				else if (ret > 1) {

					return NULL;
				}
			}
			HANDLE pid = g_NtUserQueryWindow7(hWnd, WindowProcess);
 

			if (Protect::IsProtectPID(pid)) {
				Log("filter pid %d \n");
				return NULL;
			}
			Log("MyNtUserMessageCall7 currentPid  %d  target pid %d   threadid %d  hwnd %d \r\n", imports::ps_get_current_process_id(), pid, handle, hWnd);
		}
		return  g_NtUserMessageCall7(hWnd, Msg, wParam, lParam, ResultInfo, dwType, Ansi);
	}

	NTSTATUS MyNtQueryInformationProcess7(HANDLE ProcessHandle, PROCESSINFOCLASS ProcessInformationClass, PVOID ProcessInformation, ULONG ProcessInformationLength, PULONG ReturnLength)
	{

		NTSTATUS status = g_NtQueryInformationProcess7(ProcessHandle, ProcessInformationClass, ProcessInformation, ProcessInformationLength, ReturnLength);

		return status;
	}

	ULONG MyNtUserInternalGetWindowText7(HANDLE hWnd, LPWSTR pString, int cchMaxCount)
	{

		if (Protect::IsProtectProcess(imports::io_get_current_process()))
		{
			return g_NtUserInternalGetWindowText7(hWnd, pString, cchMaxCount);
		}

		HANDLE handle = g_NtUserQueryWindow7(hWnd, WindowActiveWindow);
		if (handle)
		{
			Log("MyNtUserInternalGetWindowText7  %04x \r\n", handle);
			int ret = Protect::IsProtectWND(hWnd, 0, handle, imports::ps_get_current_thread_id());
			if (ret == 1)
			{
				return  g_NtUserInternalGetWindowText7(hWnd, pString, cchMaxCount);
			}
			else if (ret > 1) {

				return FALSE;
			}
			auto pid = g_NtUserQueryWindow7(hWnd, WindowProcess);
			if (Protect::IsProtectPID(pid)) {
				return FALSE;
			}
		}
		return g_NtUserInternalGetWindowText7(hWnd, pString, cchMaxCount);
	}


	NTSTATUS MyNtOpenProcess7(PHANDLE ProcessHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, PCLIENT_ID ClientId)
	{
		if (Protect::IsProtectProcess(imports::io_get_current_process()))
		{
			return g_NtOpenProcess7(ProcessHandle, DesiredAccess, ObjectAttributes, ClientId);
		}
		if (ClientId != NULL)
		{
			if (ClientId->UniqueProcess == NULL)
				return g_NtOpenProcess7(ProcessHandle, DesiredAccess, ObjectAttributes, ClientId);

			HANDLE OldPid = ClientId->UniqueProcess;
			if (Protect::IsProtectPID(OldPid))
			{
				ClientId->UniqueProcess = UlongToHandle(0xFFFFFFFC);
				NTSTATUS Status = g_NtOpenProcess7(ProcessHandle, DesiredAccess, ObjectAttributes, ClientId);
				ClientId->UniqueProcess = OldPid;
				return Status;
			}
		}
		return  g_NtOpenProcess7(ProcessHandle, DesiredAccess, ObjectAttributes, ClientId);
	}

	NTSTATUS MyNtCreateFile7(PHANDLE FileHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, PIO_STATUS_BLOCK IoStatusBlock, PLARGE_INTEGER AllocationSize, ULONG FileAttributes, ULONG ShareAccess, ULONG CreateDisposition, ULONG CreateOptions, PVOID EaBuffer, ULONG EaLength)
	{
		// NtCreateFile 的调用方必须在 IRQL = PASSIVE_LEVEL且 启用了特殊内核 APC 的情况下运行
		if (KeGetCurrentIrql() != PASSIVE_LEVEL) return g_NtCreateFile7(FileHandle, DesiredAccess, ObjectAttributes, IoStatusBlock, AllocationSize, FileAttributes, ShareAccess, CreateDisposition, CreateOptions, EaBuffer, EaLength);
		if (imports::ex_get_previous_mode() == KernelMode) return g_NtCreateFile7(FileHandle, DesiredAccess, ObjectAttributes, IoStatusBlock, AllocationSize, FileAttributes, ShareAccess, CreateDisposition, CreateOptions, EaBuffer, EaLength);
		if (imports::ps_get_process_session_id(imports::io_get_current_process()) == 0) return g_NtCreateFile7(FileHandle, DesiredAccess, ObjectAttributes, IoStatusBlock, AllocationSize, FileAttributes, ShareAccess, CreateDisposition, CreateOptions, EaBuffer, EaLength);

		if (ObjectAttributes &&
			ObjectAttributes->ObjectName &&
			ObjectAttributes->ObjectName->Buffer)
		{
			wchar_t* name = (wchar_t*)imports::ex_allocate_pool(NonPagedPool, ObjectAttributes->ObjectName->Length + sizeof(wchar_t));

			if (name)
			{
				Utils::kmemset(name, 0, ObjectAttributes->ObjectName->Length + sizeof(wchar_t));
				Utils::kmemcpy(name, ObjectAttributes->ObjectName->Buffer, ObjectAttributes->ObjectName->Length);
				Log("%s \n", name);

				//if (wcsstr(name, L"My\\Certificates") && !wcsstr(name, L".ini"))
				//{

				//	imports::ex_free_pool_with_tag(name,0);
				//	return STATUS_ACCESS_DENIED;
				//}

				imports::ex_free_pool_with_tag(name, 0);
			}
		}

		return g_NtCreateFile7(FileHandle, DesiredAccess, ObjectAttributes, IoStatusBlock, AllocationSize, FileAttributes, ShareAccess, CreateDisposition, CreateOptions, EaBuffer, EaLength);

	}

	HANDLE MyNtUserFindWindowEx7(IN HANDLE hwndParent, IN HANDLE hwndChild, IN PUNICODE_STRING pstrClassName OPTIONAL, IN PUNICODE_STRING pstrWindowName OPTIONAL, IN DWORD dwType)
	{

		auto res = g_NtUserFindWindowEx7(hwndParent, hwndChild, pstrClassName, pstrWindowName, dwType);
		if (!res) 	return res;

		if (Protect::IsProtectProcess(imports::io_get_current_process()))
		{
			return res;
		}

		HANDLE handle = g_NtUserQueryWindow7(res, WindowActiveWindow);
		if (handle)
		{
			Log("MyNtUserFindWindowEx7  %04x \r\n", handle);

			int ret = Protect::IsProtectWND(hwndParent, hwndChild, handle, imports::ps_get_current_thread_id());
			if (ret == 1)
			{
				return  res;
			}
			else if (ret > 1) {
				return 0;
			}
		}
		auto pid = g_NtUserQueryWindow7(res, WindowProcess);
		if (pid && Protect::IsProtectPID(pid))
		{
			return NULL;
		}

		return res;
	}

	HANDLE NTAPI  MyNtUserQueryWindow7(HANDLE  hWnd, WINDOWINFOCLASS WindowInfo)
	{

		if (Protect::IsProtectProcess(imports::io_get_current_process()))
		{
			return  g_NtUserQueryWindow7(hWnd, WindowInfo);
		}
		HANDLE handle = g_NtUserQueryWindow7(hWnd, WindowActiveWindow);
		if (handle)
		{
			auto ret = Protect::IsProtectWND(hWnd, 0, handle, imports::ps_get_current_thread_id());
			auto pid = g_NtUserQueryWindow7(hWnd, (WINDOWINFOCLASS)0);
			if (ret == 1)
			{
				return  g_NtUserQueryWindow7(hWnd, WindowInfo);
			}
			else if (ret > 1 || Protect::IsProtectPID(pid)) {
				if (WindowInfo == WindowProcess)
					return  imports::ps_get_current_process_id();

				if (WindowInfo == WindowThread || WindowInfo == WindowActiveWindow)
					return imports::ps_get_current_process_id();
				return NULL;
			}
		}
		return  g_NtUserQueryWindow7(hWnd, WindowInfo);
	}

	HANDLE MyNtUserGetForegroundWindow7()
	{
		HANDLE hWnd = g_NtUserGetForegroundWindow7();
		if (!hWnd) 	return hWnd;

		if (Protect::IsProtectProcess(imports::io_get_current_process()))
		{
			return hWnd;
		}

		HANDLE handle = g_NtUserQueryWindow7(hWnd, WindowActiveWindow);
		if (handle)
		{
			Log("MyNtUserGetForegroundWindow7  %04x \r\n", handle);
			int ret = Protect::IsProtectWND(hWnd, 0, handle, imports::ps_get_current_thread_id());
			if (ret == 1)
			{
				return  hWnd;
			}
			else if (ret > 1) {
				return 0;
			}
			HANDLE pid = g_NtUserQueryWindow7(hWnd, WindowProcess);
			if (Protect::IsProtectPID(pid))
			{
				return NULL;
			}
		}

		return hWnd;
	}

	DWORD_PTR MyNtUserCallOneParam7(DWORD_PTR Param, DWORD Routine)
	{

		HANDLE handle = g_NtUserQueryWindow7((HANDLE)Param, WindowActiveWindow);
		if (handle)
		{
			Log("MyNtUserCallOneParam7  %04x \r\n", handle);
			if (Protect::IsProtectProcess(imports::io_get_current_process()))
			{
				return g_NtUserCallOneParam7(Param, Routine);
			}
			int ret = Protect::IsProtectWND((HANDLE)Param, 0, handle, imports::ps_get_current_thread_id());
			if (ret == 1)
			{
				return g_NtUserCallOneParam7(Param, Routine);
			}
			else if (ret > 1) {
				return 0;
			}
			auto pid = g_NtUserQueryWindow7((HANDLE)Param, WindowProcess);
			if (Protect::IsProtectPID(pid)) {
				return 0;
			}
		}
		return g_NtUserCallOneParam7(Param, Routine);
	}

	HANDLE MyNtUserWindowFromPoint7(LONG x, LONG y)
	{
		auto hWnd = g_NtUserWindowFromPoint7(x, y);
		if (!hWnd) 	return hWnd;
		if (Protect::IsProtectProcess(imports::io_get_current_process()))
		{
			return hWnd;
		}
		HANDLE handle = g_NtUserQueryWindow7(hWnd, WindowActiveWindow);
		if (handle)
		{
			int ret = Protect::IsProtectWND(hWnd, 0, handle, imports::ps_get_current_thread_id());
			if (ret == 1)
			{
				return  hWnd;
			}
			else if (ret > 1) {
				return 0;
			}
			auto pid = g_NtUserQueryWindow7(hWnd, WindowProcess);
			if (Protect::IsProtectPID(pid))
			{
				return 0;
			}
		}
		return hWnd;
	}
	NTSTATUS NTAPI  MyNtUserBuildHwndList7(HANDLE hDesktop, HANDLE hwndParent, BOOLEAN bChildren, ULONG dwThreadId, ULONG lParam, PHANDLE pWnd, PULONG pBufSize) {

		if (Protect::IsProtectProcess(imports::io_get_current_process()))
		{
			return  g_NtUserBuildHwndList7(hDesktop, hwndParent, bChildren, dwThreadId, lParam, pWnd, pBufSize);
		}
		HANDLE currentThread = imports::ps_get_current_thread_id();
		if (bChildren)
		{
			HANDLE handle = g_NtUserQueryWindow7(hwndParent, WindowActiveWindow);
			if (handle)
			{
				int ret = Protect::IsProtectWND(hwndParent, 0, handle, currentThread);
				if (ret == 1)
				{
					return   g_NtUserBuildHwndList7(hDesktop, hwndParent, bChildren, dwThreadId, lParam, pWnd, pBufSize);
				}
				else if (ret > 1) {
					return STATUS_UNSUCCESSFUL;
				}
			}
		}
		auto status = g_NtUserBuildHwndList7(hDesktop, hwndParent, bChildren, dwThreadId, lParam, pWnd, pBufSize);

		if (NT_SUCCESS(status) && pWnd != nullptr && pBufSize != nullptr)
		{
			ULONG i = 0;
			ULONG j;
			while (i < *pBufSize)
			{
				if (pWnd[i] == nullptr)
				{
					i++;
					continue;
				}
				HANDLE handle = g_NtUserQueryWindow7(pWnd[i], WindowActiveWindow);
				if (!handle)
				{
					i++;
					continue;
				}
				int ret = Protect::IsProtectWND(pWnd[i], 0, handle, currentThread);
				HANDLE pid = g_NtUserQueryWindow7(pWnd[i], WindowProcess);
				if (ret > 1 || Protect::IsProtectPID(pid))
				{
					if (i == 0)
					{
						pWnd[i] = (HANDLE)0x10010;
					}
					else {
						pWnd[i] = pWnd[i - 1];
					}
				}
				i++;
			}
		}

		return status;
	}

	BOOLEAN MyNtUserSetWindowDisplayAffinity7(HANDLE hWnd, LONG dwAffinity)
	{
		return g_NtUserSetWindowDisplayAffinity7(hWnd, dwAffinity);
	}

	BOOLEAN MyNtUserGetWindowDisplayAffinity7(HANDLE hWnd, PLONG dwAffinity)
	{

		if (Protect::IsProtectProcess(imports::io_get_current_process()))
		{
			return  g_NtUserGetWindowDisplayAffinity7(hWnd, dwAffinity);
		}
		HANDLE handle = g_NtUserQueryWindow7(hWnd, WindowActiveWindow);
		if (handle)
		{
			int ret = Protect::IsProtectWND(hWnd, 0, handle, imports::ps_get_current_thread_id());
			if (ret == 1)
			{
				return  g_NtUserGetWindowDisplayAffinity7(hWnd, dwAffinity);
			}
			else if (ret > 1) {
				*dwAffinity = 0;
				return TRUE;
			}
			//todo  判断窗口句柄保护
			auto pid = g_NtUserQueryWindow7(hWnd, WindowProcess);
			if (Protect::IsProtectPID(pid))
			{
				*dwAffinity = 0;
				return TRUE;
			}
		}

		return g_NtUserGetWindowDisplayAffinity7(hWnd, dwAffinity);
	}

	EXTERN_C_END

		NTSTATUS SetProtectWindow()
	{

		if (IsHookStarted7)
		{
			return STATUS_SUCCESS;
		}

		UNICODE_STRING str = { 0 };
		//RtlInitUnicodeString(&str, L"NtCreateFile");
		//g_NtCreateFile = (FNtCreateFile)MmGetSystemRoutineAddress(&str);
		//Log("g_NtCreateFile %p \r\n", g_NtCreateFile);
		//RtlInitUnicodeString(&str, L"NtOpenProcess");
		//g_NtOpenProcess = (FNtOpenProcess)MmGetSystemRoutineAddress(&str);
		//Log("g_NtOpenProcess %p \r\n", g_NtOpenProcess);
		//RtlInitUnicodeString(&str, L"NtOpenThread");
		//g_NtOpenThread = (FNtOpenThread)MmGetSystemRoutineAddress(&str);
		//Log("g_NtOpenThread %p \r\n", g_NtOpenThread);
		g_NtUserValidateHandleSecure7 = (FNtUserValidateHandleSecure7)ssdt_serv::GetFunctionAddrInSSDT(0x1334);
		Log("g_NtUserValidateHandleSecure7 %p \r\n", g_NtUserValidateHandleSecure7);

		g_NtUserCallHwnd7 = (FNtUserCallHwnd7)ssdt_serv::GetFunctionAddrInSSDT(0x110c);
		Log("g_NtUserCallHwnd7 %p \r\n", g_NtUserCallHwnd7);

		g_NtUserCallHwndParam7 = (FNtUserCallHwndParam7)ssdt_serv::GetFunctionAddrInSSDT(0x109e);
		Log("g_NtUserCallHwndParam7 %p \r\n", g_NtUserCallHwndParam7);

		g_NtUserGetClassName7 = (FNtUserGetClassName7)ssdt_serv::GetFunctionAddrInSSDT(0x107b);
		Log("g_NtUserGetClassName7 %p \r\n", g_NtUserGetClassName7);
		g_NtUserPostMessage7 = (FNtUserPostMessage7)ssdt_serv::GetFunctionAddrInSSDT(0x100f);
		Log("g_NtUserPostMessage7 %p \r\n", g_NtUserPostMessage7);
		g_NtUserMessageCall7 = (FNtUserMessageCall7)ssdt_serv::GetFunctionAddrInSSDT(0x1007);
		Log("g_NtUserMessageCall7 %p \r\n", g_NtUserMessageCall7);
		g_NtUserInternalGetWindowText7 = (FNtUserInternalGetWindowText7)ssdt_serv::GetFunctionAddrInSSDT(0x1063);
		Log("g_NtUserInternalGetWindowText7 %p \r\n", g_NtUserInternalGetWindowText7);
		g_NtUserSetParent7 = (FNtUserSetParent7)ssdt_serv::GetFunctionAddrInSSDT(0x1077);
		Log("g_NtUserSetParent7 %p \r\n", g_NtUserSetParent7);
		g_NtUserFindWindowEx7 = (FNtUserFindWindowEx7)ssdt_serv::GetFunctionAddrInSSDT(0x106e);
		Log("g_NtUserFindWindowEx7 %p \r\n", g_NtUserFindWindowEx7);
		g_NtUserQueryWindow7 = (FNtUserQueryWindow7)ssdt_serv::GetFunctionAddrInSSDT(0x1010);
		Log("g_NtUserQueryWindow7 %p \r\n", g_NtUserQueryWindow7);
		g_NtUserGetForegroundWindow7 = (FNtUserGetForegroundWindow7)ssdt_serv::GetFunctionAddrInSSDT(0x103c);
		Log("g_NtUserGetForegroundWindow7 %p \r\n", g_NtUserGetForegroundWindow7);
		g_NtUserWindowFromPoint7 = (FNtUserWindowFromPoint7)ssdt_serv::GetFunctionAddrInSSDT(0x1014);
		Log("g_NtUserWindowFromPoint7 %p \r\n", g_NtUserWindowFromPoint7);

		g_NtUserBuildHwndList7 = (FNtUserBuildHwndList7)ssdt_serv::GetFunctionAddrInSSDT(0x101c);
		Log("g_NtUserBuildHwndList7 %p \r\n", g_NtUserBuildHwndList7);

		g_NtUserSetWindowDisplayAffinity7 = (FNtUserSetWindowDisplayAffinity7)ssdt_serv::GetFunctionAddrInSSDT(0x1317);
		Log("g_NtUserSetWindowDisplayAffinity7 %p \r\n", g_NtUserSetWindowDisplayAffinity7);
		g_NtUserGetWindowDisplayAffinity7 = (FNtUserGetWindowDisplayAffinity7)ssdt_serv::GetFunctionAddrInSSDT(0x12c8);
		Log("g_NtUserGetWindowDisplayAffinity7 %p \r\n", g_NtUserGetWindowDisplayAffinity7);

		IsHookStarted7 = TRUE;
		//return  IsHookStarted ? STATUS_SUCCESS : STATUS_UNSUCCESSFUL;
		return STATUS_SUCCESS;
	}

	NTSTATUS AntiSnapWindow(ULONG32 hwnd)
	{
		KAPC_STATE apcState = { 0 };
		PEPROCESS pEprocess = 0;
		HANDLE tmpHwnd = (HANDLE)hwnd;
		NTSTATUS status;
		BOOLEAN result = FALSE;
		auto pid = g_NtUserQueryWindow7(tmpHwnd, WindowProcess);
		if (!pid)
		{
			return STATUS_UNSUCCESSFUL;
		}
		pEprocess = Utils::lookup_process_by_id(pid);
		if (!pEprocess)
		{
			return NULL;
		}
		imports::ke_stack_attach_process(pEprocess, &apcState);
		g_NtUserSetParent7(tmpHwnd, 0);
		result = g_NtUserSetWindowDisplayAffinity7(tmpHwnd, 0x1);
		imports::ke_unstack_detach_process(&apcState);
		imports::obf_dereference_object(pEprocess);

		return result ? STATUS_SUCCESS : STATUS_UNSUCCESSFUL;
	}

	BOOLEAN RemoveProtectWindow()
	{
		BOOLEAN isok = k_hook::stop();


		// 这里需要注意,确保系统的执行点已经不再当前驱动里面了
		// 比如当前驱动卸载掉了,但是你挂钩的MyNtCreateFile还在执行for操作,当然蓝屏啊
		// 这里的休眠10秒手段可以直接改进
		LARGE_INTEGER integer = { 0 };
		integer.QuadPart = -10000;
		integer.QuadPart *= 10000;
		imports::ke_delay_execution_thread(KernelMode, FALSE, &integer);
		return isok;
	}
	HANDLE GetWindowThread(HANDLE hwnd) {
		return  g_NtUserQueryWindow7(hwnd, WindowActiveWindow);
	}
	NTSTATUS StartProtect()
	{
		//UNICODE_STRING str = { 0 };
		//RtlInitUnicodeString(&str, L"NtQueryInformationProcess");
		//g_NtQueryInformationProcess = (FNtQueryInformationProcess)MmGetSystemRoutineAddress(&str);

		return	k_hook::initialize(ssdt_call_back7) && k_hook::start();
	}


	POBJECT_NAME_INFORMATION QueryFileDosName(ULONG pid) {
		POBJECT_NAME_INFORMATION ObjectName = (POBJECT_NAME_INFORMATION)imports::ex_allocate_pool(NonPagedPool, 0x300);
		PEPROCESS pEprocess;
		PVOID pFileHandle;
		pEprocess = Utils::lookup_process_by_id(UlongToHandle(pid));
		if (!pEprocess)
		{
			return NULL;
		}
 
		if (!NT_SUCCESS(imports::ps_reference_process_file_pointer(pEprocess, &pFileHandle)))
		{
			return NULL;
		}

		if (!NT_SUCCESS(imports::io_query_file_dos_device_name((PFILE_OBJECT)pFileHandle, &ObjectName)))
		{
			return NULL;
		}
		imports::obf_dereference_object(pFileHandle);
 
		return ObjectName;
	}

}