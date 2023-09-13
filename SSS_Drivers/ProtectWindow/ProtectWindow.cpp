#pragma once
#include "ProtectWindow.h"




namespace ProtectWindow {

	EXTERN_C_START
		BOOLEAN IsHookStarted = FALSE;
	FNtCreateFile g_NtCreateFile = 0;
	FNtUserFindWindowEx	g_NtUserFindWindowEx = 0;
	FNtUserBuildHwndList  g_NtUserBuildHwndList = 0;
	FNtUserQueryWindow	g_NtUserQueryWindow = 0;
	FNtUserGetForegroundWindow	g_NtUserGetForegroundWindow = 0;
	FNtUserWindowFromPoint	g_NtUserWindowFromPoint = 0;
	FNtUserSetWindowDisplayAffinity g_NtUserSetWindowDisplayAffinity = 0;
	FNtUserGetWindowDisplayAffinity g_NtUserGetWindowDisplayAffinity = 0;
	FNtUserSetParent g_NtUserSetParent = 0;
	FNtOpenProcess g_NtOpenProcess = 0;
	FNtOpenThread g_NtOpenThread = 0;
	FNtUserSetLayeredWindowAttributes g_NtUserSetLayeredWindowAttributes = 0;
	FNtUserInternalGetWindowText g_NtUserInternalGetWindowText;
	FNtUserPostMessage g_NtUserPostMessage = 0;
	FNtUserMessageCall g_NtUserMessageCall = 0;
	FNtUserGetClassName g_NtUserGetClassName = 0;
	FNtUserCallOneParam g_NtUserCallOneParam = 0;
	FNtQueryInformationProcess g_NtQueryInformationProcess = 0;
	FNtUserCallHwndParam g_NtUserCallHwndParam = 0;
	FNtUserValidateHandleSecure g_NtUserValidateHandleSecure = 0;
	FNtUserCallHwnd g_NtUserCallHwnd = 0;
	void __fastcall ssdt_call_back(unsigned long ssdt_index, void** ssdt_address)
	{
		// https://hfiref0x.github.io/
		if (!*ssdt_address)
		{
			return;
		}
		//if (*ssdt_address == g_NtQueryInformationProcess) { *ssdt_address = MyNtQueryInformationProcess; return; }
		//if (*ssdt_address == g_NtOpenThread) { *ssdt_address = MyNtOpenThread; return; }
		//if (*ssdt_address == g_NtOpenProcess) { *ssdt_address = MyNtOpenProcess; return; }
		//if (*ssdt_address == g_NtCreateFile7) { *ssdt_address = MyNtCreateFile7; return; }

		if ((ssdt_index >> 12) >0)
		{
			if (*ssdt_address == g_NtUserCallHwndParam) { *ssdt_address = MyNtUserCallHwndParam; return; }//win7需要重新实现
			if (*ssdt_address == g_NtUserValidateHandleSecure) { *ssdt_address = MyNtUserValidateHandleSecure; return; }//win7需要重新实现
			if (*ssdt_address == g_NtUserCallHwnd) { *ssdt_address = MyNtUserCallHwnd; return; }//win7需要重新实现
			if (*ssdt_address == g_NtUserCallOneParam) { *ssdt_address = MyNtUserCallOneParam; return; }//win7需要重新实现
			if (*ssdt_address == g_NtUserInternalGetWindowText) { *ssdt_address = MyNtUserInternalGetWindowText; return; }
			if (*ssdt_address == g_NtUserPostMessage) { *ssdt_address = MyNtUserPostMessage; return; }//win7需要重新实现
			if (*ssdt_address == g_NtUserMessageCall) { *ssdt_address = MyNtUserMessageCall; return; }//win7需要重新实现
			if (*ssdt_address == g_NtUserFindWindowEx) { *ssdt_address = MyNtUserFindWindowEx; return; }//win7需要重新实现
			if (*ssdt_address == g_NtUserQueryWindow) { *ssdt_address = MyNtUserQueryWindow; return; }
			if (*ssdt_address == g_NtUserGetForegroundWindow) { *ssdt_address = MyNtUserGetForegroundWindow; return; }//win7需要重新实现
			if (*ssdt_address == g_NtUserBuildHwndList) { *ssdt_address = MyNtUserBuildHwndList; return; }
			if (*ssdt_address == g_NtUserSetWindowDisplayAffinity) { *ssdt_address = MyNtUserSetWindowDisplayAffinity; return; }
			if (*ssdt_address == g_NtUserGetWindowDisplayAffinity) { *ssdt_address = MyNtUserGetWindowDisplayAffinity; return; }
			if (*ssdt_address == g_NtUserGetClassName) { *ssdt_address = MyNtUserGetClassName; return; }//win7需要重新实现
		} 
	}

	ULONG_PTR MyNtUserCallHwnd(HANDLE hwnd, DWORD code)
	{
		if (Protect::IsProtectProcess(imports::io_get_current_process()))
		{
			return g_NtUserCallHwnd(hwnd, code);
		}
		auto handle = g_NtUserQueryWindow(hwnd, WindowActiveWindow);
		if (handle)
		{
			int ret = Protect::IsProtectWND(hwnd, 0, handle, imports::ps_get_current_thread_id());
			if (ret == 1)
			{
				return g_NtUserCallHwnd(hwnd, code);
			}
			else if (ret > 1) {
				return 0;
			}
			auto pid = g_NtUserQueryWindow(hwnd, WindowProcess);
			if (Protect::IsProtectPID(pid)) {
				return 0;
			}
		}
		return g_NtUserCallHwnd(hwnd, code);
	}

	ULONG_PTR MyNtUserCallHwndParam(HANDLE hwnd, DWORD_PTR param, DWORD code)
	{
		if (Protect::IsProtectProcess(imports::io_get_current_process()))
		{
			return g_NtUserCallHwndParam(hwnd, param, code);
		}
		auto handle = g_NtUserQueryWindow(hwnd, WindowActiveWindow);
		if (handle)
		{
			int ret = Protect::IsProtectWND(hwnd, 0, handle, imports::ps_get_current_thread_id());
			if (ret == 1)
			{
				return g_NtUserCallHwndParam(hwnd, param, code);
			}
			else if (ret > 1) {
				return 0;
			}
			auto pid = g_NtUserQueryWindow(hwnd, WindowProcess);
			if (Protect::IsProtectPID(pid)) {
				return 0;
			}
		}
		return g_NtUserCallHwndParam(hwnd, param, code);
	}

	BOOLEAN MyNtUserValidateHandleSecure(HANDLE hHdl)
	{
		if (Protect::IsProtectProcess(imports::io_get_current_process()))
		{
			return g_NtUserValidateHandleSecure(hHdl);
		}
		auto handle = g_NtUserQueryWindow((HANDLE)hHdl, WindowActiveWindow);
		if (handle)
		{
			int ret = Protect::IsProtectWND((HANDLE)hHdl, 0, handle, imports::ps_get_current_thread_id());
			if (ret == 1)
			{
				return TRUE;
			}
			else if (ret > 1) {
				return FALSE;
			}
			auto pid = g_NtUserQueryWindow((HANDLE)hHdl, WindowProcess);
			if (Protect::IsProtectPID(pid)) {
				return FALSE;
			}
		}
		return  g_NtUserValidateHandleSecure(hHdl);
	}



	INT MyNtUserGetClassName(HANDLE hWnd, BOOLEAN Ansi, PUNICODE_STRING ClassName)
	{
		if (Protect::IsProtectProcess(imports::io_get_current_process()))
		{
			return g_NtUserGetClassName(hWnd, Ansi, ClassName);
		}
		auto handle = g_NtUserQueryWindow(hWnd, WindowActiveWindow);
		if (handle)
		{
			int ret = Protect::IsProtectWND(hWnd, 0, handle, imports::ps_get_current_thread_id());
			if (ret == 1)
			{
				return g_NtUserGetClassName(hWnd, Ansi, ClassName);
			}
			else if (ret > 1) {
				return FALSE;
			}
			auto pid = g_NtUserQueryWindow(hWnd, WindowProcess);
			if (Protect::IsProtectPID(pid)) {
				return FALSE;
			}
		}
		return 	  g_NtUserGetClassName(hWnd, Ansi, ClassName);
	}

	BOOLEAN MyNtUserPostMessage(HANDLE hWnd, UINT Msg, ULONG wParam, ULONG lParam)
	{
		if (Msg == WM_GETTEXT || Msg == WM_GETICON)
		{
			if (Protect::IsProtectProcess(imports::io_get_current_process()))
			{
				return g_NtUserPostMessage(hWnd, Msg, wParam, lParam);
			}
			auto handle = g_NtUserQueryWindow(hWnd, WindowActiveWindow);
			if (handle)
			{
				int ret = Protect::IsProtectWND(hWnd, 0, handle, imports::ps_get_current_thread_id());
				if (ret == 1)
				{
					return g_NtUserPostMessage(hWnd, Msg, wParam, lParam);
				}
				else if (ret > 1) {
					return FALSE;
				}
				auto pid = g_NtUserQueryWindow(hWnd, WindowProcess);
				if (Protect::IsProtectPID(pid)) {
					return FALSE;
				}
			}
		}
		return  g_NtUserPostMessage(hWnd, Msg, wParam, lParam);
	}

	BOOLEAN MyNtUserMessageCall(HANDLE hWnd, UINT Msg, ULONG wParam, ULONG lParam, ULONG_PTR ResultInfo, DWORD dwType, BOOLEAN Ansi)
	{
		if (Msg == WM_GETTEXT || Msg == WM_GETICON)
		{
			if (Protect::IsProtectProcess(imports::io_get_current_process()))
			{
				return g_NtUserMessageCall(hWnd, Msg, wParam, lParam, ResultInfo, dwType, Ansi);
			}
			auto handle = g_NtUserQueryWindow(hWnd, WindowActiveWindow);
			if (handle)
			{
				int ret = Protect::IsProtectWND(hWnd, 0, handle, imports::ps_get_current_thread_id());
				if (ret == 1)
				{
					return g_NtUserMessageCall(hWnd, Msg, wParam, lParam, ResultInfo, dwType, Ansi);
				}
				else if (ret > 1) {

					return FALSE;
				}
			}
			auto pid = g_NtUserQueryWindow(hWnd, WindowProcess);
			if (Protect::IsProtectPID(pid)) {
				return FALSE;
			}
		}
		return  g_NtUserMessageCall(hWnd, Msg, wParam, lParam, ResultInfo, dwType, Ansi);
	}

	NTSTATUS MyNtQueryInformationProcess(HANDLE ProcessHandle, PROCESSINFOCLASS ProcessInformationClass, PVOID ProcessInformation, ULONG ProcessInformationLength, PULONG ReturnLength)
	{

		NTSTATUS status = g_NtQueryInformationProcess(ProcessHandle, ProcessInformationClass, ProcessInformation, ProcessInformationLength, ReturnLength);

		return status;
	}

	ULONG MyNtUserInternalGetWindowText(HANDLE hWnd, LPWSTR pString, int cchMaxCount)
	{
		if (Protect::IsProtectProcess(imports::io_get_current_process()))
		{
			return g_NtUserInternalGetWindowText(hWnd, pString, cchMaxCount);
		}

		auto handle = g_NtUserQueryWindow(hWnd, WindowActiveWindow);
		if (handle)
		{
			int ret = Protect::IsProtectWND(hWnd, 0, handle, imports::ps_get_current_thread_id());
			if (ret == 1)
			{
				return  g_NtUserInternalGetWindowText(hWnd, pString, cchMaxCount);
			}
			else if (ret > 1) {

				return FALSE;
			}
			auto pid = g_NtUserQueryWindow(hWnd, WindowProcess);
			if (Protect::IsProtectPID(pid)) {
				return FALSE;
			}
		}
		return g_NtUserInternalGetWindowText(hWnd, pString, cchMaxCount);
	}


	NTSTATUS MyNtOpenProcess(PHANDLE ProcessHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, PCLIENT_ID ClientId)
	{
		if (Protect::IsProtectProcess(imports::io_get_current_process()))
		{
			return g_NtOpenProcess(ProcessHandle, DesiredAccess, ObjectAttributes, ClientId);
		}
		if (ClientId != NULL)
		{
			if (ClientId->UniqueProcess == NULL)
				return g_NtOpenProcess(ProcessHandle, DesiredAccess, ObjectAttributes, ClientId);

			HANDLE OldPid = ClientId->UniqueProcess;
			if (Protect::IsProtectPID(OldPid))
			{
				ClientId->UniqueProcess = UlongToHandle(0xFFFFFFFC);
				NTSTATUS Status = g_NtOpenProcess(ProcessHandle, DesiredAccess, ObjectAttributes, ClientId);
				ClientId->UniqueProcess = OldPid;
				return Status;
			}
		}
		return  g_NtOpenProcess(ProcessHandle, DesiredAccess, ObjectAttributes, ClientId);
	}

	NTSTATUS MyNtCreateFile(PHANDLE FileHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, PIO_STATUS_BLOCK IoStatusBlock, PLARGE_INTEGER AllocationSize, ULONG FileAttributes, ULONG ShareAccess, ULONG CreateDisposition, ULONG CreateOptions, PVOID EaBuffer, ULONG EaLength)
	{
		// NtCreateFile 的调用方必须在 IRQL = PASSIVE_LEVEL且 启用了特殊内核 APC 的情况下运行
		if (KeGetCurrentIrql() != PASSIVE_LEVEL) return g_NtCreateFile(FileHandle, DesiredAccess, ObjectAttributes, IoStatusBlock, AllocationSize, FileAttributes, ShareAccess, CreateDisposition, CreateOptions, EaBuffer, EaLength);
		if (imports::ex_get_previous_mode() == KernelMode) return g_NtCreateFile(FileHandle, DesiredAccess, ObjectAttributes, IoStatusBlock, AllocationSize, FileAttributes, ShareAccess, CreateDisposition, CreateOptions, EaBuffer, EaLength);
		if (imports::ps_get_process_session_id(imports::io_get_current_process()) == 0) return g_NtCreateFile(FileHandle, DesiredAccess, ObjectAttributes, IoStatusBlock, AllocationSize, FileAttributes, ShareAccess, CreateDisposition, CreateOptions, EaBuffer, EaLength);

		if (ObjectAttributes &&
			ObjectAttributes->ObjectName &&
			ObjectAttributes->ObjectName->Buffer)
		{
			wchar_t* name = (wchar_t*)imports::ex_allocate_pool(NonPagedPool, ObjectAttributes->ObjectName->Length + sizeof(wchar_t));
			if (name)
			{
				Utils::kmemset(name, 0, ObjectAttributes->ObjectName->Length + sizeof(wchar_t));
				Utils::kmemcpy(name, ObjectAttributes->ObjectName->Buffer, ObjectAttributes->ObjectName->Length);


				//if (wcsstr(name, L"My\\Certificates") && !wcsstr(name, L".ini"))
				//{

				//	imports::ex_free_pool_with_tag(name,0);
				//	return STATUS_ACCESS_DENIED;
				//}

				imports::ex_free_pool_with_tag(name, 0);
			}
		}

		return g_NtCreateFile(FileHandle, DesiredAccess, ObjectAttributes, IoStatusBlock, AllocationSize, FileAttributes, ShareAccess, CreateDisposition, CreateOptions, EaBuffer, EaLength);

	}

	HANDLE MyNtUserFindWindowEx(IN HANDLE hwndParent, IN HANDLE hwndChild, IN PUNICODE_STRING pstrClassName OPTIONAL, IN PUNICODE_STRING pstrWindowName OPTIONAL, IN DWORD dwType)
	{
		auto res = g_NtUserFindWindowEx(hwndParent, hwndChild, pstrClassName, pstrWindowName, dwType);
		if (!res) 	return res;

		if (Protect::IsProtectProcess(imports::io_get_current_process()))
		{
			return res;
		}

		HANDLE handle = g_NtUserQueryWindow(res, WindowActiveWindow);
		if (handle)
		{
			int ret = Protect::IsProtectWND(hwndParent, hwndChild, handle, imports::ps_get_current_thread_id());
			if (ret == 1)
			{
				return  res;
			}
			else if (ret > 1) {
				return 0;
			}
		}
		auto pid = g_NtUserQueryWindow(res, WindowProcess);
		if (pid && Protect::IsProtectPID(pid))
		{
			return NULL;
		}

		return res;
	}

	NTSTATUS NTAPI MyNtUserBuildHwndList(HANDLE hDesktop, HANDLE  hwndParent, BOOLEAN bChildren, BOOLEAN bUnknownFlag, ULONG dwThreadId, ULONG lParam, HANDLE* pWnd, PULONG pBufSize)
	{

		if (Protect::IsProtectProcess(imports::io_get_current_process()))
		{
			return  g_NtUserBuildHwndList(hDesktop, hwndParent, bChildren, bUnknownFlag, dwThreadId, lParam, pWnd, pBufSize);
		}
		HANDLE currentThread = imports::ps_get_current_thread_id();
		//if (bChildren)
		//{
		//	HANDLE handle = g_NtUserQueryWindow(hwndParent, WindowActiveWindow);
		//	if (handle)
		//	{
		//		int ret = Protect::IsProtectWND(hwndParent, 0, handle, currentThread);
		//		if (ret == 1)
		//		{
		//			return   g_NtUserBuildHwndList(hDesktop, hwndParent, bChildren, bUnknownFlag, dwThreadId, lParam, pWnd, pBufSize);
		//		}
		//		else if (ret > 1) {
		//			return STATUS_UNSUCCESSFUL;
		//		}
		//	}
		//}
		NTSTATUS status = g_NtUserBuildHwndList(hDesktop, hwndParent, bChildren, bUnknownFlag, dwThreadId, lParam, pWnd, pBufSize);

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
				auto handle = g_NtUserQueryWindow(pWnd[i], WindowActiveWindow);
				if (!handle)
				{
					i++;
					continue;
				}
				int ret = Protect::IsProtectWND(pWnd[i], 0, handle, currentThread);
				auto pid = g_NtUserQueryWindow(pWnd[i], WindowProcess);
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

	HANDLE MyNtUserQueryWindow(HANDLE  hWnd, WINDOWINFOCLASS WindowInfo)
	{

		if (Protect::IsProtectProcess(imports::io_get_current_process()))
		{
			return  g_NtUserQueryWindow(hWnd, WindowInfo);
		}
		auto handle = g_NtUserQueryWindow(hWnd, WindowActiveWindow);
		if (handle)
		{
			auto ret = Protect::IsProtectWND(hWnd, 0, handle, imports::ps_get_current_thread_id());
			auto pid = g_NtUserQueryWindow(hWnd, (WINDOWINFOCLASS)0);
			if (ret == 1)
			{
				return  g_NtUserQueryWindow(hWnd, WindowInfo);
			}
			else if (ret > 1 || Protect::IsProtectPID(pid)) {
				if (WindowInfo == WindowProcess)
					return  imports::ps_get_current_process_id();

				if (WindowInfo == WindowThread || WindowInfo == WindowActiveWindow)
					return imports::ps_get_current_process_id();
				return NULL;
			}
		}
		return  g_NtUserQueryWindow(hWnd, WindowInfo);
	}

	HANDLE MyNtUserGetForegroundWindow()
	{
		HANDLE hWnd = g_NtUserGetForegroundWindow();
		if (!hWnd) 	return hWnd;

		if (Protect::IsProtectProcess(imports::io_get_current_process()))
		{
			return hWnd;
		}

		auto handle = g_NtUserQueryWindow(hWnd, WindowActiveWindow);
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
			HANDLE pid = g_NtUserQueryWindow(hWnd, WindowProcess);
			if (Protect::IsProtectPID(pid))
			{
				return NULL;
			}
		}

		return hWnd;
	}

	DWORD_PTR MyNtUserCallOneParam(DWORD_PTR Param, DWORD Routine)
	{

		auto handle = g_NtUserQueryWindow((HANDLE)Param, WindowActiveWindow);
		if (handle)
		{
			if (Protect::IsProtectProcess(imports::io_get_current_process()))
			{
				return g_NtUserCallOneParam(Param, Routine);
			}
			int ret = Protect::IsProtectWND((HANDLE)Param, 0, handle, imports::ps_get_current_thread_id());
			if (ret == 1)
			{
				return g_NtUserCallOneParam(Param, Routine);
			}
			else if (ret > 1) {
				return 0;
			}
			auto pid = g_NtUserQueryWindow((HANDLE)Param, WindowProcess);
			if (Protect::IsProtectPID(pid)) {
				return 0;
			}
		}
		return g_NtUserCallOneParam(Param, Routine);
	}

	HANDLE MyNtUserWindowFromPoint(LONG x, LONG y)
	{
		auto hWnd = g_NtUserWindowFromPoint(x, y);
		if (!hWnd) 	return hWnd;
		if (Protect::IsProtectProcess(imports::io_get_current_process()))
		{
			return hWnd;
		}
		auto handle = g_NtUserQueryWindow(hWnd, WindowActiveWindow);
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
			auto pid = g_NtUserQueryWindow(hWnd, WindowProcess);
			if (Protect::IsProtectPID(pid))
			{
				return 0;
			}
		}
		return hWnd;
	}

	BOOLEAN MyNtUserSetWindowDisplayAffinity(HANDLE hWnd, LONG dwAffinity)
	{
		return g_NtUserSetWindowDisplayAffinity(hWnd, dwAffinity);
	}

	BOOLEAN MyNtUserGetWindowDisplayAffinity(HANDLE hWnd, PLONG dwAffinity)
	{

		if (Protect::IsProtectProcess(imports::io_get_current_process()))
		{
			return  g_NtUserGetWindowDisplayAffinity(hWnd, dwAffinity);
		}
		auto handle = g_NtUserQueryWindow(hWnd, WindowActiveWindow);
		if (handle)
		{
			int ret = Protect::IsProtectWND(hWnd, 0, handle, imports::ps_get_current_thread_id());
			if (ret == 1)
			{
				return  g_NtUserGetWindowDisplayAffinity(hWnd, dwAffinity);
			}
			else if (ret > 1) {
				*dwAffinity = 0;
				return TRUE;
			}
			//todo  判断窗口句柄保护
			auto pid = g_NtUserQueryWindow(hWnd, WindowProcess);
			if (Protect::IsProtectPID(pid))
			{
				*dwAffinity = 0;
				return TRUE;
			}
		}

		return g_NtUserGetWindowDisplayAffinity(hWnd, dwAffinity);
	}

	EXTERN_C_END

		NTSTATUS SetProtectWindow()
	{

		if (IsHookStarted)
		{
			return STATUS_SUCCESS;
		}
		DbgBreakPoint();
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
		g_NtUserValidateHandleSecure = (FNtUserValidateHandleSecure)ssdt_serv::GetWin32kFunc10(skCrypt("NtUserValidateHandleSecure"));
		Log("g_NtUserValidateHandleSecure %p \r\n", g_NtUserValidateHandleSecure);

		g_NtUserCallHwnd = (FNtUserCallHwnd)ssdt_serv::GetWin32kFunc10(skCrypt("NtUserCallHwnd"));
		Log("g_NtUserCallHwnd %p \r\n", g_NtUserCallHwnd);

		g_NtUserCallHwndParam = (FNtUserCallHwndParam)ssdt_serv::GetWin32kFunc10(skCrypt("NtUserCallHwndParam"));
		Log("g_NtUserCallHwndParam %p \r\n", g_NtUserCallHwndParam);

		g_NtUserGetClassName = (FNtUserGetClassName)ssdt_serv::GetWin32kFunc10(skCrypt("NtUserGetClassName"));
		Log("g_NtUserGetClassName %p \r\n", g_NtUserGetClassName);
		g_NtUserPostMessage = (FNtUserPostMessage)ssdt_serv::GetWin32kFunc10(skCrypt("NtUserPostMessage"));
		Log("g_NtUserPostMessage %p \r\n", g_NtUserPostMessage);
		g_NtUserMessageCall = (FNtUserMessageCall)ssdt_serv::GetWin32kFunc10(skCrypt("NtUserMessageCall"));
		Log("g_NtUserMessageCall %p \r\n", g_NtUserMessageCall);
		g_NtUserInternalGetWindowText = (FNtUserInternalGetWindowText)ssdt_serv::GetWin32kFunc10(skCrypt("NtUserInternalGetWindowText"));
		Log("g_NtUserInternalGetWindowText %p \r\n", g_NtUserInternalGetWindowText);
		g_NtUserSetParent = (FNtUserSetParent)ssdt_serv::GetWin32kFunc10(skCrypt("NtUserSetParent"));
		Log("g_NtUserSetParent %p \r\n", g_NtUserSetParent);
		g_NtUserFindWindowEx = (FNtUserFindWindowEx)ssdt_serv::GetWin32kFunc10(skCrypt("NtUserFindWindowEx"));
		Log("g_NtUserFindWindowEx %p \r\n", g_NtUserFindWindowEx);
		g_NtUserQueryWindow = (FNtUserQueryWindow)ssdt_serv::GetWin32kFunc10(skCrypt("NtUserQueryWindow"));
		Log("g_NtUserQueryWindow %p \r\n", g_NtUserQueryWindow);
		g_NtUserGetForegroundWindow = (FNtUserGetForegroundWindow)ssdt_serv::GetWin32kFunc10(skCrypt("NtUserGetForegroundWindow"));
		Log("g_NtUserGetForegroundWindow %p \r\n", g_NtUserGetForegroundWindow);
		g_NtUserWindowFromPoint = (FNtUserWindowFromPoint)ssdt_serv::GetWin32kFunc10(skCrypt("NtUserWindowFromPoint"));
		Log("g_NtUserWindowFromPoint %p \r\n", g_NtUserWindowFromPoint);
		g_NtUserBuildHwndList = (FNtUserBuildHwndList)ssdt_serv::GetWin32kFunc10(skCrypt("NtUserBuildHwndList"));
		Log("g_NtUserBuildHwndList %p \r\n", g_NtUserBuildHwndList);




		g_NtUserSetWindowDisplayAffinity = (FNtUserSetWindowDisplayAffinity)ssdt_serv::GetWin32kFunc10(skCrypt("NtUserSetWindowDisplayAffinity"));
		Log("g_NtUserSetWindowDisplayAffinity %p \r\n", g_NtUserSetWindowDisplayAffinity);
		g_NtUserGetWindowDisplayAffinity = (FNtUserGetWindowDisplayAffinity)ssdt_serv::GetWin32kFunc10(skCrypt("NtUserGetWindowDisplayAffinity"));		Log("g_NtUserGetWindowDisplayAffinity %p \r\n", g_NtUserGetWindowDisplayAffinity);

		IsHookStarted = TRUE;
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
		auto pid = g_NtUserQueryWindow(tmpHwnd, WindowProcess);
		if (!pid)
		{
			return STATUS_UNSUCCESSFUL;
		}
		status = imports::ps_lookup_process_by_process_id(pid, &pEprocess);
		if (!NT_SUCCESS(status))
		{
			return STATUS_UNSUCCESSFUL;
		}
		imports::ke_stack_attach_process(pEprocess, &apcState);
		g_NtUserSetParent(tmpHwnd, 0);
		result = g_NtUserSetWindowDisplayAffinity(tmpHwnd, 0x11);
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
		return  g_NtUserQueryWindow(hwnd, WindowActiveWindow);
	}
	NTSTATUS StartProtect()
	{
		//UNICODE_STRING str = { 0 };
		//RtlInitUnicodeString(&str, L"NtQueryInformationProcess");
		//g_NtQueryInformationProcess = (FNtQueryInformationProcess)MmGetSystemRoutineAddress(&str);

		return	k_hook::initialize(ssdt_call_back) && k_hook::start();
	}


	POBJECT_NAME_INFORMATION QueryFileDosName(ULONG pid) {
		POBJECT_NAME_INFORMATION ObjectName = (POBJECT_NAME_INFORMATION)imports::ex_allocate_pool(NonPagedPool, 0x300);
		PEPROCESS pEprocess;
		PVOID pFileHandle;

		NTSTATUS status = imports::ps_lookup_process_by_process_id(UlongToHandle(pid), &pEprocess);

		if (!NT_SUCCESS(imports::ps_reference_process_file_pointer(pEprocess, &pFileHandle)))
		{
			return NULL;
		}

		if (!NT_SUCCESS(imports::io_query_file_dos_device_name((PFILE_OBJECT)pFileHandle, &ObjectName)))
		{
			return NULL;
		}
		imports::obf_dereference_object(pFileHandle);
		imports::obf_dereference_object(pEprocess);//释放引用次数 
		return ObjectName;
	}

}