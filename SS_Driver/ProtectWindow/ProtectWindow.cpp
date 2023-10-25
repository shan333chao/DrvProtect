#include "ProtectWindow.hpp"
#include "Protect.hpp"


namespace ProtectWindow {

	EXTERN_C_START
		BOOLEAN IsHookStarted = FALSE;
	FNtCreateFile g_NtCreateFile = 0;
	FNtUserFindWindowEx	g_NtUserFindWindowEx = 0;
 
	FNtUserBuildHwndList7  g_NtUserBuildHwndList = 0;
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
	FNtUserGetWindowDC g_NtUserGetWindowDC = 0;
	FNtUserGetDC g_NtUserGetDC = 0;
	void __fastcall ssdt_call_back(unsigned long ssdt_index, void** ssdt_address)
	{
		// https://hfiref0x.github.io/
		UNREFERENCED_PARAMETER(ssdt_index);
		if (*ssdt_address == 0)
		{
			return;
		}
		//if (*ssdt_address == g_NtUserCallHwndParam) { *ssdt_address = MyNtUserCallHwndParam; return; }
		if (*ssdt_address == g_NtUserValidateHandleSecure) { *ssdt_address = MyNtUserValidateHandleSecure; return; }
		//if (*ssdt_address == g_NtUserCallHwnd) { *ssdt_address = MyNtUserCallHwnd; return; }
		//if (*ssdt_address == g_NtUserCallOneParam) { *ssdt_address = MyNtUserCallOneParam; return; }
		if (*ssdt_address == g_NtUserInternalGetWindowText) { *ssdt_address = MyNtUserInternalGetWindowText; return; }
		//if (*ssdt_address == g_NtUserPostMessage) { *ssdt_address = MyNtUserPostMessage; return; }
		//if (*ssdt_address == g_NtUserMessageCall) { *ssdt_address = MyNtUserMessageCall; return; }
		//if (*ssdt_address == g_NtQueryInformationProcess) { *ssdt_address = MyNtQueryInformationProcess; return; }
		//if (*ssdt_address == g_NtCreateFile) { *ssdt_address = MyNtCreateFile; return; }
		//if (*ssdt_address == g_NtOpenThread) { *ssdt_address = MyNtOpenThread; return; }
		//if (*ssdt_address == g_NtOpenProcess) { *ssdt_address = MyNtOpenProcess; return; }
		if (*ssdt_address == g_NtUserFindWindowEx) { *ssdt_address = MyNtUserFindWindowEx; return; }
		if (*ssdt_address == g_NtUserQueryWindow) { *ssdt_address = MyNtUserQueryWindow; return; }
		//if (*ssdt_address == g_NtUserWindowFromPoint) { *ssdt_address = MyNtUserWindowFromPoint; return; }
		if (*ssdt_address == g_NtUserGetForegroundWindow) { *ssdt_address = MyNtUserGetForegroundWindow; return; }
	 
		if (*ssdt_address== g_NtUserBuildHwndList)
		{
			*ssdt_address = MyNtUserBuildHwndList7; 
			return;
		}
 
		if (*ssdt_address == g_NtUserGetClassName) { *ssdt_address = MyNtUserGetClassName; return; }

		if (*ssdt_address == g_NtUserGetWindowDC) { *ssdt_address = MyNtUserGetWindowDC; return; }
		if (*ssdt_address == g_NtUserGetDC) { *ssdt_address = MyNtUserGetWindowDC; return; }


		//if (*ssdt_address == g_NtUserBuildHwndList7) { *ssdt_address = MyNtUserBuildHwndList7;  return; }

	}

	ULONG_PTR MyNtUserCallHwnd(HWND hwnd, DWORD code)
	{
		if (Protect::IsProtectProcess(PsGetCurrentProcess()))
		{
			return g_NtUserCallHwnd(hwnd, code);
		}
		auto handle = g_NtUserQueryWindow(hwnd, WindowActiveWindow);
		if (handle)
		{
			int ret = Protect::IsProtectWND(hwnd, 0, handle, PsGetCurrentThreadId());
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

	ULONG_PTR MyNtUserCallHwndParam(HWND hwnd, DWORD_PTR param, DWORD code)
	{
		if (Protect::IsProtectProcess(PsGetCurrentProcess()))
		{
			return g_NtUserCallHwndParam(hwnd, param, code);
		}
		auto handle = g_NtUserQueryWindow(hwnd, WindowActiveWindow);
		if (handle)
		{
			int ret = Protect::IsProtectWND(hwnd, 0, handle, PsGetCurrentThreadId());
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

	BOOL MyNtUserValidateHandleSecure(HANDLE hHdl)
	{
		if (Protect::IsProtectProcess(PsGetCurrentProcess()))
		{
			return g_NtUserValidateHandleSecure(hHdl);
		}
		auto handle = g_NtUserQueryWindow((HWND)hHdl, WindowActiveWindow);
		if (handle)
		{
			int ret = Protect::IsProtectWND((HWND)hHdl, 0, handle, PsGetCurrentThreadId());
			if (ret == 1)
			{
				return TRUE;
			}
			else if (ret > 1) {
				return FALSE;
			}
			auto pid = g_NtUserQueryWindow((HWND)hHdl, WindowProcess);
			if (Protect::IsProtectPID(pid)) {
				return FALSE;
			}
		}
		return  g_NtUserValidateHandleSecure(hHdl);
	}

	__int64 MyNtUserGetWindowDC(__int64 hwnd)
	{
		if (Protect::IsProtectProcess(IoGetCurrentProcess()))
		{
			return  g_NtUserGetWindowDC(hwnd);
		}
		auto threadHandle = g_NtUserQueryWindow(ULongToHandle(hwnd), WindowActiveWindow);
		if (threadHandle)
		{
			auto ret = Protect::IsProtectWND((HWND)hwnd, 0, threadHandle, PsGetCurrentProcessId());
			auto pid = g_NtUserQueryWindow(ULongToHandle(hwnd), (WINDOWINFOCLASS)0);
			if (ret == 1)
			{
				return   g_NtUserGetWindowDC(hwnd);
			}
			else if (ret > 1 || Protect::IsProtectPID(pid)) {
				return g_NtUserGetWindowDC(0x10010);
			}
		}
		return  g_NtUserGetWindowDC(hwnd);
	}



	INT MyNtUserGetClassName(HWND hWnd, BOOL Ansi, PUNICODE_STRING ClassName)
	{
		if (Protect::IsProtectProcess(PsGetCurrentProcess()))
		{
			return g_NtUserGetClassName(hWnd, Ansi, ClassName);
		}
		auto handle = g_NtUserQueryWindow(hWnd, WindowActiveWindow);
		if (handle)
		{
			int ret = Protect::IsProtectWND(hWnd, 0, handle, PsGetCurrentThreadId());
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

	BOOL MyNtUserPostMessage(HWND hWnd, UINT Msg, WPARAM wParam, LPARAM lParam)
	{
		if (Msg == WM_GETTEXT || Msg == WM_GETICON)
		{
			if (Protect::IsProtectProcess(PsGetCurrentProcess()))
			{
				return g_NtUserPostMessage(hWnd, Msg, wParam, lParam);
			}
			auto handle = g_NtUserQueryWindow(hWnd, WindowActiveWindow);
			if (handle)
			{
				int ret = Protect::IsProtectWND(hWnd, 0, handle, PsGetCurrentThreadId());
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

	BOOL MyNtUserMessageCall(HWND hWnd, UINT Msg, WPARAM wParam, LPARAM lParam, ULONG_PTR ResultInfo, DWORD dwType, BOOL Ansi)
	{
		if (Msg == WM_GETTEXT || Msg == WM_GETICON)
		{
			if (Protect::IsProtectProcess(PsGetCurrentProcess()))
			{
				return g_NtUserMessageCall(hWnd, Msg, wParam, lParam, ResultInfo, dwType, Ansi);
			}
			auto handle = g_NtUserQueryWindow(hWnd, WindowActiveWindow);
			if (handle)
			{
				int ret = Protect::IsProtectWND(hWnd, 0, handle, PsGetCurrentThreadId());
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

	ULONG MyNtUserInternalGetWindowText(HWND hWnd, LPWSTR pString, int cchMaxCount)
	{
		if (Protect::IsProtectProcess(PsGetCurrentProcess()))
		{
			return g_NtUserInternalGetWindowText(hWnd, pString, cchMaxCount);
		}

		auto handle = g_NtUserQueryWindow(hWnd, WindowActiveWindow);
		if (handle)
		{
			int ret = Protect::IsProtectWND(hWnd, 0, handle, PsGetCurrentThreadId());
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

	NTSTATUS MyNtOpenThread(PHANDLE ProcessHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, PCLIENT_ID ClientId)
	{
		if (Protect::IsProtectProcess(PsGetCurrentProcess()))
		{
			return g_NtOpenThread(ProcessHandle, DesiredAccess, ObjectAttributes, ClientId);
		}
		if (ClientId != NULL)
		{
			if (ClientId->UniqueProcess == NULL)
				return g_NtOpenThread(ProcessHandle, DesiredAccess, ObjectAttributes, ClientId);
			PETHREAD TargetThread;
			NTSTATUS status = PsLookupThreadByThreadId(ClientId->UniqueThread, &TargetThread);
			if (!NT_SUCCESS(status) && TargetThread != NULL)
			{
				PEPROCESS TargetProcess = IoThreadToProcess(TargetThread);
				ObDereferenceObject(TargetThread);
				if (Protect::IsProtectProcess(TargetProcess))
				{
					HANDLE OldTid = ClientId->UniqueThread;
					ClientId->UniqueThread = UlongToHandle(0xFFFFFFFC);
					NTSTATUS Status = g_NtOpenThread(ProcessHandle, DesiredAccess, ObjectAttributes, ClientId);
					ClientId->UniqueProcess = OldTid;
					return Status;
				}
			}
		}
		return  g_NtOpenThread(ProcessHandle, DesiredAccess, ObjectAttributes, ClientId);
	}

	NTSTATUS MyNtOpenProcess(PHANDLE ProcessHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, PCLIENT_ID ClientId)
	{
		if (Protect::IsProtectProcess(PsGetCurrentProcess()))
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
		if (ExGetPreviousMode() == KernelMode) return g_NtCreateFile(FileHandle, DesiredAccess, ObjectAttributes, IoStatusBlock, AllocationSize, FileAttributes, ShareAccess, CreateDisposition, CreateOptions, EaBuffer, EaLength);
		if (PsGetProcessSessionId(IoGetCurrentProcess()) == 0) return g_NtCreateFile(FileHandle, DesiredAccess, ObjectAttributes, IoStatusBlock, AllocationSize, FileAttributes, ShareAccess, CreateDisposition, CreateOptions, EaBuffer, EaLength);

		if (ObjectAttributes &&
			ObjectAttributes->ObjectName &&
			ObjectAttributes->ObjectName->Buffer)
		{
			wchar_t* name = (wchar_t*)ExAllocatePool(NonPagedPool, ObjectAttributes->ObjectName->Length + sizeof(wchar_t));
			if (name)
			{
				RtlZeroMemory(name, ObjectAttributes->ObjectName->Length + sizeof(wchar_t));
				RtlCopyMemory(name, ObjectAttributes->ObjectName->Buffer, ObjectAttributes->ObjectName->Length);

				if (wcsstr(name, L"My\\Certificates") && !wcsstr(name, L".ini"))
				{
 
					ExFreePool(name);
					return STATUS_ACCESS_DENIED;
				}

				ExFreePool(name);
			}
		}

		return g_NtCreateFile(FileHandle, DesiredAccess, ObjectAttributes, IoStatusBlock, AllocationSize, FileAttributes, ShareAccess, CreateDisposition, CreateOptions, EaBuffer, EaLength);

	}

	HANDLE MyNtUserFindWindowEx(IN HWND hwndParent, IN HWND hwndChild, IN PUNICODE_STRING pstrClassName OPTIONAL, IN PUNICODE_STRING pstrWindowName OPTIONAL, IN DWORD dwType)
	{
		auto res = g_NtUserFindWindowEx(hwndParent, hwndChild, pstrClassName, pstrWindowName, dwType);
		if (!res) 	return res;

		if (Protect::IsProtectProcess(PsGetCurrentProcess()))
		{
			return res;
		}

		HANDLE handle = g_NtUserQueryWindow(res, WindowActiveWindow);
		if (handle)
		{
			int ret = Protect::IsProtectWND(hwndParent, hwndChild, handle, PsGetCurrentThreadId());
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

 
	HANDLE MyNtUserQueryWindow(HWND  hWnd, WINDOWINFOCLASS WindowInfo)
	{

		if (Protect::IsProtectProcess(PsGetCurrentProcess()))
		{
			return  g_NtUserQueryWindow(hWnd, WindowInfo);
		}
		auto handle = g_NtUserQueryWindow(hWnd, WindowActiveWindow);
		if (handle)
		{
			auto ret = Protect::IsProtectWND(hWnd, 0, handle, PsGetCurrentThreadId());
			auto pid = g_NtUserQueryWindow(hWnd, (WINDOWINFOCLASS)0);
			if (ret == 1)
			{
				return  g_NtUserQueryWindow(hWnd, WindowInfo);
			}
			else if (ret > 1 || Protect::IsProtectPID(pid)) {
				if (WindowInfo == WindowProcess)
					return PsGetCurrentProcessId();

				if (WindowInfo == WindowThread || WindowInfo == WindowActiveWindow)
					return PsGetCurrentProcessId();
				return NULL;
			}
		}
		return  g_NtUserQueryWindow(hWnd, WindowInfo);
	}

	HWND MyNtUserGetForegroundWindow()
	{
		HWND hWnd = g_NtUserGetForegroundWindow();
		if (!hWnd) 	return hWnd;

		if (Protect::IsProtectProcess(PsGetCurrentProcess()))
		{
			return hWnd;
		}

		auto handle = g_NtUserQueryWindow(hWnd, WindowActiveWindow);
		if (handle)
		{
			int ret = Protect::IsProtectWND(hWnd, 0, handle, PsGetCurrentThreadId());
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
				return NULL;
			}
		}

		return hWnd;
	}

	DWORD_PTR MyNtUserCallOneParam(DWORD_PTR Param, DWORD Routine)
	{

		auto handle = g_NtUserQueryWindow((HWND)Param, WindowActiveWindow);
		if (handle)
		{
			if (Protect::IsProtectProcess(PsGetCurrentProcess()))
			{
				return g_NtUserCallOneParam(Param, Routine);
			}
			int ret = Protect::IsProtectWND((HWND)Param, 0, handle, PsGetCurrentThreadId());
			if (ret == 1)
			{
				return g_NtUserCallOneParam(Param, Routine);
			}
			else if (ret > 1) {
				return 0;
			}
			auto pid = g_NtUserQueryWindow((HWND)Param, WindowProcess);
			if (Protect::IsProtectPID(pid)) {
				return 0;
			}
		}
		return g_NtUserCallOneParam(Param, Routine);
	}

	HWND MyNtUserWindowFromPoint(LONG x, LONG y)
	{
		auto hWnd = g_NtUserWindowFromPoint(x, y);
		if (!hWnd) 	return hWnd;
		if (Protect::IsProtectProcess(PsGetCurrentProcess()))
		{
			return hWnd;
		}
		auto handle = g_NtUserQueryWindow(hWnd, WindowActiveWindow);
		if (handle)
		{
			int ret = Protect::IsProtectWND(hWnd, 0, handle, PsGetCurrentThreadId());
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
	NTSTATUS   MyNtUserBuildHwndList7(HANDLE hDesktop, HWND hwndParent, BOOLEAN bChildren, ULONG dwThreadId, ULONG lParam, PHANDLE pWnd, PULONG pBufSize) {

		if (Protect::IsProtectProcess(IoGetCurrentProcess()))
		{
			return  g_NtUserBuildHwndList(hDesktop, hwndParent, bChildren, dwThreadId, lParam, pWnd, pBufSize);
		}
		HANDLE currentThread = PsGetCurrentThreadId();
		if (bChildren)
		{
			HANDLE handle = g_NtUserQueryWindow(hwndParent, WindowActiveWindow);
			if (handle)
			{
				int ret = Protect::IsProtectWND(hwndParent, 0, handle, currentThread);
				if (ret == 1)
				{
					return   g_NtUserBuildHwndList(hDesktop, hwndParent, bChildren, dwThreadId, lParam, pWnd, pBufSize);
				}
				else if (ret > 1) {
					return STATUS_UNSUCCESSFUL;
				}
			}
		}
		auto status = g_NtUserBuildHwndList(hDesktop, hwndParent, bChildren, dwThreadId, lParam, pWnd, pBufSize);

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
				HANDLE handle = g_NtUserQueryWindow(pWnd[i], WindowActiveWindow);
				if (!handle)
				{
					i++;
					continue;
				}
				int ret = Protect::IsProtectWND((HWND)pWnd[i], 0, handle, currentThread);
				HANDLE pid = g_NtUserQueryWindow(pWnd[i], WindowProcess);
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

	BOOLEAN MyNtUserSetWindowDisplayAffinity(HWND hWnd, LONG dwAffinity)
	{
		return g_NtUserSetWindowDisplayAffinity(hWnd, dwAffinity);
	}

	BOOLEAN MyNtUserGetWindowDisplayAffinity(HWND hWnd, PLONG dwAffinity)
	{

		if (Protect::IsProtectProcess(PsGetCurrentProcess()))
		{
			return  g_NtUserGetWindowDisplayAffinity(hWnd, dwAffinity);
		}
		auto handle = g_NtUserQueryWindow(hWnd, WindowActiveWindow);
		if (handle)
		{
			int ret = Protect::IsProtectWND(hWnd, 0, handle, PsGetCurrentThreadId());
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

		g_NtUserValidateHandleSecure = (FNtUserValidateHandleSecure)GetFunctionAddrInSSDT(0x1334);
		Log("g_NtUserValidateHandleSecure %p \r\n", g_NtUserValidateHandleSecure);
		g_NtUserCallHwnd = (FNtUserCallHwnd)GetFunctionAddrInSSDT(0x110c);
		Log("g_NtUserCallHwnd %p \r\n", g_NtUserCallHwnd);
		g_NtUserCallHwndParam = (FNtUserCallHwndParam)GetFunctionAddrInSSDT(0x109e);
		Log("g_NtUserCallHwndParam %p \r\n", g_NtUserCallHwndParam);
		g_NtUserGetClassName = (FNtUserGetClassName)GetFunctionAddrInSSDT(0x107b);
		Log("g_NtUserGetClassName %p \r\n", g_NtUserGetClassName);
		g_NtUserPostMessage = (FNtUserPostMessage)GetFunctionAddrInSSDT(0x100f);
		Log("g_NtUserPostMessage %p \r\n", g_NtUserPostMessage);
		g_NtUserMessageCall = (FNtUserMessageCall)GetFunctionAddrInSSDT(0x1007);
		Log("g_NtUserMessageCall %p \r\n", g_NtUserMessageCall);
		g_NtUserInternalGetWindowText = (FNtUserInternalGetWindowText)GetFunctionAddrInSSDT(0x1063);
		Log("g_NtUserInternalGetWindowText %p \r\n", g_NtUserInternalGetWindowText);
		//g_NtUserSetParent = (FNtUserSetParent)GetFunctionAddrInSSDT(0x1077);
		//Log("g_NtUserSetParent %p \r\n", g_NtUserSetParent);
		g_NtUserFindWindowEx = (FNtUserFindWindowEx)GetFunctionAddrInSSDT(0x106e);
		Log("g_NtUserFindWindowEx %p \r\n", g_NtUserFindWindowEx);
		g_NtUserQueryWindow = (FNtUserQueryWindow)GetFunctionAddrInSSDT(0x1010);
		Log("g_NtUserQueryWindow %p \r\n", g_NtUserQueryWindow);
		g_NtUserGetForegroundWindow = (FNtUserGetForegroundWindow)GetFunctionAddrInSSDT(0x103c);
		Log("g_NtUserGetForegroundWindow %p \r\n", g_NtUserGetForegroundWindow); 
		g_NtUserBuildHwndList = (FNtUserBuildHwndList7)GetFunctionAddrInSSDT(0x101c);
		Log("g_NtUserBuildHwndList %p \r\n", g_NtUserBuildHwndList); 
		 
		g_NtUserGetWindowDC = (FNtUserGetWindowDC)GetFunctionAddrInSSDT(4196);
		Log("g_NtUserGetWindowDC %p \r\n", g_NtUserGetWindowDC);

		g_NtUserGetDC = (FNtUserGetDC)GetFunctionAddrInSSDT(4106);
		Log("g_NtUserGetDC %p \r\n", g_NtUserGetDC);

		IsHookStarted = TRUE; 
		//return  IsHookStarted ? STATUS_SUCCESS : STATUS_UNSUCCESSFUL;
		return STATUS_SUCCESS;
	}

	NTSTATUS AntiSnapWindow(ULONG32 hwnd)
	{
		KAPC_STATE apcState = { 0 };
		PEPROCESS pEprocess = 0;
		HWND tmpHwnd = (HWND)hwnd;
		NTSTATUS status;
		BOOLEAN result = FALSE;
		auto pid = g_NtUserQueryWindow(tmpHwnd, WindowProcess);
		if (!pid)
		{
			return STATUS_UNSUCCESSFUL;
		}
		status = PsLookupProcessByProcessId(pid, &pEprocess);
		if (!NT_SUCCESS(status))
		{
			return STATUS_UNSUCCESSFUL;
		}
		KeStackAttachProcess(pEprocess, &apcState);
		g_NtUserSetParent(tmpHwnd, 0);
		if (InitOsVersion().dwBuildNumber < 1570)
		{
			result = g_NtUserSetWindowDisplayAffinity(tmpHwnd, 0x1);
		}
		else {
			result = g_NtUserSetWindowDisplayAffinity(tmpHwnd, 0x11);
		}
		KeUnstackDetachProcess(&apcState);
		ObDereferenceObject(pEprocess);

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
		KeDelayExecutionThread(KernelMode, FALSE, &integer);
		return isok;
	}
	HANDLE GetWindowThread(HWND hwnd) {
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
		POBJECT_NAME_INFORMATION ObjectName = (POBJECT_NAME_INFORMATION)ExAllocatePool(NonPagedPool, 0x300);
		PEPROCESS pEprocess;
		PVOID pFileHandle;
		NTSTATUS status = PsLookupProcessByProcessId(UlongToHandle(pid), &pEprocess);
		if (!NT_SUCCESS(PsReferenceProcessFilePointer(pEprocess, &pFileHandle)))
		{
			return NULL;
		}
		if (!NT_SUCCESS(IoQueryFileDosDeviceName((PFILE_OBJECT)pFileHandle, &ObjectName)))
		{
			return NULL;
		}
		ObDereferenceObject(pFileHandle);
		ObDereferenceObject(pEprocess);//释放引用次数 
		return ObjectName;
	}

}