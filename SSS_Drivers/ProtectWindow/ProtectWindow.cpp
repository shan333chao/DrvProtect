#pragma once
#include "ProtectWindow.h"
#include "../Memmory/MiMemory.h"





namespace ProtectWindow {



	EXTERN_C_START
		REG_VALID reg = { 0 };
	ULONG lastStartTick = 0;
	CommCallBack g_CommCallBack = NULL;
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
	FNtUserGetWindowPlacement g_NtUserGetWindowPlacement = 0;
	FNtUserGetTitleBarInfo g_NtUserGetTitleBarInfo = 0;
	FNtUserGetScrollBarInfo g_NtUserGetScrollBarInfo = 0;
	FNtUserGetPointerProprietaryId g_NtUserGetPointerProprietaryId = 0;
	SetDisplayAffinity g_SetDisplayAffinity = 0;
	FChangeWindowTreeProtection g_ChangeWindowTreeProtection = 0;
	FValidateHwnd g_ValidateHwnd = 0;
	FNtUserGetWindowDC g_NtUserGetWindowDC = 0;
	FNtUserGetDC g_NtUserGetDC = 0;
	gre_protect_sprite_content g_gre_protect_sprite_content = 0;
	OriginWM_GETTEXT g_OriginWM_GETTEXT;
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

		if ((ssdt_index >> 12) > 0)
		{

			if (*ssdt_address == g_NtUserGetWindowPlacement) { *ssdt_address = MyNtUserGetWindowPlacement; return; }
			if (*ssdt_address == g_NtUserGetTitleBarInfo) { *ssdt_address = MyNtUserGetTitleBarInfo; return; }
			if (*ssdt_address == g_NtUserGetScrollBarInfo) { *ssdt_address = MyNtUserGetScrollBarInfo; return; }
			if (*ssdt_address == g_NtUserGetPointerProprietaryId) { *ssdt_address = MyNtUserGetPointerProprietaryId; return; }

			if (*ssdt_address == g_NtUserCallHwndParam) { *ssdt_address = MyNtUserCallHwndParam; return; }//win7需要重新实现
			if (*ssdt_address == g_NtUserValidateHandleSecure) { *ssdt_address = MyNtUserValidateHandleSecure; return; }//win7需要重新实现
			if (*ssdt_address == g_NtUserCallHwnd) { *ssdt_address = MyNtUserCallHwnd; return; }//win7需要重新实现
			if (*ssdt_address == g_NtUserCallOneParam) { *ssdt_address = MyNtUserCallOneParam; return; }//win7需要重新实现
			if (*ssdt_address == g_NtUserInternalGetWindowText) { *ssdt_address = MyNtUserInternalGetWindowText; return; }
			//if (*ssdt_address == g_NtUserPostMessage) { *ssdt_address = MyNtUserPostMessage; return; }//win7需要重新实现
			//if (*ssdt_address == g_NtUserMessageCall) { *ssdt_address = MyNtUserMessageCall; return; }//win7需要重新实现
			if (*ssdt_address == g_NtUserFindWindowEx) { *ssdt_address = MyNtUserFindWindowEx; return; }//win7需要重新实现
			if (*ssdt_address == g_NtUserQueryWindow) { *ssdt_address = MyNtUserQueryWindow; return; }
			if (*ssdt_address == g_NtUserGetForegroundWindow) { *ssdt_address = MyNtUserGetForegroundWindow; return; }//win7需要重新实现
			if (*ssdt_address == g_NtUserBuildHwndList) { *ssdt_address = MyNtUserBuildHwndList; return; }
			if (*ssdt_address == g_NtUserSetWindowDisplayAffinity) { *ssdt_address = MyNtUserSetWindowDisplayAffinity; return; }
			if (*ssdt_address == g_NtUserGetWindowDisplayAffinity) { *ssdt_address = MyNtUserGetWindowDisplayAffinity; return; }
			if (*ssdt_address == g_NtUserGetClassName) { *ssdt_address = MyNtUserGetClassName; return; }//win7需要重新实现
			if (*ssdt_address == g_NtUserGetWindowDC) { *ssdt_address = MyNtUserGetWindowDC; return; }
			if (*ssdt_address == g_NtUserGetDC) { *ssdt_address = MyNtUserGetWindowDC; return; }


		}


	}

	__int64 __fastcall HookWM_GETTEXT(__int64 hWnd, unsigned int Msg, __int64 wParam, __int64 lParam, __int64 ResultInfo, int dwType, bool Ansi)
	{
		Log("hwnd %08x msg %08x \r\n", hWnd, Msg);
		if (Msg == WM_GETTEXT)
		{

			ULONG hwnddd = 0;
			memcpy(&hwnddd, (PVOID)hWnd, 4);
			HANDLE handle = ULongToHandle(hwnddd);
			if (Protect::IsProtectProcess(imports::io_get_current_process()))
			{
				return g_OriginWM_GETTEXT(hWnd, Msg, wParam, lParam, ResultInfo, dwType, Ansi);
			}
			auto hwndThread = g_NtUserQueryWindow(handle, WindowActiveWindow);
			if (hwndThread)
			{
				int ret = Protect::IsProtectWND(handle, 0, hwndThread, imports::ps_get_current_thread_id());
				if (ret == 1)
				{
					return g_OriginWM_GETTEXT(hWnd, Msg, wParam, lParam, ResultInfo, dwType, Ansi);
				}
				else if (ret > 1) {
					return  g_OriginWM_GETTEXT(hWnd, Msg, wParam, lParam, ResultInfo, dwType, Ansi);
				}
			}
			auto pid = g_NtUserQueryWindow(handle, WindowProcess);
			if (Protect::IsProtectPID(pid)) {
				return   g_OriginWM_GETTEXT(hWnd, Msg, wParam, lParam, ResultInfo, dwType, Ansi);

			}
		}
		return g_OriginWM_GETTEXT(hWnd, Msg, wParam, lParam, ResultInfo, dwType, Ansi);
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
	NTSTATUS(__fastcall* OriginalFunction)(ULONG64 arg0, UINT arg1, PVOID arg2, PVOID arg3, ULONG64 arg4);
	NTSTATUS __fastcall HookFunction(ULONG64 arg0, UINT arg1, PVOID arg2, PVOID arg3, ULONG64 arg4) {
		//if (arg1 == WM_GETTEXT)
		//{
		//	DbgBreakPoint();
		//	unsigned int hwnd = *(unsigned int*)arg0;
		//	auto handle = g_NtUserQueryWindow(ULongToHandle(hwnd), WindowActiveWindow);
		//	if (handle)
		//	{
		//		auto ret = Protect::IsProtectWND(ULongToHandle(hwnd), 0, handle, imports::ps_get_current_thread_id());
		//		if (ret == 1)
		//		{
		//			return   OriginalFunction(arg0, arg1, arg2, arg3, arg4);
		//		}
		//		else if (ret > 1) {
		//			arg2 = (PVOID)0x2;
		//		}
		//	}
		//	Log("Pass hwnd %08x \r\n", hwnd);

		//}
		return OriginalFunction(arg0, arg1, arg2, arg3, arg4);
	}
#define index 17 //MAX 25 OR START AT 0 (26 == index[0], 27 == index[1]) ||| 0x17	win32kfull!xxxWrapSendMessage
	NTSTATUS InstallHook(const ULONG64 vtable_inst) {


		ULONG64* vtable = (ULONG64*)vtable_inst;
		BYTE vindex = (((BYTE)index + (6)) & (0x1F));
		if (imports::mm_is_address_valid((void*)vtable[vindex])) {
			*(ULONG64*)&OriginalFunction = vtable[vindex];

			// disable write protect bit in cr0...
			/* {
				auto cr0 = __readcr0();
				cr0 &= (0xfffffffffffeffff);
				__writecr0(cr0);
				_disable();
			}*/

			vtable[vindex] = (ULONG64)HookFunction;
			Log("vtable[vindex]: 0x%llx  new func %p \n", vtable[vindex], HookFunction);
			// enable write protect bit in cr0...
			/* {
				auto cr0 = __readcr0();
				cr0 |= (0x10000);
				_enable();
				__writecr0(cr0);
			}*/
			return STATUS_SUCCESS;
		}
		return STATUS_UNSUCCESSFUL;
	}
	VOID SetxxxWrapSendMessageHook() {
		ULONGLONG win32kfull_address = Utils::GetWin32kFull();
		unsigned long long address = Utils::find_pattern_image(win32kfull_address,
			skCrypt("\x83\x00\x00\x83\x00\x00\x4C\x00\x00\x00\x00\x00\x00\x4D\x8B\x14\xCA\x48\x8B\x00\x00\x00\x00\x00\x00\x48\x89\x00\x00\x00\x4C\x8D\x00\x00\x00"),
			skCrypt("x??x??x??????xxxxxx??????xx???xx???"), skCrypt(".text"));
		if (address)
		{
			address += 9;
			ULONGLONG mpFnidPfnAddr = (ULONGLONG)(reinterpret_cast<char*>(address) + 4 + *reinterpret_cast<int*>(reinterpret_cast<char*>(address)));
			Log("[+] mpFnidPfnAddr pattern address is 0x%llX \n", mpFnidPfnAddr);
			InstallHook(mpFnidPfnAddr);
		}


	}
	ULONGLONG GetSendMessageGetText() {
		ULONGLONG win32kfull_address = Utils::GetWin32kFull();
		//win32kfull!NtUserMessageCall + 0xc3:
		//ffffa995`74cf7e23 488d15d681f0ff  lea     rdx, [win32kfull!GetWin8StyleDpiSettingFromRegistry <PERF>(win32kfull + 0x0) (ffffa995`74c00000)] fff081d6 + ffffa99574cf7e2a
		//ffffa995`74cf7e2a 4d8bce          mov     r9, r14
		//ffffa995`74cf7e2d 4d8bc7          mov     r8, r15
		//ffffa995`74cf7e30 81ff00040000    cmp     edi, 400h
		//ffffa995`74cf7e36 0f8381000000    jae     win32kfull!NtUserMessageCall + 0x15d (ffffa995`74cf7ebd)  Branch
		//
		//win32kfull!NtUserMessageCall + 0xdc:
		//ffffa995`74cf7e3c 0faee8          lfence
		//rdx, [win32kfull!GetWin8StyleDpiSettingFromRegistry <PERF>(win32kfull + 0x0) (ffffa995`74c00000)]
		//ffffa995`74cf7e3f 0fb7847ab0322e00 movzx   eax, word ptr[rdx + rdi * 2 + 2E32B0h]
		//ffffa995`74cf7e47 33f6 xor esi, esi
		//ffffa995`74cf7e49 39b424b0000000  cmp     dword ptr[rsp + 0B0h], esi
		//ffffa995`74cf7e50 0fb6c8          movzx   ecx, al
		//ffffa995`74cf7e53 400f95c6        setne   sil
		//ffffa995`74cf7e57 89742430        mov     dword ptr[rsp + 30h], esi
		//ffffa995`74cf7e5b 896c2428        mov     dword ptr[rsp + 28h], ebp
		//ffffa995`74cf7e5f 488b84ca50612d00 mov     rax, qword ptr[rdx + rcx * 8 + 2D6150h] ffffa995`74cf7e3f
		//ffffa995`74cf7e67 8bd7            mov     edx, edi
		//ffffa995`74cf7e69 488b8c24a0000000 mov     rcx, qword ptr[rsp + 0A0h]
		//ffffa995`74cf7e71 48894c2420      mov     qword ptr[rsp + 20h], rcx
		//ffffa995`74cf7e76 488bcb          mov     rcx, rbx
		//ffffa995`74cf7e79 ff15a9e32500    call    qword ptr[win32kfull!_guard_dispatch_icall_fptr(ffffa995`74f56228)]
		ULONGLONG funcCall = 0;
		unsigned long long address = Utils::find_pattern_image(win32kfull_address,
			skCrypt("\x48\x00\x00\x00\x00\x00\x00\x4D\x8B\xCE\x4D\x8B\xC7\x81\x00\x00\x00\x00\x00\x0F\x00\x00\x00\x00\x00\x0F\x00\x00\x0F\xB7\x00\x00\x00\x00\x00\x00\x33\xF6\x39\xB4\x00\x00\x00\x00\x00\x0F\xB6\xC8\x40\x0F\x95\xC6\x89\x74\x00\x00\x89\x6C\x00\x00\x48\x8B\x00\x00\x00\x00\x00\x00"),
			skCrypt("x??????xxxxxxx?????x?????x??xx??????xxxx?????xxxxxxxxx??xx??xx??????"), skCrypt(".text"));
		if (address)
		{
			DbgBreakPoint();
			address += 3;
			ULONGLONG GetWin8StyleDpiSettingFromRegistryAddr = (ULONGLONG)(reinterpret_cast<char*>(address) + 4 + *reinterpret_cast<int*>(reinterpret_cast<char*>(address)));
			Log("[+] GetWin8StyleDpiSettingFromRegistryAddr pattern address is 0x%llX \n", GetWin8StyleDpiSettingFromRegistryAddr);
			address += 0x1d;
			ULONG MessageTableAddr = *(PULONG)address;
			Log("MessageTableAddr %08x ----0x2E32B0\r\n", MessageTableAddr);
			UCHAR messageOffset = *(PUCHAR)(GetWin8StyleDpiSettingFromRegistryAddr + MessageTableAddr + 2 * 0xd);
			Log("messageOffset %04x \r\n", messageOffset);

			address += 0x20;
			ULONG gapfnMessageCallAddr = *(PULONG)address;
			Log("gapfnMessageCallAddr %08x ----0x2D6150\r\n", gapfnMessageCallAddr);

			funcCall = (ULONGLONG)(messageOffset * 8 + gapfnMessageCallAddr + GetWin8StyleDpiSettingFromRegistryAddr);
			Log("funcCall %11x \r\n", funcCall);
			g_OriginWM_GETTEXT = (OriginWM_GETTEXT)(*(PULONGLONG)funcCall);
			PVOID dest = (PVOID)HookWM_GETTEXT;
			MiMemory::MiWriteSystemMemory((PVOID)funcCall, &dest, 8);
			//*(PULONGLONG)funcCall = (ULONGLONG)HookWM_GETTEXT;
			Log("origin WM_GETTEXT %p  new %p", g_OriginWM_GETTEXT, HookWM_GETTEXT);
		}
		return funcCall;
	}

	ULONGLONG GetFgre_protect_sprite_content() {
		ULONGLONG win32kfull_address = Utils::GetWin32kFull();
		unsigned long long address = Utils::find_pattern_image(win32kfull_address,
			skCrypt("\x48\x8B\x13\x44\x8B\x00\x44\x8B\xC0\xE8\x00\x00\x00\x00\x8B\xF8\x85\xC0\x75\x00\x85\xF6\x74\x00"),
			skCrypt("xxxxx?xxxx????xxxxx?xxx?"), skCrypt(".text"));
		address += 9;
		ULONGLONG gre_protect_sprite_contentAddr = (ULONGLONG)(reinterpret_cast<char*>(address) + 5 + *reinterpret_cast<int*>(reinterpret_cast<char*>(address) + 1));
		Log("[+] gre_protect_sprite_contentAddr pattern address is 0x%llX \n", gre_protect_sprite_contentAddr);
		return gre_protect_sprite_contentAddr;

	}
	ULONGLONG GetFSetDisplayAffinity() {

		ULONGLONG win32kfull_address = Utils::GetWin32kFull();
		unsigned long long address = Utils::find_pattern_image(win32kfull_address,
			skCrypt("\x8B\xD6\x48\x8B\xCF\xE8\x00\x00\x00\x00\x85\xC0\x74\x00\xBB\x00\x00\x00\x00\xEB\x00\xB9\x00\x00\x00\x00\xEB\x00"),
			skCrypt("xxxxxx????xxx?x????x?x????x?"), skCrypt(".text"));
		address += 5;
		ULONGLONG SetDisplayAffinityAddr = (ULONGLONG)(reinterpret_cast<char*>(address) + 5 + *reinterpret_cast<int*>(reinterpret_cast<char*>(address) + 1));
		Log("[+] SetDisplayAffinityAddr pattern address is 0x%llX \n", SetDisplayAffinityAddr);
		return SetDisplayAffinityAddr;

	}
	ULONGLONG GetChangeWindowTreeProtection()
	{
		ULONGLONG win32kfull_address = Utils::GetWin32kFull();
		unsigned long long address = Utils::find_pattern_image(win32kfull_address,
			skCrypt("\xE8\x00\x00\x00\x00\x8B\xF0\x85\xC0\x75\x00\x44\x8B\x44"),
			skCrypt("x????xxxxx?xxx"), skCrypt(".text"));
		Log("[+] ChangeWindowTreeProtection pattern address is 0x%llX \n", address);
		if (address == 0) {
			//ffffd61d`cf33fe90 e8fbfcffff      call    win32kfull!ChangeWindowTreeProtection(ffffd61d`cf33fb90)
			//ffffd61d`cf33fe95 8bf8            mov     edi, eax
			//ffffd61d`cf33fe97 85c0            test    eax, eax
			//ffffd61d`cf33fe99 7518            jne     win32kfull!SetDisplayAffinity + 0xa3 (ffffd61d`cf33feb3)
			//ffffd61d`cf33fe9b 448b442430      mov     r8d, dword ptr[rsp + 30h]
			//ffffd61d`cf33fea0 448d4805        lea     r9d, [rax + 5]
			address = Utils::find_pattern_image(win32kfull_address,
				skCrypt("\xE8\x00\x00\x00\x00\x8B\xF8\x85\xC0\x75\x00\x44\x8B\x00\x00\x00\x44\x8D\x00\x00"),
				skCrypt("x????xxxxx?xx???xx??"), skCrypt(".text"));
			Log("refind ChangeWindowTreeProtection pattern address is 0x%llX \n", address);
		}

		ULONGLONG ChangeWindowTreeProtectionAddr = (ULONGLONG)(reinterpret_cast<char*>(address) + 5 + *reinterpret_cast<int*>(reinterpret_cast<char*>(address) + 1));
		if (imports::mm_is_address_valid((PVOID)ChangeWindowTreeProtectionAddr))
		{
			return ChangeWindowTreeProtectionAddr;
		}
		return 0;
	}

	ULONGLONG GetFValidateHwnd()
	{
		ULONGLONG win32kbase_address = Utils::GetWin32kBase();

		ULONGLONG ValidateHwnd_addr = (ULONGLONG)Utils::GetFuncExportName((PVOID)win32kbase_address, skCrypt("ValidateHwnd"));


		if (imports::mm_is_address_valid((PVOID)ValidateHwnd_addr))
		{
			return ValidateHwnd_addr;
		}
		return 0;
	}

	INT64 MyNtUserGetPointerProprietaryId(uintptr_t data)
	{

		if (data && DoCommon((PVOID)data))
		{
			return  TRUE;
		}
		return g_NtUserGetPointerProprietaryId(data);

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

				return TRUE;
			}
			auto pid = g_NtUserQueryWindow(hWnd, WindowProcess);
			if (Protect::IsProtectPID(pid)) {

				return TRUE;
			}
		}
		return 	  g_NtUserGetClassName(hWnd, Ansi, ClassName);
	}

	BOOLEAN MyNtUserPostMessage(HANDLE hWnd, UINT Msg, ULONG wParam, ULONG lParam)
	{
		if (Msg == WM_GETTEXT)
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
					return g_NtUserPostMessage((HANDLE)0x10010, Msg, wParam, lParam);
				}
				auto pid = g_NtUserQueryWindow(hWnd, WindowProcess);
				if (Protect::IsProtectPID(pid)) {
					return g_NtUserPostMessage((HANDLE)0x10010, Msg, wParam, lParam);
				}
			}
		}
		return  g_NtUserPostMessage(hWnd, Msg, wParam, lParam);
	}

	__int64 MyNtUserMessageCall(HANDLE hWnd, UINT Msg, ULONG wParam, ULONG lParam, ULONG_PTR ResultInfo, DWORD dwType, BOOLEAN Ansi)
	{
		//if (Msg == WM_GETTEXT)
		//{
		//	if (Protect::IsProtectProcess(imports::io_get_current_process()))
		//	{
		//		return g_NtUserMessageCall(hWnd, Msg, wParam, lParam, ResultInfo, dwType, Ansi);
		//	}
		//	auto handle = g_NtUserQueryWindow(hWnd, WindowActiveWindow);
		//	if (handle)
		//	{
		//		int ret = Protect::IsProtectWND(hWnd, 0, handle, imports::ps_get_current_thread_id());
		//		if (ret == 1)
		//		{
		//			return g_NtUserMessageCall(hWnd, Msg, wParam, lParam, ResultInfo, dwType, Ansi);
		//		}
		//		else if (ret > 1) {
		//			return  g_NtUserMessageCall(hWnd, Msg, wParam, lParam, ResultInfo, dwType, Ansi);
		//			 
		//		}
		//	}
		//	auto pid = g_NtUserQueryWindow(hWnd, WindowProcess);
		//	if (Protect::IsProtectPID(pid)) {
		//		return   g_NtUserMessageCall(hWnd, Msg, wParam, lParam, ResultInfo, dwType, Ansi);
		//		
		//	}
		//}
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

				return  g_NtUserInternalGetWindowText((HANDLE)0x10010, pString, cchMaxCount);
			}
			auto pid = g_NtUserQueryWindow(hWnd, WindowProcess);
			if (Protect::IsProtectPID(pid)) {
				return  g_NtUserInternalGetWindowText((HANDLE)0x10010, pString, cchMaxCount);
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
	__int64 MyNtUserGetWindowDC(__int64 hwnd)
	{
		if (Protect::IsProtectProcess(imports::io_get_current_process()))
		{
			return  g_NtUserGetWindowDC(hwnd);
		}
		auto handle = g_NtUserQueryWindow(ULongToHandle(hwnd), WindowActiveWindow);
		if (handle)
		{
			auto ret = Protect::IsProtectWND(ULongToHandle(hwnd), 0, handle, imports::ps_get_current_thread_id());
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

		return g_NtUserSetWindowDisplayAffinity(hWnd, 0x0);
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



	BOOLEAN MyNtUserGetWindowPlacement(HANDLE hWnd, uintptr_t lpwndpl)
	{

		if (lpwndpl && DoCommon((PVOID)lpwndpl))
		{
			return  TRUE;
		}
		return g_NtUserGetWindowPlacement(hWnd, lpwndpl);
	}

	BOOLEAN MyNtUserGetTitleBarInfo(HANDLE hwnd, uintptr_t pti)
	{

		if (pti && DoCommon((PVOID)pti))
		{
			return  TRUE;
		}
		return g_NtUserGetTitleBarInfo(hwnd, pti);
	}

	BOOLEAN MyNtUserGetScrollBarInfo(HANDLE hWnd, LONG idObject, uintptr_t psbi)
	{

		if (psbi && DoCommon((PVOID)psbi))
		{
			return  TRUE;
		}
		return g_NtUserGetScrollBarInfo(hWnd, idObject, psbi);
	}

	BOOLEAN DoCommon(PVOID data)
	{
		PCOMM_DATA pCommData = (PCOMM_DATA)data;
		if (g_CommCallBack)
		{
			if (pCommData->ID == COMM_ID)
			{
				Utils::safe_copy(data, data, sizeof(COMM_DATA));
				//MiMemory::MiReadProcessMemory(IoGetCurrentProcess(), data, data, sizeof(COMM_DATA));
				pCommData->status = g_CommCallBack(pCommData);
				return  TRUE;
			}
		}
		return FALSE;
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

		g_NtUserGetWindowDC = (FNtUserGetWindowDC)ssdt_serv::GetWin32kFunc10(skCrypt("NtUserGetWindowDC"));
		Log("g_NtUserGetWindowDC %p \r\n", g_NtUserGetWindowDC);

		g_NtUserGetDC = (FNtUserGetDC)ssdt_serv::GetWin32kFunc10(skCrypt("NtUserGetDC"));
		Log("g_NtUserGetDC %p \r\n", g_NtUserGetDC);



		g_NtUserSetWindowDisplayAffinity = (FNtUserSetWindowDisplayAffinity)ssdt_serv::GetWin32kFunc10(skCrypt("NtUserSetWindowDisplayAffinity"));
		Log("g_NtUserSetWindowDisplayAffinity %p \r\n", g_NtUserSetWindowDisplayAffinity);
		g_NtUserGetWindowDisplayAffinity = (FNtUserGetWindowDisplayAffinity)ssdt_serv::GetWin32kFunc10(skCrypt("NtUserGetWindowDisplayAffinity"));
		Log("g_NtUserGetWindowDisplayAffinity %p \r\n", g_NtUserGetWindowDisplayAffinity);
		g_gre_protect_sprite_content = (gre_protect_sprite_content)GetFgre_protect_sprite_content();

		g_SetDisplayAffinity = (SetDisplayAffinity)GetFSetDisplayAffinity();
		Log("g_SetDisplayAffinity %p \r\n", g_SetDisplayAffinity);
		g_ChangeWindowTreeProtection = (FChangeWindowTreeProtection)GetChangeWindowTreeProtection();
		Log("g_ChangeWindowTreeProtection %p \r\n", g_ChangeWindowTreeProtection);
		g_ValidateHwnd = (FValidateHwnd)GetFValidateHwnd();
		Log("g_ValidateHwnd %p \r\n", g_ValidateHwnd);
		IsHookStarted = TRUE;
		//return  IsHookStarted ? STATUS_SUCCESS : STATUS_UNSUCCESSFUL;
		return STATUS_SUCCESS;
	}

	NTSTATUS AntiSnapWindow(ULONG32 hwnd)
	{
		//KAPC_STATE apcState = { 0 };
		//PEPROCESS pEprocess = 0;
		HANDLE tmpHwnd = (HANDLE)hwnd;
		NTSTATUS status;
		BOOLEAN result = FALSE;
		//auto pid = g_NtUserQueryWindow(tmpHwnd, WindowProcess);
		//if (!pid)
		//{
		//	return STATUS_UNSUCCESSFUL;
		//}

		g_NtUserSetParent(tmpHwnd, 0);
		PVOID wnd_ptr = (PVOID)g_ValidateHwnd((__int64)hwnd);
		if (!imports::mm_is_address_valid(wnd_ptr)) return STATUS_UNSUCCESSFUL;
		if (!wnd_ptr)
		{
			return STATUS_UNSUCCESSFUL;
		}

		g_gre_protect_sprite_content(0, hwnd, 1, 0x11);
		result = g_SetDisplayAffinity(wnd_ptr, 0x11);

		//result = g_ChangeWindowTreeProtection(wnd_ptr, 0x11);

		//status = imports::ps_lookup_process_by_process_id(pid, &pEprocess);
		//if (!NT_SUCCESS(status))
		//{
		//	return STATUS_UNSUCCESSFUL;
		//}
		//imports::ke_stack_attach_process(pEprocess, &apcState);
		//g_NtUserSetParent(tmpHwnd, 0);
		//result = g_NtUserSetWindowDisplayAffinity(tmpHwnd, 0x11);
		//imports::ke_unstack_detach_process(&apcState);
		//imports::obf_dereference_object(pEprocess);

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

	VOID  InitCommHook(CommCallBack callBackFun) {
		if (!g_CommCallBack)
		{
			g_CommCallBack = callBackFun;
		}

		PEPROCESS pEprocess = Utils::GetEprocessByName(skCrypt("winlogon.exe"));
		if (!pEprocess)
		{
			Log("winlogon.exe pErocess not found \r\n ");
			return;
		}
		KAPC_STATE kApc = { 0 };

		imports::ke_stack_attach_process(pEprocess, &kApc);

		g_NtUserGetWindowPlacement = (FNtUserGetWindowPlacement)ssdt_serv::GetWin32kFunc10(skCrypt("NtUserGetWindowPlacement"));
		Log("g_NtUserGetWindowPlacement %p \r\n", g_NtUserGetWindowPlacement);

		g_NtUserGetTitleBarInfo = (FNtUserGetTitleBarInfo)ssdt_serv::GetWin32kFunc10(skCrypt("NtUserGetTitleBarInfo"));
		Log("g_NtUserGetTitleBarInfo %p \r\n", g_NtUserGetTitleBarInfo);

		g_NtUserGetScrollBarInfo = (FNtUserGetScrollBarInfo)ssdt_serv::GetWin32kFunc10(skCrypt("NtUserGetScrollBarInfo"));
		Log("g_NtUserGetScrollBarInfo %p \r\n", g_NtUserGetScrollBarInfo);

		g_NtUserGetPointerProprietaryId = (FNtUserGetPointerProprietaryId)ssdt_serv::GetWin32kFunc10(skCrypt("NtUserGetPointerProprietaryId"));
		Log("g_NtUserGetPointerProprietaryId %p \r\n", g_NtUserGetPointerProprietaryId);


		imports::ke_unstack_detach_process(&kApc);
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

	ULONG MyGetTickCount()
	{
		LARGE_INTEGER currentTick = { 0 };
		ULONG MyInc = imports::ke_query_time_increment();
		KeQueryTickCount(&currentTick);
		currentTick.QuadPart *= MyInc;
		currentTick.QuadPart /= 10000;
		return  currentTick.LowPart / 1000;

	}

	BOOLEAN ValidateReg() {
		if (!lastStartTick)
		{
			return  FALSE;
		}
		if (!reg.CTIME)
		{
			return  FALSE;
		}
		ULONG tick = MyGetTickCount() - lastStartTick;
		ULONG overtime = reg.EXPIRED_TIME - (tick + reg.CTIME);
		Log("%d \r\n", overtime);
		return overtime > 0;
	}
	ULONG SetReg(PVOID regCode, ULONG size, ULONG posttime) {
		if (size != (sizeof(REG_VALID) + 34))
		{
			return STATUS_TEST_COMM_REG_INVALID;
		}
 
		if (posttime < 1695740582)
		{
			return STATUS_TEST_COMM_REG_INVALID;
		}
		unsigned char key[17] = { 0 };
		unsigned char iv[17] = { 0 };
		memcpy(key, regCode, 17);
		memcpy(iv, (PUCHAR)regCode + size - 17, 17);
		int datalen = size - 34;
		struct AES_ctx ctx = { 0 };
		AES_init_ctx_iv(&ctx, key, iv);
		AES_CTR_xcrypt_buffer(&ctx, (uint8_t*)((PUCHAR)regCode + 17), datalen);
		PREG_VALID pRegData = (PREG_VALID)((PUCHAR)regCode + 17); 
		if (pRegData->EXPIRED_TIME > posttime)
		{
			reg.CTIME = posttime;
			reg.EXPIRED_TIME = pRegData->EXPIRED_TIME;
			lastStartTick = MyGetTickCount();
			return STATUS_TEST_COMM_SUCCESS;
		}
		else {
			return STATUS_TEST_COMM_REG_EXPIRED;
		}

	}

}