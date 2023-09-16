#ifndef  _PROTECT_WINDOW7_H
#define _PROTECT_WINDOW7_H


#pragma once
#include "../infinity_hook_pro/imports.hpp"
#include "../infinity_hook_pro/hook.hpp"
#include "Protect.h"
#include "../SSDT/ssdt.h"




namespace ProtectWindow7 {
	EXTERN_C_START
		typedef NTSTATUS(*FNtCreateFile7)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, PIO_STATUS_BLOCK, PLARGE_INTEGER, ULONG, ULONG, ULONG, ULONG, PVOID, ULONG);
	typedef HANDLE(*FNtUserFindWindowEx7)(PVOID, PVOID, PUNICODE_STRING, PUNICODE_STRING, ULONG);
	typedef NTSTATUS(NTAPI* FNtUserBuildHwndList7)(HANDLE hDesktop, HANDLE hwndParent, BOOLEAN bChildren, ULONG dwThreadId, ULONG lParam, PHANDLE pWnd, PULONG pBufSize);
	typedef	HANDLE(NTAPI* FNtUserQueryWindow7)(HANDLE, WINDOWINFOCLASS);
	typedef HANDLE(*FNtUserGetForegroundWindow7)();
	typedef NTSTATUS(*FNtQueryInformationProcess7)(HANDLE ProcessHandle, PROCESSINFOCLASS ProcessInformationClass, PVOID ProcessInformation, ULONG ProcessInformationLength, PULONG ReturnLength);

	typedef	INT(*FNtUserGetClassName7)(HANDLE hWnd, BOOLEAN Ansi, PUNICODE_STRING ClassName);

	typedef HANDLE(*FNtUserSetParent7)(HANDLE hWndChild, HANDLE hWndNewParent);
	typedef BOOLEAN(*FNtUserSetLayeredWindowAttributes7)(HANDLE  hwnd, ULONG32 COLORREF, BYTE  bAlpha, ULONG32 dwFlags);
	typedef HANDLE(*FNtUserWindowFromPoint7)(LONG x, LONG y);
	typedef BOOLEAN(*FNtUserSetWindowDisplayAffinity7)(HANDLE hWnd, LONG dwAffinity);
	typedef BOOLEAN(*FNtUserGetWindowDisplayAffinity7)(HANDLE hWnd, PLONG dwAffinity);
	typedef NTSTATUS(*FNtOpenProcess7)(PHANDLE ProcessHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, PCLIENT_ID ClientId);
	typedef NTSTATUS(*FNtOpenThread7)(PHANDLE ProcessHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, PCLIENT_ID ClientId);
	typedef ULONG(*FNtUserInternalGetWindowText7)(HANDLE   hWnd, LPWSTR pString, int    cchMaxCount);
	typedef BOOLEAN(*FNtUserPostMessage7)(HANDLE hWnd, UINT Msg, ULONG wParam, __int64 lParam);
	typedef BOOLEAN(*FNtUserMessageCall7)(HANDLE hWnd, UINT Msg, ULONG wParam, ULONG lParam, ULONG_PTR ResultInfo, DWORD dwType, BOOLEAN Ansi);
	typedef DWORD_PTR(*FNtUserCallOneParam7)(DWORD_PTR Param, DWORD Routine);
	typedef BOOLEAN(*FNtUserValidateHandleSecure7)(HANDLE hHdl);
	typedef ULONG_PTR(*FNtUserCallHwndParam7)(HANDLE hwnd, DWORD_PTR param, DWORD code);
	typedef ULONG_PTR(*FNtUserCallHwnd7) (HANDLE hwnd, DWORD code);
	typedef BOOLEAN (NTAPI*FNtUserGetWindowPlacement)(HANDLE 	hWnd, PVOID lpwndpl);
	typedef BOOLEAN (NTAPI*FNtUserGetTitleBarInfo)(HANDLE 	hwnd, PVOID 	pti);
	typedef BOOLEAN (NTAPI*FNtUserGetScrollBarInfo)(HANDLE 	hWnd, LONG 	idObject, PVOID 	psbi);
 

	ULONG_PTR MyNtUserCallHwnd7(HANDLE hwnd, DWORD code);
	ULONG_PTR MyNtUserCallHwndParam7(HANDLE hwnd, DWORD_PTR param, DWORD code);
	BOOLEAN MyNtUserValidateHandleSecure7(HANDLE hHdl);


 
 
	INT MyNtUserGetClassName7(HANDLE hWnd, BOOLEAN Ansi, PUNICODE_STRING ClassName);
	BOOLEAN MyNtUserPostMessage7(HANDLE hWnd, UINT Msg, ULONG wParam, __int64 lParam);
	BOOLEAN MyNtUserMessageCall7(HANDLE hWnd, UINT Msg, ULONG wParam, ULONG lParam, ULONG_PTR ResultInfo, DWORD dwType, BOOLEAN Ansi);
	NTSTATUS MyNtQueryInformationProcess7(HANDLE ProcessHandle, PROCESSINFOCLASS ProcessInformationClass, PVOID ProcessInformation, ULONG ProcessInformationLength, PULONG ReturnLength);
	ULONG MyNtUserInternalGetWindowText7(HANDLE   hWnd, LPWSTR pString, int    cchMaxCount);
	NTSTATUS  MyNtOpenThread7(PHANDLE ProcessHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, PCLIENT_ID ClientId);
	NTSTATUS   MyNtOpenProcess7(PHANDLE ProcessHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, PCLIENT_ID ClientId);
	NTSTATUS   MyNtCreateFile7(PHANDLE FileHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, PIO_STATUS_BLOCK IoStatusBlock, PLARGE_INTEGER AllocationSize, ULONG FileAttributes, ULONG ShareAccess, ULONG CreateDisposition, ULONG CreateOptions, PVOID EaBuffer, ULONG EaLength);
	HANDLE     MyNtUserFindWindowEx7(IN HANDLE hwndParent, IN HANDLE hwndChild, IN PUNICODE_STRING pstrClassName OPTIONAL, IN PUNICODE_STRING pstrWindowName OPTIONAL, IN DWORD dwType);
	HANDLE  NTAPI    MyNtUserQueryWindow7(HANDLE hWnd, WINDOWINFOCLASS WindowInfo);
	HANDLE	   MyNtUserGetForegroundWindow7();
	DWORD_PTR  MyNtUserCallOneParam7(DWORD_PTR Param, DWORD Routine);
	HANDLE	   MyNtUserWindowFromPoint7(LONG x, LONG y);
	NTSTATUS  NTAPI  MyNtUserBuildHwndList7(HANDLE hDesktop, HANDLE hwndParent, BOOLEAN bChildren, ULONG dwThreadId, ULONG lParam, PHANDLE pWnd, PULONG pBufSize);
	BOOLEAN MyNtUserSetWindowDisplayAffinity7(HANDLE hWnd, LONG dwAffinity);
	BOOLEAN MyNtUserGetWindowDisplayAffinity7(HANDLE hWnd, PLONG dwAffinity);
	void __fastcall ssdt_call_back7(unsigned long ssdt_index, void** ssdt_address);

	BOOLEAN NTAPI MyNtUserGetWindowPlacement7(HANDLE 	hWnd, PVOID lpwndpl); 
	BOOLEAN NTAPI MyNtUserGetTitleBarInfo7(HANDLE 	hwnd, PVOID 	pti); 
	BOOLEAN NTAPI MyNtUserGetScrollBarInfo7(HANDLE 	hWnd,		LONG 	idObject, PVOID 	psbi	);

	EXTERN_C_END

		//extern	BOOLEAN IsHookStarted;
		//extern	FNtCreateFile g_NtCreateFile;
		//extern	FNtUserFindWindowEx	g_NtUserFindWindowEx;
		//extern	FNtUserBuildHwndList  g_NtUserBuildHwndList;
		//extern	FNtUserBuildHwndList7  g_NtUserBuildHwndList7;
		//extern	FNtUserQueryWindow	g_NtUserQueryWindow;
		//extern	FNtUserGetForegroundWindow	g_NtUserGetForegroundWindow;
		//extern	FNtUserWindowFromPoint	g_NtUserWindowFromPoint;


		NTSTATUS StartProtect();

	NTSTATUS SetProtectWindow();
	NTSTATUS AntiSnapWindow(ULONG32 hwnd);
	BOOLEAN RemoveProtectWindow();
	HANDLE GetWindowThread(HANDLE hwnd);
	POBJECT_NAME_INFORMATION QueryFileDosName(ULONG pid);


}
#endif // ! _PROTECT_WINDOW_H