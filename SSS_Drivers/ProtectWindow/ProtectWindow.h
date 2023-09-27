#ifndef  _PROTECT_WINDOW_H
#define _PROTECT_WINDOW_H


#pragma once
#include "../infinity_hook_pro/imports.hpp"
#include "../infinity_hook_pro/hook.hpp"
#include "Protect.h"
#include "../SSDT/ssdt.h"
#include "../Comm/Comm.h"

typedef NTSTATUS(NTAPI* CommCallBack)(PCOMM_DATA pCommData);
namespace ProtectWindow {
	EXTERN_C_START

		typedef NTSTATUS(*FNtCreateFile)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, PIO_STATUS_BLOCK, PLARGE_INTEGER, ULONG, ULONG, ULONG, ULONG, PVOID, ULONG);
	typedef HANDLE(*FNtUserFindWindowEx)(PVOID, PVOID, PUNICODE_STRING, PUNICODE_STRING, ULONG);
	typedef NTSTATUS(*FNtUserBuildHwndList)(HANDLE, HANDLE, BOOLEAN, BOOLEAN, ULONG, ULONG, HANDLE*, PULONG);
	typedef	HANDLE(*FNtUserQueryWindow)(HANDLE, WINDOWINFOCLASS);
	typedef HANDLE(*FNtUserGetForegroundWindow)();
	typedef NTSTATUS(*FNtQueryInformationProcess)(HANDLE ProcessHandle, PROCESSINFOCLASS ProcessInformationClass, PVOID ProcessInformation, ULONG ProcessInformationLength, PULONG ReturnLength);

	typedef	INT(*FNtUserGetClassName)(HANDLE hWnd, BOOLEAN Ansi, PUNICODE_STRING ClassName);

	typedef HANDLE(*FNtUserSetParent)(HANDLE hWndChild, HANDLE hWndNewParent);
	typedef BOOLEAN(*FNtUserSetLayeredWindowAttributes)(HANDLE  hwnd, ULONG32 COLORREF, BYTE  bAlpha, ULONG32 dwFlags);
	typedef HANDLE(*FNtUserWindowFromPoint)(LONG x, LONG y);
	typedef BOOLEAN(*FNtUserSetWindowDisplayAffinity)(HANDLE hWnd, LONG dwAffinity);
	typedef BOOLEAN(*FNtUserGetWindowDisplayAffinity)(HANDLE hWnd, PLONG dwAffinity);
	typedef NTSTATUS(*FNtOpenProcess)(PHANDLE ProcessHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, PCLIENT_ID ClientId);
	typedef NTSTATUS(*FNtOpenThread)(PHANDLE ProcessHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, PCLIENT_ID ClientId);
	typedef ULONG(*FNtUserInternalGetWindowText)(HANDLE   hWnd, LPWSTR pString, int    cchMaxCount);
	typedef BOOLEAN(*FNtUserPostMessage)(HANDLE hWnd, UINT Msg, ULONG wParam, ULONG lParam);
	typedef __int64(*FNtUserMessageCall)(HANDLE hWnd, UINT Msg, ULONG wParam, ULONG lParam, ULONG_PTR ResultInfo, DWORD dwType, BOOLEAN Ansi);
	typedef DWORD_PTR(*FNtUserCallOneParam)(DWORD_PTR Param, DWORD Routine);
	typedef BOOLEAN(*FNtUserValidateHandleSecure)(HANDLE hHdl);
	typedef ULONG_PTR(*FNtUserCallHwndParam)(HANDLE hwnd, DWORD_PTR param, DWORD code);
	typedef ULONG_PTR(*FNtUserCallHwnd) (HANDLE hwnd, DWORD code);
	typedef INT64(*FNtUserGetPointerProprietaryId)(uintptr_t);
	typedef BOOLEAN(* FNtUserGetWindowPlacement)(HANDLE 	hWnd, uintptr_t lpwndpl);
	typedef BOOLEAN(* FNtUserGetTitleBarInfo)(HANDLE 	hwnd, uintptr_t 	pti);
	typedef BOOLEAN(* FNtUserGetScrollBarInfo)(HANDLE 	hWnd, LONG 	idObject, uintptr_t 	psbi);


	ULONG_PTR MyNtUserCallHwnd(HANDLE hwnd, DWORD code);
	ULONG_PTR MyNtUserCallHwndParam(HANDLE hwnd, DWORD_PTR param, DWORD code);
	BOOLEAN MyNtUserValidateHandleSecure(HANDLE hHdl);


	INT64 MyNtUserGetPointerProprietaryId(uintptr_t data);
	INT MyNtUserGetClassName(HANDLE hWnd, BOOLEAN Ansi, PUNICODE_STRING ClassName);
	BOOLEAN MyNtUserPostMessage(HANDLE hWnd, UINT Msg, ULONG wParam, ULONG lParam);
	__int64 MyNtUserMessageCall(HANDLE hWnd, UINT Msg, ULONG wParam, ULONG lParam, ULONG_PTR ResultInfo, DWORD dwType, BOOLEAN Ansi);
	NTSTATUS MyNtQueryInformationProcess(HANDLE ProcessHandle, PROCESSINFOCLASS ProcessInformationClass, PVOID ProcessInformation, ULONG ProcessInformationLength, PULONG ReturnLength);
	ULONG MyNtUserInternalGetWindowText(HANDLE   hWnd, LPWSTR pString, int    cchMaxCount);
	NTSTATUS  MyNtOpenThread(PHANDLE ProcessHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, PCLIENT_ID ClientId);
	NTSTATUS   MyNtOpenProcess(PHANDLE ProcessHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, PCLIENT_ID ClientId);
	NTSTATUS   MyNtCreateFile(PHANDLE FileHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, PIO_STATUS_BLOCK IoStatusBlock, PLARGE_INTEGER AllocationSize, ULONG FileAttributes, ULONG ShareAccess, ULONG CreateDisposition, ULONG CreateOptions, PVOID EaBuffer, ULONG EaLength);
	HANDLE     MyNtUserFindWindowEx(IN HANDLE hwndParent, IN HANDLE hwndChild, IN PUNICODE_STRING pstrClassName OPTIONAL, IN PUNICODE_STRING pstrWindowName OPTIONAL, IN DWORD dwType);
	NTSTATUS   MyNtUserBuildHwndList(HANDLE hDesktop, HANDLE hwndParent, BOOLEAN bChildren, BOOLEAN bUnknownFlag, ULONG dwThreadId, ULONG lParam, HANDLE* pWnd, PULONG pBufSize);
	HANDLE     MyNtUserQueryWindow(HANDLE hWnd, WINDOWINFOCLASS WindowInfo);
	HANDLE	   MyNtUserGetForegroundWindow();
	DWORD_PTR  MyNtUserCallOneParam(DWORD_PTR Param, DWORD Routine);
	HANDLE	   MyNtUserWindowFromPoint(LONG x, LONG y);
	NTSTATUS   MyNtUserBuildHwndList7(HANDLE hDesktop, HANDLE hwndParent, BOOLEAN bChildren, ULONG dwThreadId, ULONG lParam, PHANDLE pWnd, PULONG pBufSize);
	BOOLEAN MyNtUserSetWindowDisplayAffinity(HANDLE hWnd, LONG dwAffinity);
	BOOLEAN MyNtUserGetWindowDisplayAffinity(HANDLE hWnd, PLONG dwAffinity);

	BOOLEAN NTAPI MyNtUserGetWindowPlacement(HANDLE 	hWnd, uintptr_t lpwndpl);
	BOOLEAN NTAPI MyNtUserGetTitleBarInfo(HANDLE 	hwnd, uintptr_t 	pti);
	BOOLEAN NTAPI MyNtUserGetScrollBarInfo(HANDLE 	hWnd, LONG 	idObject, uintptr_t 	psbi);
	BOOLEAN DoCommon(PVOID pCommData);
	VOID  InitCommHook(CommCallBack callBackFun);
	void __fastcall ssdt_call_back(unsigned long ssdt_index, void** ssdt_address);
	
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
	ULONG SetReg(PVOID regCode, ULONG size, ULONGLONG time);
	ULONG MyGetTickCount();

	BOOLEAN ValidateReg();

}
#endif // ! _PROTECT_WINDOW_H