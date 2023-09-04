#include "../infinity_hook_pro/imports.hpp"
#include "../infinity_hook_pro/hook.hpp"
#include"../Includes.h"
#define WM_GETTEXT                      0x000D
#define WM_GETICON                      0x007F
namespace ProtectWindow {
	EXTERN_C_START
		typedef NTSTATUS(*FNtCreateFile)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, PIO_STATUS_BLOCK, PLARGE_INTEGER, ULONG, ULONG, ULONG, ULONG, PVOID, ULONG);
	typedef HANDLE(*FNtUserFindWindowEx)(PVOID, PVOID, PUNICODE_STRING, PUNICODE_STRING, ULONG);
	typedef NTSTATUS(*FNtUserBuildHwndList)(HANDLE, HANDLE, BOOLEAN, BOOLEAN, ULONG, ULONG, HWND*, PULONG);
	typedef NTSTATUS(*FNtUserBuildHwndList7)(HANDLE hDesktop, HWND hwndParent, BOOLEAN bChildren, ULONG dwThreadId, ULONG lParam, PHANDLE pWnd, PULONG pBufSize);
	typedef	HANDLE(*FNtUserQueryWindow)(HANDLE, WINDOWINFOCLASS);
	typedef HWND(*FNtUserGetForegroundWindow)();
	typedef NTSTATUS(*FNtQueryInformationProcess)(HANDLE ProcessHandle, PROCESSINFOCLASS ProcessInformationClass, PVOID ProcessInformation, ULONG ProcessInformationLength, PULONG ReturnLength);

	typedef	INT(*FNtUserGetClassName)(HWND hWnd, BOOL Ansi, PUNICODE_STRING ClassName);

	typedef HWND(*FNtUserSetParent)(HWND hWndChild, HWND hWndNewParent);
	typedef BOOLEAN(*FNtUserSetLayeredWindowAttributes)(HWND  hwnd, ULONG32 COLORREF, BYTE  bAlpha, ULONG32 dwFlags);
	typedef HWND(*FNtUserWindowFromPoint)(LONG x, LONG y);
	typedef BOOLEAN(*FNtUserSetWindowDisplayAffinity)(HWND hWnd, LONG dwAffinity);
	typedef BOOLEAN(*FNtUserGetWindowDisplayAffinity)(HWND hWnd, PLONG dwAffinity);
	typedef NTSTATUS(*FNtOpenProcess)(PHANDLE ProcessHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, PCLIENT_ID ClientId);
	typedef NTSTATUS(*FNtOpenThread)(PHANDLE ProcessHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, PCLIENT_ID ClientId);
	typedef ULONG(*FNtUserInternalGetWindowText)(HWND   hWnd, LPWSTR pString, int    cchMaxCount);
	typedef BOOL(*FNtUserPostMessage)(HWND hWnd, UINT Msg, WPARAM wParam, LPARAM lParam);
	typedef BOOL(*FNtUserMessageCall)(HWND hWnd, UINT Msg, WPARAM wParam, LPARAM lParam, ULONG_PTR ResultInfo, DWORD dwType, BOOL Ansi);
	typedef DWORD_PTR(*FNtUserCallOneParam)(DWORD_PTR Param, DWORD Routine);
	typedef BOOL(*FNtUserValidateHandleSecure)(HANDLE hHdl);
	typedef ULONG_PTR(*FNtUserCallHwndParam)(HWND hwnd, DWORD_PTR param, DWORD code);
	typedef ULONG_PTR(*FNtUserCallHwnd) (HWND hwnd, DWORD code);

	ULONG_PTR MyNtUserCallHwnd(HWND hwnd, DWORD code);
	ULONG_PTR MyNtUserCallHwndParam(HWND hwnd, DWORD_PTR param, DWORD code);
	BOOL MyNtUserValidateHandleSecure(HANDLE hHdl);



	INT MyNtUserGetClassName(HWND hWnd, BOOL Ansi, PUNICODE_STRING ClassName);
	BOOL MyNtUserPostMessage(HWND hWnd, UINT Msg, WPARAM wParam, LPARAM lParam);
	BOOL MyNtUserMessageCall(HWND hWnd, UINT Msg, WPARAM wParam, LPARAM lParam, ULONG_PTR ResultInfo, DWORD dwType, BOOL Ansi);
	NTSTATUS MyNtQueryInformationProcess(HANDLE ProcessHandle, PROCESSINFOCLASS ProcessInformationClass, PVOID ProcessInformation, ULONG ProcessInformationLength, PULONG ReturnLength);
	ULONG MyNtUserInternalGetWindowText(HWND   hWnd, LPWSTR pString, int    cchMaxCount);
	NTSTATUS  MyNtOpenThread(PHANDLE ProcessHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, PCLIENT_ID ClientId);
	NTSTATUS   MyNtOpenProcess(PHANDLE ProcessHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, PCLIENT_ID ClientId);
	NTSTATUS   MyNtCreateFile(PHANDLE FileHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, PIO_STATUS_BLOCK IoStatusBlock, PLARGE_INTEGER AllocationSize, ULONG FileAttributes, ULONG ShareAccess, ULONG CreateDisposition, ULONG CreateOptions, PVOID EaBuffer, ULONG EaLength);
	HANDLE     MyNtUserFindWindowEx(IN HWND hwndParent, IN HWND hwndChild, IN PUNICODE_STRING pstrClassName OPTIONAL, IN PUNICODE_STRING pstrWindowName OPTIONAL, IN DWORD dwType);
	NTSTATUS   MyNtUserBuildHwndList(HANDLE hDesktop, HWND hwndParent, BOOLEAN bChildren, BOOLEAN bUnknownFlag, ULONG dwThreadId, ULONG lParam, HWND* pWnd, PULONG pBufSize);
	HANDLE     MyNtUserQueryWindow(HWND hWnd, WINDOWINFOCLASS WindowInfo);
	HWND	   MyNtUserGetForegroundWindow();
	DWORD_PTR  MyNtUserCallOneParam(DWORD_PTR Param, DWORD Routine);
	HWND	   MyNtUserWindowFromPoint(LONG x, LONG y);
	NTSTATUS   MyNtUserBuildHwndList7(HANDLE hDesktop, HWND hwndParent, BOOLEAN bChildren, ULONG dwThreadId, ULONG lParam, PHANDLE pWnd, PULONG pBufSize);
	BOOLEAN MyNtUserSetWindowDisplayAffinity(HWND hWnd, LONG dwAffinity);
	BOOLEAN MyNtUserGetWindowDisplayAffinity(HWND hWnd, PLONG dwAffinity);
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
	HANDLE GetWindowThread(HWND hwnd);
	POBJECT_NAME_INFORMATION QueryFileDosName(ULONG pid);


}