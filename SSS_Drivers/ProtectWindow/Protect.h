

#ifndef _PROTECT_H
#define _PROTECT_H

#pragma once

#include "../includes.h"
#define WM_GETTEXT                      0x000D
typedef enum _WINDOWINFOCLASS {
	WindowProcess,
	WindowThread,
	WindowActiveWindow,
	WindowFocusWindow,
	WindowIsHung,
	WindowClientBase,
	WindowIsForegroundThread,

} WINDOWINFOCLASS;
namespace Protect {

 
	typedef struct _PROTECT_PROCESS
	{
		LIST_ENTRY ProtectProcesses;
		PEPROCESS  Process; 
		HANDLE PID;
		HANDLE FAKEID;
	}PROTECT_PROCESS, * PPROTECT_PROCESS;

	typedef struct _PROTECT_HWND
	{
		LIST_ENTRY ProtectHWNDS;
		HANDLE  hwnd; 
		HANDLE thread;
	}PROTECT_HWND, * PPROTECT_HWND;


	
 

	BOOLEAN Initialize();
	BOOLEAN IsProtectProcess(PEPROCESS TargetProcess);
	BOOLEAN IsProtectPID(HANDLE pid);
	BOOLEAN RemoveProtectProcess(PEPROCESS TargetProcess);
	BOOLEAN AddProtectProcess(PEPROCESS TargetProcess, ULONG fakeID);
	BOOLEAN AddProtectPid(ULONG PID, ULONG fakeID);
	ULONG32 IsProtectWND(HANDLE hwnd, HANDLE child, HANDLE hwndThread, HANDLE currentThread);
	BOOLEAN AddProtectWND(HANDLE hwnd, HANDLE threadId);
	BOOLEAN AddProtectWNDBatch(PULONG32 hwnds, ULONG32 length, HANDLE threadId);


}



#endif // !_PROTECT_H

