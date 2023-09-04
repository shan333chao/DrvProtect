#include "../Includes.h"

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
		HWND  hwnd; 
		HANDLE thread;
	}PROTECT_HWND, * PPROTECT_HWND;


	
 

	BOOLEAN Initialize();
	BOOLEAN IsProtectProcess(PEPROCESS TargetProcess);
	BOOLEAN IsProtectPID(HANDLE pid);
	BOOLEAN RemoveProtectProcess(PEPROCESS TargetProcess);
	BOOLEAN AddProtectProcess(PEPROCESS TargetProcess, ULONG fakeID);
	BOOLEAN AddProtectPid(ULONG PID, ULONG fakeID);
	ULONG32 IsProtectWND(HWND hwnd, HWND child, HANDLE hwndThread, HANDLE currentThread);
	BOOLEAN AddProtectWND(HWND hwnd, HANDLE threadId);
	BOOLEAN AddProtectWNDBatch(PULONG32 hwnds, ULONG32 length, HANDLE threadId);


}





