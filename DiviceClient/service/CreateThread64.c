#include <windows.h>
#include <stdio.h>
#include <TlHelp32.h>  
 
BOOL IsWow64(HANDLE hProcess)
{
    typedef BOOL(WINAPI* LPFN_ISWOW64PROCESS) (HANDLE, PBOOL);
    LPFN_ISWOW64PROCESS fnIsWow64Process;

    BOOL bIsWow64 = FALSE;
    fnIsWow64Process = (LPFN_ISWOW64PROCESS)GetProcAddress(
        GetModuleHandle("kernel32"), "IsWow64Process");

    if (NULL != fnIsWow64Process)
    {
        fnIsWow64Process(hProcess, &bIsWow64);
    }
    return bIsWow64;
}

DWORD processNameToId(LPCTSTR lpszProcessName)
{
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    PROCESSENTRY32 pe;
    pe.dwSize = sizeof(PROCESSENTRY32);
    if (!Process32First(hSnapshot, &pe)) {
        MessageBox(NULL, "The frist entry of the process list has not been copyied to the buffer", "Notice", MB_ICONINFORMATION | MB_OK);
        return 0;
    }
    while (Process32Next(hSnapshot, &pe)) {
        if (!strcmp(lpszProcessName, pe.szExeFile)) {
            return pe.th32ProcessID;
        }
    }

    return 0;
}

BOOL Is64BitOS()
{
    typedef VOID(WINAPI* LPFN_GetNativeSystemInfo)(__out LPSYSTEM_INFO lpSystemInfo);
    LPFN_GetNativeSystemInfo fnGetNativeSystemInfo = (LPFN_GetNativeSystemInfo)GetProcAddress(GetModuleHandle("kernel32"), "GetNativeSystemInfo");
    if (fnGetNativeSystemInfo)
    {
        SYSTEM_INFO stInfo = { 0 };
        fnGetNativeSystemInfo(&stInfo);
        if (stInfo.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_IA64
            || stInfo.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_AMD64)
        {
            return TRUE;
        }
    }
    return FALSE;
}

LPVOID init_func(char* asmcode, DWORD len)
{
    LPVOID sc = NULL;
    // allocate write/executable memory for code
    sc = VirtualAlloc(0, len, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    if (sc != NULL) {
        // copy code
        memcpy(sc, asmcode, len);
    }
    else {
        
        MessageBox(NULL, "VirtualAlloc()", "Notice", MB_ICONINFORMATION | MB_OK);
    }
    return sc;
}

 

BOOL enableDebugPriv()
{
    HANDLE hToken;
    LUID sedebugnameValue;
    TOKEN_PRIVILEGES tkp;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken)) {
        return FALSE;
    }
    if (!LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &sedebugnameValue)) {
        CloseHandle(hToken);
        return FALSE;
    }
    tkp.PrivilegeCount = 1;
    tkp.Privileges[0].Luid = sedebugnameValue;
    tkp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
    if (!AdjustTokenPrivileges(hToken, FALSE, &tkp, sizeof(tkp), NULL, NULL)) {
        CloseHandle(hToken);
        return FALSE;
    }
    return TRUE;
}

 
 