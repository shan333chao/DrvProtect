#include "DefineCommon.h"


PVOID GetSystemInformation(SYSTEM_INFORMATION_CLASS information_class);

VOID GetKernelModule(PCHAR szModuleName, PRTL_PROCESS_MODULE_INFORMATION pModuleInfo);

HANDLE GetPidByName(PWCH imageName);


RTL_OSVERSIONINFOW InitOsVersion();


 
