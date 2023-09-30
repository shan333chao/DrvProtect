#ifndef  _MEMORY_H 
#define _MEMORY_H

#pragma once
#include "../SSDT/Functions.h" 

#define WINDOWS_7 7600
#define WINDOWS_7_SP1 7601
#define WINDOWS_8 9200
#define WINDOWS_8_1 9600
#define WINDOWS_10_VERSION_THRESHOLD1 10240
#define WINDOWS_10_VERSION_THRESHOLD2 10586
#define WINDOWS_10_VERSION_REDSTONE1 14393
#define WINDOWS_10_VERSION_REDSTONE2 15063
#define WINDOWS_10_VERSION_REDSTONE3 16299
#define WINDOWS_10_VERSION_REDSTONE4 17134
#define WINDOWS_10_VERSION_REDSTONE5 17763
#define WINDOWS_10_VERSION_19H1 18362
#define WINDOWS_10_VERSION_19H2 18363
#define WINDOWS_10_VERSION_20H1 19041
#define WINDOWS_10_VERSION_20H2 19042
#define WINDOWS_10_VERSION_21H1 19043
#define WINDOWS_10_VERSION_21H2 19044
#define WINDOWS_10_VERSION_22H2 19045
#define WINDOWS_11 22000

#define SEC_IMAGE 0x1000000


//0x8 bytes (sizeof)
typedef struct _HARDWARE_PTE
{
    ULONGLONG Valid : 1;                                                      //0x0
    ULONGLONG Write : 1;                                                      //0x0
    ULONGLONG Owner : 1;                                                      //0x0
    ULONGLONG WriteThrough : 1;                                               //0x0
    ULONGLONG CacheDisable : 1;                                               //0x0
    ULONGLONG Accessed : 1;                                                   //0x0
    ULONGLONG Dirty : 1;                                                      //0x0
    ULONGLONG LargePage : 1;                                                  //0x0
    ULONGLONG Global : 1;                                                     //0x0
    ULONGLONG CopyOnWrite : 1;                                                //0x0
    ULONGLONG Prototype : 1;                                                  //0x0
    ULONGLONG reserved0 : 1;                                                  //0x0
    ULONGLONG PageFrameNumber : 36;                                           //0x0
    ULONGLONG reserved1 : 4;                                                  //0x0
    ULONGLONG SoftwareWsIndex : 11;                                           //0x0
    ULONGLONG NoExecute : 1;                                                  //0x0
}HARDWARE_PTE,* PHARDWARE_PTE;

namespace memory {
    NTSTATUS SS_ReadMemory(ULONG_PTR uPid, ULONG_PTR uFakePid, PVOID Address, ULONG_PTR uReadSize, PVOID ReadBuffer);

    NTSTATUS SS_WriteMemory(ULONG_PTR uPid, ULONG_PTR uFakePid, PVOID Address, ULONG_PTR uWriteSize, PVOID WriteBuffer);


    NTSTATUS SS_ReadMemoryPhy(ULONG_PTR uPid, PVOID Address, ULONG_PTR uReadSize, PVOID ReadBuffer);

    NTSTATUS SS_WriteMemoryPhy(ULONG_PTR uPid, PVOID Address, ULONG_PTR uWriteSize, PVOID WriteBuffer);

    NTSTATUS SS_CreateMemory(ULONG uPid, ULONG_PTR uSize, PULONG64 retAddress);

    VOID ChangePageAttributeExecute(ULONG64 uAddress, ULONG64 uSize);
    NTSTATUS SS_GetImageSize(ULONG_PTR uPid, PVOID Address, PULONG pSizeOfImage);


}

#endif // ! _MEMORY_H 