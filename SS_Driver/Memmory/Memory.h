#pragma once
#include <ntifs.h>
#include <windef.h>
#include "../SSDT/Functions.h"

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


NTSTATUS SS_ReadMemory(ULONG_PTR uPid, ULONG_PTR uFakePid, PVOID Address, ULONG_PTR uReadSize, PVOID ReadBuffer);

NTSTATUS SS_WriteMemory(ULONG_PTR uPid, ULONG_PTR uFakePid, PVOID Address, ULONG_PTR uWriteSize, PVOID WriteBuffer);


NTSTATUS SS_ReadMemoryPhy(ULONG_PTR uPid,  PVOID Address, ULONG_PTR uReadSize, PVOID ReadBuffer);

NTSTATUS SS_WriteMemoryPhy(ULONG_PTR uPid,  PVOID Address, ULONG_PTR uWriteSize, PVOID WriteBuffer);

NTSTATUS SS_CreateMemory(ULONG uPid , ULONG_PTR uSize, PULONG64 retAddress);

VOID ChangePageAttributeExecute(ULONG64 uAddress, ULONG64 uSize);


