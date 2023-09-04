#pragma once
#include <ntifs.h>
#include "../SSDT/Functions.h"

ULONG_PTR GetProcessModuleInfo(ULONG pid, PCHAR pcModuleName, PULONG pModuleSize);
ULONG_PTR GetX86ProcessModule(PEPROCESS	pTargetEprocess, PUNICODE_STRING szModuleName, PULONG pModuleSize);
ULONG_PTR GetX64ProcessModule(PEPROCESS	pTargetEprocess, PUNICODE_STRING szModuleName, PULONG pModuleSize);
//PsGetProcessExitStatus
ULONG_PTR GetProcessModuleFromVad(PEPROCESS	pTargetEprocess, PUNICODE_STRING szModuleName, PULONG pModuleSize);

//0x18 bytes (sizeof)
typedef struct _CURDIR32
{
    UNICODE_STRING32 DosPath;                                         //0x0
    ULONG Handle;                                                           //0x10
}CURDIR32,*PCURDIR32;

typedef struct _RTL_DRIVE_LETTER_CURDIR
{
    USHORT Flags;                                                           //0x0
    USHORT Length;                                                          //0x2
    ULONG TimeStamp;                                                        //0x4
    struct _STRING DosPath;                                                 //0x8
}RTL_DRIVE_LETTER_CURDIR,PRTL_DRIVE_LETTER_CURDIR;

//0x18 bytes (sizeof)
typedef struct _CURDIR
{
    struct _UNICODE_STRING DosPath;                                         //0x0
    VOID* Handle;                                                           //0x10
}CURDIR, * PCURDIR;
//0x298 bytes (sizeof)
typedef struct _RTL_USER_PROCESS_PARAMETERS32
{
    ULONG MaximumLength;                                                    //0x0
    ULONG Length;                                                           //0x4
    ULONG Flags;                                                            //0x8
    ULONG DebugFlags;                                                       //0xc
    ULONG ConsoleHandle;                                                    //0x10
    ULONG ConsoleFlags;                                                     //0x14
    ULONG StandardInput;                                                    //0x18
    ULONG StandardOutput;                                                   //0x1c
    ULONG StandardError;                                                    //0x20
      CURDIR32 CurrentDirectory;                                        //0x24
      UNICODE_STRING32 DllPath;                                         //0x30
      UNICODE_STRING32 ImagePathName;                                   //0x38
      UNICODE_STRING32 CommandLine;                                     //0x40
      ULONG Environment;                                                      //0x48
    ULONG StartingX;                                                        //0x4c
    ULONG StartingY;                                                        //0x50
    ULONG CountX;                                                           //0x54
    ULONG CountY;                                                           //0x58
    ULONG CountCharsX;                                                      //0x5c
    ULONG CountCharsY;                                                      //0x60
    ULONG FillAttribute;                                                    //0x64
    ULONG WindowFlags;                                                      //0x68
    ULONG ShowWindowFlags;                                                  //0x6c
      UNICODE_STRING32 WindowTitle;                                     //0x70
      UNICODE_STRING32 DesktopInfo;                                     //0xc0
      UNICODE_STRING32 ShellInfo;                                       //0xd0
      UNICODE_STRING32 RuntimeData;                                     //0xe0
      RTL_DRIVE_LETTER_CURDIR CurrentDirectores[32];                  //0xf0
      ULONG EnvironmentSize;                                                  //0x290
      ULONG EnvironmentVersion;                                               //0x294
      ULONG PackageDependencyData;                                            //0x298
      ULONG ProcessGroupId;                                                   //0x29c

}RTL_USER_PROCESS_PARAMETERS32,*PRTL_USER_PROCESS_PARAMETERS32;


//0x440 bytes (sizeof)
typedef struct _RTL_USER_PROCESS_PARAMETERS
{
    ULONG MaximumLength;                                                    //0x0
    ULONG Length;                                                           //0x4
    ULONG Flags;                                                            //0x8
    ULONG DebugFlags;                                                       //0xc
    VOID* ConsoleHandle;                                                    //0x10
    ULONG ConsoleFlags;                                                     //0x18
    VOID* StandardInput;                                                    //0x20
    VOID* StandardOutput;                                                   //0x28
    VOID* StandardError;                                                    //0x30
      CURDIR CurrentDirectory;                                        //0x38
      UNICODE_STRING DllPath;                                         //0x50
      UNICODE_STRING ImagePathName;                                   //0x60
      UNICODE_STRING CommandLine;                                     //0x70
    VOID* Environment;                                                      //0x80
    ULONG StartingX;                                                        //0x88
    ULONG StartingY;                                                        //0x8c
    ULONG CountX;                                                           //0x90
    ULONG CountY;                                                           //0x94
    ULONG CountCharsX;                                                      //0x98
    ULONG CountCharsY;                                                      //0x9c
    ULONG FillAttribute;                                                    //0xa0
    ULONG WindowFlags;                                                      //0xa4
    ULONG ShowWindowFlags;                                                  //0xa8
    UNICODE_STRING WindowTitle;                                     //0xb0
    UNICODE_STRING DesktopInfo;                                     //0xc0
    UNICODE_STRING ShellInfo;                                       //0xd0
    UNICODE_STRING RuntimeData;                                     //0xe0
    RTL_DRIVE_LETTER_CURDIR CurrentDirectores[32];                  //0xf0
    ULONGLONG EnvironmentSize;                                              //0x3f0
    ULONGLONG EnvironmentVersion;                                           //0x3f8
    VOID* PackageDependencyData;                                            //0x400
    ULONG ProcessGroupId;                                                   //0x408
    ULONG LoaderThreads;                                                    //0x40c

 
}RTL_USER_PROCESS_PARAMETERS,*PRTL_USER_PROCESS_PARAMETERS;
 
//0x58 bytes (sizeof)
typedef struct _PEB_LDR_DATA64
{
    ULONG Length;                                                           //0x0
    UCHAR Initialized;                                                      //0x4
    VOID* SsHandle;                                                         //0x8
    struct LIST_ENTRY64 InLoadOrderModuleList;                               //0x10
    struct LIST_ENTRY64 InMemoryOrderModuleList;                             //0x20
    struct LIST_ENTRY64 InInitializationOrderModuleList;                     //0x30
    VOID* EntryInProgress;                                                  //0x40
    UCHAR ShutdownInProgress;                                               //0x48
    VOID* ShutdownThreadId;                                                 //0x50
}PEB_LDR_DATA64,*PPEB_LDR_DATA64;


//0x30 bytes (sizeof)
typedef struct _PEB_LDR_DATA32
{
    ULONG Length;                                                           //0x0
    UCHAR Initialized;                                                      //0x4
    ULONG SsHandle;                                                         //0x8
    struct LIST_ENTRY32 InLoadOrderModuleList;                               //0xc
    struct LIST_ENTRY32 InMemoryOrderModuleList;                             //0x14
    struct LIST_ENTRY32 InInitializationOrderModuleList;                     //0x1c
    VOID* EntryInProgress;                                                  //0x24
    UCHAR ShutdownInProgress;                                               //0x28
    VOID* ShutdownThreadId;                                                 //0x2c
}PEB_LDR_DATA32, *PPEB_LDR_DATA32;

//0x480 bytes (sizeof)
typedef struct _PEB32
{
    UCHAR InheritedAddressSpace;
    UCHAR ReadImageFileExecOptions;
    UCHAR BeingDebugged;
    UCHAR BitField;
    ULONG Mutant;
    ULONG ImageBaseAddress;
    ULONG Ldr;
    ULONG ProcessParameters;
    ULONG SubSystemData;
    ULONG ProcessHeap;
    ULONG FastPebLock;
    ULONG AtlThunkSListPtr;
    ULONG IFEOKey;
    ULONG CrossProcessFlags;
    ULONG UserSharedInfoPtr;
    ULONG SystemReserved;
    ULONG AtlThunkSListPtr32;
    ULONG ApiSetMap;
} PEB32, *PPEB32;


//0x7c8 bytes (sizeof)
typedef struct _PEB64
{
    UCHAR InheritedAddressSpace;                                            //0x0
    UCHAR ReadImageFileExecOptions;                                         //0x1
    UCHAR BeingDebugged;                                                    //0x2
    union
    {
        UCHAR BitField;                                                     //0x3
        struct
        {
            UCHAR ImageUsesLargePages : 1;                                    //0x3
            UCHAR IsProtectedProcess : 1;                                     //0x3
            UCHAR IsImageDynamicallyRelocated : 1;                            //0x3
            UCHAR SkipPatchingUser32Forwarders : 1;                           //0x3
            UCHAR IsPackagedProcess : 1;                                      //0x3
            UCHAR IsAppContainer : 1;                                         //0x3
            UCHAR IsProtectedProcessLight : 1;                                //0x3
            UCHAR IsLongPathAwareProcess : 1;                                 //0x3
        };
    };
    UCHAR Padding0[4];                                                      //0x4
    ULONGLONG Mutant;                                                       //0x8
    ULONGLONG ImageBaseAddress;                                             //0x10
    PPEB_LDR_DATA64 Ldr;                                                          //0x18
    PRTL_USER_PROCESS_PARAMETERS   ProcessParameters;                                            //0x20

   
}PEB64, * PPEB64;

//0x120 bytes (sizeof)
typedef struct _LDR_DATA_TABLE_ENTRY
{
    struct _LIST_ENTRY InLoadOrderLinks;                                    //0x0
    struct _LIST_ENTRY InMemoryOrderLinks;                                  //0x10
    struct _LIST_ENTRY InInitializationOrderLinks;                          //0x20
    ULONG64 DllBase;                                                          //0x30
    VOID* EntryPoint;                                                       //0x38
    ULONG SizeOfImage;                                                      //0x40
    struct _UNICODE_STRING FullDllName;                                     //0x48
    struct _UNICODE_STRING BaseDllName;                                     //0x58
    union
    {
        UCHAR FlagGroup[4];                                                 //0x68
        ULONG Flags;                                                        //0x68
        struct
        {
            ULONG PackagedBinary : 1;                                         //0x68
            ULONG MarkedForRemoval : 1;                                       //0x68
            ULONG ImageDll : 1;                                               //0x68
            ULONG LoadNotificationsSent : 1;                                  //0x68
            ULONG TelemetryEntryProcessed : 1;                                //0x68
            ULONG ProcessStaticImport : 1;                                    //0x68
            ULONG InLegacyLists : 1;                                          //0x68
            ULONG InIndexes : 1;                                              //0x68
            ULONG ShimDll : 1;                                                //0x68
            ULONG InExceptionTable : 1;                                       //0x68
            ULONG ReservedFlags1 : 2;                                         //0x68
            ULONG LoadInProgress : 1;                                         //0x68
            ULONG LoadConfigProcessed : 1;                                    //0x68
            ULONG EntryProcessed : 1;                                         //0x68
            ULONG ProtectDelayLoad : 1;                                       //0x68
            ULONG ReservedFlags3 : 2;                                         //0x68
            ULONG DontCallForThreads : 1;                                     //0x68
            ULONG ProcessAttachCalled : 1;                                    //0x68
            ULONG ProcessAttachFailed : 1;                                    //0x68
            ULONG CorDeferredValidate : 1;                                    //0x68
            ULONG CorImage : 1;                                               //0x68
            ULONG DontRelocate : 1;                                           //0x68
            ULONG CorILOnly : 1;                                              //0x68
            ULONG ChpeImage : 1;                                              //0x68
            ULONG ReservedFlags5 : 2;                                         //0x68
            ULONG Redirected : 1;                                             //0x68
            ULONG ReservedFlags6 : 2;                                         //0x68
            ULONG CompatDatabaseProcessed : 1;                                //0x68
        };
    };
    USHORT ObsoleteLoadCount;                                               //0x6c
    USHORT TlsIndex;                                                        //0x6e
    struct _LIST_ENTRY HashLinks;                                           //0x70
    ULONG TimeDateStamp;                                                    //0x80
    struct _ACTIVATION_CONTEXT* EntryPointActivationContext;                //0x88
    VOID* Lock;                                                             //0x90
    struct _LDR_DDAG_NODE* DdagNode;                                        //0x98
    struct _LIST_ENTRY NodeModuleLink;                                      //0xa0
    struct _LDRP_LOAD_CONTEXT* LoadContext;                                 //0xb0
    VOID* ParentDllBase;                                                    //0xb8
    VOID* SwitchBackContext;                                                //0xc0
    struct _RTL_BALANCED_NODE BaseAddressIndexNode;                         //0xc8
    struct _RTL_BALANCED_NODE MappingInfoIndexNode;                         //0xe0
    ULONGLONG OriginalBase;                                                 //0xf8
    union _LARGE_INTEGER LoadTime;                                          //0x100
    ULONG BaseNameHashValue;                                                //0x108
    enum _LDR_DLL_LOAD_REASON LoadReason;                                   //0x10c
    ULONG ImplicitPathOptions;                                              //0x110
    ULONG ReferenceCount;                                                   //0x114
    ULONG DependentLoadFlags;                                               //0x118
    UCHAR SigningLevel;                                                     //0x11c
}LDR_DATA_TABLE_ENTRY,* PLDR_DATA_TABLE_ENTRY;



typedef struct _LDR_DATA_TABLE_ENTRY32
{
    LIST_ENTRY32 InLoadOrderLinks;                                    //0x0
    LIST_ENTRY32 InMemoryOrderLinks;
    LIST_ENTRY32 InInitializationOrderLinks;
    ULONG DllBase;
    ULONG EntryPoint;
    ULONG SizeOfImage;
    UNICODE_STRING32 FullDllName;
    UNICODE_STRING32 BaseDllName;
    ULONG Flags;
    USHORT LoadCount;
    USHORT TlsIndex;
    LIST_ENTRY32 HashLinks;
    ULONG TimeDateStamp;
} LDR_DATA_TABLE_ENTRY32, * PLDR_DATA_TABLE_ENTRY32;