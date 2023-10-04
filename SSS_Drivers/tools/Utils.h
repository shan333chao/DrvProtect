#pragma once
#ifndef UTILS_H
#define UTILS_H


#include <ntifs.h>
#include <intrin.h>
#include <ntimage.h> 

#define DOS_HEADER_MAGIC 0x5A4D
#define PE_HEADER_MAGIC 0x4550


#define PFN_TO_PAGE(pfn) ( pfn << 12 )
#define dereference(ptr) (const uintptr_t)(ptr + *( int * )( ( BYTE * )ptr + 3 ) + 7)
#define in_range(x,a,b)    (x >= a && x <= b) 
#define get_bits( x )    (in_range((x&(~0x20)),'A','F') ? ((x&(~0x20)) - 'A' + 0xA) : (in_range(x,'0','9') ? x - '0' : 0))
#define get_byte( x )    (get_bits(x[0]) << 4 | get_bits(x[1]))
#define size_align(Size) ((Size + 0xFFF) & 0xFFFFFFFFFFFFF000)
#define to_lower_i(Char) ((Char >= 'A' && Char <= 'Z') ? (Char + 32) : Char)
#define to_lower_c(Char) ((Char >= (char*)'A' && Char <= (char*)'Z') ? (Char + 32) : Char)
//EXTERN_C_START
typedef struct _RTL_PROCESS_MODULE_INFORMATION {
	HANDLE Section;                 // Not filled in
	PVOID MappedBase;
	PVOID ImageBase;
	ULONG ImageSize;
	ULONG Flags;
	USHORT LoadOrderIndex;
	USHORT InitOrderIndex;
	USHORT LoadCount;
	USHORT OffsetToFileName;
	UCHAR  FullPathName[256];
} RTL_PROCESS_MODULE_INFORMATION, * PRTL_PROCESS_MODULE_INFORMATION;

typedef struct _SYSTEM_THREAD_INFORMATION {
	LARGE_INTEGER KernelTime;
	LARGE_INTEGER UserTime;
	LARGE_INTEGER CreateTime;
	ULONG WaitTime;
	PVOID StartAddress;
	CLIENT_ID ClientId;
	LONG Priority;
	LONG BasePriority;
	ULONG ContextSwitches;
	ULONG ThreadState;
	ULONG WaitReason;
} SYSTEM_THREAD_INFORMATION, * PSYSTEM_THREAD_INFORMATION;

typedef struct _SYSTEM_EXTENDED_THREAD_INFORMATION {
	SYSTEM_THREAD_INFORMATION ThreadInfo;
	PVOID StackBase;
	PVOID StackLimit;
	PVOID Win32StartAddress;
	PVOID TebBase;
	ULONG_PTR Reserved2;
	ULONG_PTR Reserved3;
	ULONG_PTR Reserved4;
}SYSTEM_EXTENDED_THREAD_INFORMATION, * PSYSTEM_EXTENDED_THREAD_INFORMATION;

typedef struct _SYSTEM_PROCESS_INFORMATION {
	ULONG NextEntryOffset;
	ULONG NumberOfThreads;
	LARGE_INTEGER WorkingSetPrivateSize; // since VISTA
	ULONG HardFaultCount; // since WIN7
	ULONG NumberOfThreadsHighWatermark; // since WIN7
	ULONGLONG CycleTime; // since WIN7
	LARGE_INTEGER CreateTime;
	LARGE_INTEGER UserTime;
	LARGE_INTEGER KernelTime;
	UNICODE_STRING ImageName;
	KPRIORITY BasePriority;
	HANDLE UniqueProcessId;
	HANDLE InheritedFromUniqueProcessId;
	ULONG HandleCount;
	ULONG SessionId;
	ULONG_PTR UniqueProcessKey; // since VISTA (requires SystemExtendedProcessInformation)
	SIZE_T PeakVirtualSize;
	SIZE_T VirtualSize;
	ULONG PageFaultCount;
	SIZE_T PeakWorkingSetSize;
	SIZE_T WorkingSetSize;
	SIZE_T QuotaPeakPagedPoolUsage;
	SIZE_T QuotaPagedPoolUsage;
	SIZE_T QuotaPeakNonPagedPoolUsage;
	SIZE_T QuotaNonPagedPoolUsage;
	SIZE_T PagefileUsage;
	SIZE_T PeakPagefileUsage;
	SIZE_T PrivatePageCount;
	LARGE_INTEGER ReadOperationCount;
	LARGE_INTEGER WriteOperationCount;
	LARGE_INTEGER OtherOperationCount;
	LARGE_INTEGER ReadTransferCount;
	LARGE_INTEGER WriteTransferCount;
	LARGE_INTEGER OtherTransferCount;
	SYSTEM_EXTENDED_THREAD_INFORMATION Threads[1];
} SYSTEM_PROCESS_INFORMATION, * PSYSTEM_PROCESS_INFORMATION;


typedef struct _RTL_PROCESS_MODULES {
	ULONG NumberOfModules;
	RTL_PROCESS_MODULE_INFORMATION Modules[1];
} RTL_PROCESS_MODULES, * PRTL_PROCESS_MODULES;

typedef struct _SYSTEM_MODULE
{
	ULONG_PTR Reserved[2];
	PVOID Base;
	ULONG Size;
	ULONG Flags;
	USHORT Index;
	USHORT Unknown;
	USHORT LoadCount;
	USHORT ModuleNameOffset;
	CHAR ImageName[256];
} SYSTEM_MODULE, * PSYSTEM_MODULE;

typedef struct _SYSTEM_MODULE_INFORMATION
{
	ULONG_PTR ulModuleCount;
	SYSTEM_MODULE Modules[1];
} SYSTEM_MODULE_INFORMATION, * PSYSTEM_MODULE_INFORMATION;
typedef enum _SYSTEM_INFORMATION_CLASS
{
	SystemBasicInformation = 0x0,
	SystemProcessorInformation = 0x1,
	SystemPerformanceInformation = 0x2,
	SystemTimeOfDayInformation = 0x3,
	SystemPathInformation = 0x4,
	SystemProcessInformation = 0x5,
	SystemCallCountInformation = 0x6,
	SystemDeviceInformation = 0x7,
	SystemProcessorPerformanceInformation = 0x8,
	SystemFlagsInformation = 0x9,
	SystemCallTimeInformation = 0xa,
	SystemModuleInformation = 0xb,
	SystemLocksInformation = 0xc,
	SystemStackTraceInformation = 0xd,
	SystemPagedPoolInformation = 0xe,
	SystemNonPagedPoolInformation = 0xf,
	SystemHandleInformation = 0x10,
	SystemObjectInformation = 0x11,
	SystemPageFileInformation = 0x12,
	SystemVdmInstemulInformation = 0x13,
	SystemVdmBopInformation = 0x14,
	SystemFileCacheInformation = 0x15,
	SystemPoolTagInformation = 0x16,
	SystemInterruptInformation = 0x17,
	SystemDpcBehaviorInformation = 0x18,
	SystemFullMemoryInformation = 0x19,
	SystemLoadGdiDriverInformation = 0x1a,
	SystemUnloadGdiDriverInformation = 0x1b,
	SystemTimeAdjustmentInformation = 0x1c,
	SystemSummaryMemoryInformation = 0x1d,
	SystemMirrorMemoryInformation = 0x1e,
	SystemPerformanceTraceInformation = 0x1f,
	SystemObsolete0 = 0x20,
	SystemExceptionInformation = 0x21,
	SystemCrashDumpStateInformation = 0x22,
	SystemKernelDebuggerInformation = 0x23,
	SystemContextSwitchInformation = 0x24,
	SystemRegistryQuotaInformation = 0x25,
	SystemExtendServiceTableInformation = 0x26,
	SystemPrioritySeperation = 0x27,
	SystemVerifierAddDriverInformation = 0x28,
	SystemVerifierRemoveDriverInformation = 0x29,
	SystemProcessorIdleInformation = 0x2a,
	SystemLegacyDriverInformation = 0x2b,
	SystemCurrentTimeZoneInformation = 0x2c,
	SystemLookasideInformation = 0x2d,
	SystemTimeSlipNotification = 0x2e,
	SystemSessionCreate = 0x2f,
	SystemSessionDetach = 0x30,
	SystemSessionInformation = 0x31,
	SystemRangeStartInformation = 0x32,
	SystemVerifierInformation = 0x33,
	SystemVerifierThunkExtend = 0x34,
	SystemSessionProcessInformation = 0x35,
	SystemLoadGdiDriverInSystemSpace = 0x36,
	SystemNumaProcessorMap = 0x37,
	SystemPrefetcherInformation = 0x38,
	SystemExtendedProcessInformation = 0x39,
	SystemRecommendedSharedDataAlignment = 0x3a,
	SystemComPlusPackage = 0x3b,
	SystemNumaAvailableMemory = 0x3c,
	SystemProcessorPowerInformation = 0x3d,
	SystemEmulationBasicInformation = 0x3e,
	SystemEmulationProcessorInformation = 0x3f,
	SystemExtendedHandleInformation = 0x40,
	SystemLostDelayedWriteInformation = 0x41,
	SystemBigPoolInformation = 0x42,
	SystemSessionPoolTagInformation = 0x43,
	SystemSessionMappedViewInformation = 0x44,
	SystemHotpatchInformation = 0x45,
	SystemObjectSecurityMode = 0x46,
	SystemWatchdogTimerHandler = 0x47,
	SystemWatchdogTimerInformation = 0x48,
	SystemLogicalProcessorInformation = 0x49,
	SystemWow64SharedInformationObsolete = 0x4a,
	SystemRegisterFirmwareTableInformationHandler = 0x4b,
	SystemFirmwareTableInformation = 0x4c,
	SystemModuleInformationEx = 0x4d,
	SystemVerifierTriageInformation = 0x4e,
	SystemSuperfetchInformation = 0x4f,
	SystemMemoryListInformation = 0x50,
	SystemFileCacheInformationEx = 0x51,
	SystemThreadPriorityClientIdInformation = 0x52,
	SystemProcessorIdleCycleTimeInformation = 0x53,
	SystemVerifierCancellationInformation = 0x54,
	SystemProcessorPowerInformationEx = 0x55,
	SystemRefTraceInformation = 0x56,
	SystemSpecialPoolInformation = 0x57,
	SystemProcessIdInformation = 0x58,
	SystemErrorPortInformation = 0x59,
	SystemBootEnvironmentInformation = 0x5a,
	SystemHypervisorInformation = 0x5b,
	SystemVerifierInformationEx = 0x5c,
	SystemTimeZoneInformation = 0x5d,
	SystemImageFileExecutionOptionsInformation = 0x5e,
	SystemCoverageInformation = 0x5f,
	SystemPrefetchPatchInformation = 0x60,
	SystemVerifierFaultsInformation = 0x61,
	SystemSystemPartitionInformation = 0x62,
	SystemSystemDiskInformation = 0x63,
	SystemProcessorPerformanceDistribution = 0x64,
	SystemNumaProximityNodeInformation = 0x65,
	SystemDynamicTimeZoneInformation = 0x66,
	SystemCodeIntegrityInformation = 0x67,
	SystemProcessorMicrocodeUpdateInformation = 0x68,
	SystemProcessorBrandString = 0x69,
	SystemVirtualAddressInformation = 0x6a,
	SystemLogicalProcessorAndGroupInformation = 0x6b,
	SystemProcessorCycleTimeInformation = 0x6c,
	SystemStoreInformation = 0x6d,
	SystemRegistryAppendString = 0x6e,
	SystemAitSamplingValue = 0x6f,
	SystemVhdBootInformation = 0x70,
	SystemCpuQuotaInformation = 0x71,
	SystemNativeBasicInformation = 0x72,
	SystemErrorPortTimeouts = 0x73,
	SystemLowPriorityIoInformation = 0x74,
	SystemBootEntropyInformation = 0x75,
	SystemVerifierCountersInformation = 0x76,
	SystemPagedPoolInformationEx = 0x77,
	SystemSystemPtesInformationEx = 0x78,
	SystemNodeDistanceInformation = 0x79,
	SystemAcpiAuditInformation = 0x7a,
	SystemBasicPerformanceInformation = 0x7b,
	SystemQueryPerformanceCounterInformation = 0x7c,
	SystemSessionBigPoolInformation = 0x7d,
	SystemBootGraphicsInformation = 0x7e,
	SystemScrubPhysicalMemoryInformation = 0x7f,
	SystemBadPageInformation = 0x80,
	SystemProcessorProfileControlArea = 0x81,
	SystemCombinePhysicalMemoryInformation = 0x82,
	SystemEntropyInterruptTimingInformation = 0x83,
	SystemConsoleInformation = 0x84,
	SystemPlatformBinaryInformation = 0x85,
	SystemThrottleNotificationInformation = 0x86,
	SystemHypervisorProcessorCountInformation = 0x87,
	SystemDeviceDataInformation = 0x88,
	SystemDeviceDataEnumerationInformation = 0x89,
	SystemMemoryTopologyInformation = 0x8a,
	SystemMemoryChannelInformation = 0x8b,
	SystemBootLogoInformation = 0x8c,
	SystemProcessorPerformanceInformationEx = 0x8d,
	SystemSpare0 = 0x8e,
	SystemSecureBootPolicyInformation = 0x8f,
	SystemPageFileInformationEx = 0x90,
	SystemSecureBootInformation = 0x91,
	SystemEntropyInterruptTimingRawInformation = 0x92,
	SystemPortableWorkspaceEfiLauncherInformation = 0x93,
	SystemFullProcessInformation = 0x94,
	SystemKernelDebuggerInformationEx = 0x95,
	SystemBootMetadataInformation = 0x96,
	SystemSoftRebootInformation = 0x97,
	SystemElamCertificateInformation = 0x98,
	SystemOfflineDumpConfigInformation = 0x99,
	SystemProcessorFeaturesInformation = 0x9a,
	SystemRegistryReconciliationInformation = 0x9b,
	MaxSystemInfoClass = 0x9c,
} SYSTEM_INFORMATION_CLASS, * PSYSTEM_INFORMATION_CLASS;
 
typedef struct _REG_VALID {
	ULONGLONG TIMESPAN;
	int DAYS;
	ULONGLONG CTIME;
}REG_VALID, * PREG_VALID;

 

namespace Utils {

	//EXTERN_C_START
	PVOID GetFuncExportName(_In_ PVOID ModuleBase, _In_ PCHAR FuncName);
	USHORT GetServiceNoByName(_In_ PVOID ModuleBase, _In_ PCHAR FuncName);

	VOID SetKernelBase(ULONG_PTR ntoskrnl_base);

	PVOID GetKernelBase();
	uintptr_t GetNtFuncExportName(_In_ PCHAR FuncName);
	PVOID GetSystemInformation(const SYSTEM_INFORMATION_CLASS information_class);
	ULONG_PTR GetKernelModule(PCHAR szModuleName, PULONG imageSize);

	ULONGLONG GetWin32kFull();

	ULONGLONG GetWin32kBase();
 
	HANDLE GetPidByName(PWCH imageName);
	VOID InitApis();
	RTL_OSVERSIONINFOW InitOsVersion();
	INT kmemcmp(const void* s1, const void* s2, size_t n);
	PVOID kmemcpy(void* dest, const void* src, size_t len);
	PVOID kmemset(void* dest, UINT8 c, size_t count);
	char* kstrchr(const char* str, int character);
	char* kstrstr(const char* haystack, const char* needle);
	wchar_t* random_wstring(wchar_t* str, size_t size);
	wchar_t* kwcsstr(const wchar_t* haystack, const wchar_t* needle);
	//EXTERN_C_END

	bool pattern_check(const char* data, const char* pattern, const char* mask); 
	unsigned long long find_pattern(unsigned long long addr, unsigned long size, const char* pattern, const char* mask);
	unsigned long long find_pattern_image(unsigned long long addr, const char* pattern, const char* mask, const char* name);
	BOOLEAN safe_copy(PVOID dst, PVOID src, size_t size);
	BOOLEAN self_safe_copy(PEPROCESS self, PVOID dst, PVOID src, size_t size);
}

#endif // !UTILS_H