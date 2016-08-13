#pragma once

#ifndef SYSTEMINFODEF_H
#define SYSTEMINFODEF_H

#define STATUS_SUCCESS 0
#define NT_SUCCESS(Status) ((NTSTATUS)(Status) >= 0)
typedef LONG NTSTATUS;
typedef LONG KPRIORITY;

typedef struct _CLIENT_ID
{
	PVOID UniqueProcess;
	PVOID UniqueThread;
} CLIENT_ID, *PCLIENT_ID;

typedef struct _LSA_UNICODE_STRING {
	USHORT Length;			//字节长度
	USHORT MaximumLength;		//字节长度
	PWSTR  Buffer;
} LSA_UNICODE_STRING, *PLSA_UNICODE_STRING, UNICODE_STRING, *PUNICODE_STRING;

typedef struct _LDR_MODULE
{
	LIST_ENTRY InLoadOrderModuleList;
	LIST_ENTRY InMemoryOrderModuleList;
	LIST_ENTRY InInitializationOrderModuleList;
	PVOID BaseAddress;
	PVOID EntryPoint;
	ULONG SizeOfImage;
	UNICODE_STRING FullDllName;
	UNICODE_STRING BaseDllName;
	ULONG Flags;
	USHORT LoadCount;
	USHORT TlsIndex;
	LIST_ENTRY HashTableEntry;
	ULONG TimeDateStamp;
} LDR_MODULE, *PLDR_MODULE, *PLML;

//////////////////////////////////////////////////////////////////////////
//	线程预定义
//
typedef enum _THREADINFOCLASS {
	ThreadBasicInformation,
	ThreadTimes,
	ThreadPriority,
	ThreadBasePriority,
	ThreadAffinityMask,
	ThreadImpersonationToken,
	ThreadDescriptorTableEntry,
	ThreadEnableAlignmentFaultFixup,
	ThreadEventPair_Reusable,
	ThreadQuerySetWin32StartAddress,
	ThreadZeroTlsCell,
	ThreadPerformanceCount,
	ThreadAmILastThread,
	ThreadIdealProcessor,
	ThreadPriorityBoost,
	ThreadSetTlsArrayAddress,   // Obsolete  
	ThreadIsIoPending,
	ThreadHideFromDebugger,
	ThreadBreakOnTermination,
	ThreadSwitchLegacyState,
	ThreadIsTerminated,
	ThreadLastSystemCall,
	ThreadIoPriority,
	ThreadCycleTime,
	ThreadPagePriority,
	ThreadActualBasePriority,
	ThreadTebInformation,
	ThreadCSwitchMon,          // Obsolete  
	ThreadCSwitchPmu,
	ThreadWow64Context,
	ThreadGroupInformation,
	ThreadUmsInformation,      // UMS  
	ThreadCounterProfiling,
	ThreadIdealProcessorEx,
	MaxThreadInfoClass
} THREADINFOCLASS;

//MEMORY_INFORMATION_CLASS定义  
typedef enum _MEMORY_INFORMATION_CLASS
{
	MemoryBasicInformation,          //内存基本信息  
	MemoryWorkingSetInformation,       //工作集信息  
	MemoryMappedFilenameInformation,    //内存映射文件名信息
	MemoryBasicVlmInformation
} MEMORY_INFORMATION_CLASS;

// typedef struct _MEMORY_BASIC_INFORMATION {
// 	PVOID       BaseAddress;
// 	PVOID       AllocationBase;
// 	DWORD       AllocationProtect;
// 	SIZE_T      RegionSize;
// 	DWORD       State;
// 	DWORD       Protect;
// 	DWORD       Type;
// } MEMORY_BASIC_INFORMATION, *PMEMORY_BASIC_INFORMATION;

typedef struct
{
	UNICODE_STRING SectionFileName;
	WCHAR       NameBuffer[MAX_PATH * 5];
} MEMORY_SECTION_NAME, *PMEMORY_SECTION_NAME;

typedef struct _MEMORY_WORKING_SET_INFORMATION {
	ULONG       SizeOfWorkingSet;
	DWORD       WsEntries[ANYSIZE_ARRAY];
} MEMORY_WORKING_SET_INFORMATION, *PMEMORY_WORKING_SET_INFORMATION;

#define _MAX_OBJECT_NAME 1024/sizeof(WCHAR)  
typedef struct _MEMORY_MAPPED_FILE_NAME_INFORMATION {
	UNICODE_STRING Name;
	WCHAR     Buffer[_MAX_OBJECT_NAME];
} MEMORY_MAPPED_FILE_NAME_INFORMATION, *PMEMORY_MAPPED_FILE_NAME_INFORMATION;

typedef   struct   _THREAD_BASIC_INFORMATION   {
	LONG        ExitStatus;
	PVOID       TebBaseAddress;
	CLIENT_ID   ClientId;
	LONG        AffinityMask;
	LONG        Priority;
	LONG        BasePriority;
}   THREAD_BASIC_INFORMATION, *PTHREAD_BASIC_INFORMATION;


typedef LONG(WINAPI *ZwQueryInformationThread)(
	_In_      HANDLE          ThreadHandle,
	_In_      THREADINFOCLASS ThreadInformationClass,
	_Inout_   PVOID           ThreadInformation,
	_In_      ULONG           ThreadInformationLength,
	_Out_opt_ PULONG          ReturnLength
	);

typedef NTSTATUS (NTAPI *ZwSetInformationThread)(
	__in HANDLE ThreadHandle,
	__in THREADINFOCLASS ThreadInformationClass,
	__in_bcount(ThreadInformationLength) PVOID ThreadInformation,
	__in ULONG ThreadInformationLength
	);

typedef LONG(WINAPI *ZwSuspendThread)(
	_In_		HANDLE hThreadHandle,
	_Out_	PULONG pSuspendCount
	);


typedef struct
{
	DWORD ExitStatus; // 接收进程终止状态
	DWORD PebBaseAddress; // 接收进程环境块地址
	DWORD AffinityMask; // 接收进程关联掩码
	DWORD BasePriority; // 接收进程的优先级类
	ULONG UniqueProcessId; // 接收进程ID
	ULONG InheritedFromUniqueProcessId; //接收父进程ID
} PROCESS_BASIC_INFORMATION;

typedef struct _OBJECT_ATTRIBUTES {
	ULONG Length;
	HANDLE RootDirectory;
	PUNICODE_STRING ObjectName;
	ULONG Attributes;
	PVOID SecurityDescriptor;
	PVOID SecurityQualityOfService;
} OBJECT_ATTRIBUTES, *POBJECT_ATTRIBUTES;

typedef enum _PROCESSINFOCLASS {
	ProcessBasicInformation,
	ProcessQuotaLimits,
	ProcessIoCounters,
	ProcessVmCounters,
	ProcessTimes,
	ProcessBasePriority,
	ProcessRaisePriority,
	ProcessDebugPort,
	ProcessExceptionPort,
	ProcessAccessToken,
	ProcessLdtInformation,
	ProcessLdtSize,
	ProcessDefaultHardErrorMode,
	ProcessIoPortHandlers,
	ProcessPooledUsageAndLimits,
	ProcessWorkingSetWatch,
	ProcessUserModeIOPL,
	ProcessEnableAlignmentFaultFixup,
	ProcessPriorityClass,
	ProcessWx86Information,
	ProcessHandleCount,
	ProcessAffinityMask,
	ProcessPriorityBoost,
	ProcessDeviceMap,
	ProcessSessionInformation,
	ProcessForegroundInformation,
	ProcessWow64Information,
	ProcessImageFileName,
	ProcessLUIDDeviceMapsEnabled,
	ProcessBreakOnTermination,
	ProcessDebugObjectHandle,
	ProcessDebugFlags,
	ProcessHandleTracing,
	ProcessIoPriority,
	ProcessExecuteFlags,
	ProcessResourceManagement,
	ProcessCookie,
	ProcessImageInformation,
	MaxProcessInfoClass
} PROCESSINFOCLASS;


typedef NTSTATUS(WINAPI *ZwQueryInformationProcess)(
	_In_      HANDLE           ProcessHandle,
	_In_      PROCESSINFOCLASS ProcessInformationClass,
	_Out_     PVOID            ProcessInformation,
	_In_      ULONG            ProcessInformationLength,
	_Out_opt_ PULONG           ReturnLength
	);

typedef enum _EVENT_TYPE {
	NotificationEvent,
	SynchronizationEvent
} EVENT_TYPE;

typedef enum _SYSTEM_INFORMATION_CLASS {
	SystemBasicInformation,
	SystemProcessorInformation,
	SystemPerformanceInformation,
	SystemTimeOfDayInformation,
	SystemPathInformation,
	SystemProcessInformation,
	SystemCallCountInformation,
	SystemDeviceInformation,
	SystemProcessorPerformanceInformation,
	SystemFlagsInformation,
	SystemCallTimeInformation,
	SystemModuleInformation,
	SystemLocksInformation,
	SystemStackTraceInformation,
	SystemPagedPoolInformation,
	SystemNonPagedPoolInformation,
	SystemHandleInformation,
	SystemObjectInformation,
	SystemPageFileInformation,
	SystemVdmInstemulInformation,
	SystemVdmBopInformation,
	SystemFileCacheInformation,
	SystemPoolTagInformation,
	SystemInterruptInformation,
	SystemDpcBehaviorInformation,
	SystemFullMemoryInformation,
	SystemLoadGdiDriverInformation,
	SystemUnloadGdiDriverInformation,
	SystemTimeAdjustmentInformation,
	SystemSummaryMemoryInformation,
	SystemMirrorMemoryInformation,
	SystemPerformanceTraceInformation,
	SystemObsolete0,
	SystemExceptionInformation,
	SystemCrashDumpStateInformation,
	SystemKernelDebuggerInformation,
	SystemContextSwitchInformation,
	SystemRegistryQuotaInformation,
	SystemExtendServiceTableInformation,
	SystemPrioritySeperation,
	SystemVerifierAddDriverInformation,
	SystemVerifierRemoveDriverInformation,
	SystemProcessorIdleInformation,
	SystemLegacyDriverInformation,
	SystemCurrentTimeZoneInformation,
	SystemLookasideInformation,
	SystemTimeSlipNotification,
	SystemSessionCreate,
	SystemSessionDetach,
	SystemSessionInformation,
	SystemRangeStartInformation,
	SystemVerifierInformation,
	SystemVerifierThunkExtend,
	SystemSessionProcessInformation,
	SystemLoadGdiDriverInSystemSpace,
	SystemNumaProcessorMap,
	SystemPrefetcherInformation,
	SystemExtendedProcessInformation,
	SystemRecommendedSharedDataAlignment,
	SystemComPlusPackage,
	SystemNumaAvailableMemory,
	SystemProcessorPowerInformation,
	SystemEmulationBasicInformation,
	SystemEmulationProcessorInformation,
	SystemExtendedHandleInformation,
	SystemLostDelayedWriteInformation,
	SystemBigPoolInformation,
	SystemSessionPoolTagInformation,
	SystemSessionMappedViewInformation,
	SystemHotpatchInformation,
	SystemObjectSecurityMode,
	SystemWatchdogTimerHandler,
	SystemWatchdogTimerInformation,
	SystemLogicalProcessorInformation,
	SystemWow64SharedInformation,
	SystemRegisterFirmwareTableInformationHandler,
	SystemFirmwareTableInformation,
	SystemModuleInformationEx,
	SystemVerifierTriageInformation,
	SystemSuperfetchInformation,
	SystemMemoryListInformation,
	SystemFileCacheInformationEx,
	MaxSystemInfoClass
} SYSTEM_INFORMATION_CLASS, *PSYSTEM_INFORMATION_CLASS;

typedef enum _THREAD_STATE
{
	StateInitialized,
	StateReady,
	StateRunning,
	StateStandby,
	StateTerminated,
	StateWait,
	StateTransition,
	StateUnknown
}THREAD_STATE;

typedef enum _KWAIT_REASON
{
	Executive = 0,
	FreePage = 1,
	PageIn = 2,
	PoolAllocation = 3,
	DelayExecution = 4,
	Suspended = 5,
	UserRequest = 6,
	WrExecutive = 7,
	WrFreePage = 8,
	WrPageIn = 9,
	WrPoolAllocation = 10,
	WrDelayExecution = 11,
	WrSuspended = 12,
	WrUserRequest = 13,
	WrEventPair = 14,
	WrQueue = 15,
	WrLpcReceive = 16,
	WrLpcReply = 17,
	WrVirtualMemory = 18,
	WrPageOut = 19,
	WrRendezvous = 20,
	Spare2 = 21,
	Spare3 = 22,
	Spare4 = 23,
	Spare5 = 24,
	WrCalloutStack = 25,
	WrKernel = 26,
	WrResource = 27,
	WrPushLock = 28,
	WrMutex = 29,
	WrQuantumEnd = 30,
	WrDispatchInt = 31,
	WrPreempted = 32,
	WrYieldExecution = 33,
	WrFastMutex = 34,
	WrGuardedMutex = 35,
	WrRundown = 36,
	MaximumWaitReason = 37
} KWAIT_REASON;

typedef struct _VM_COUNTERS {
	SIZE_T        PeakVirtualSize;
	SIZE_T        VirtualSize;
	ULONG        PageFaultCount;
	SIZE_T        PeakWorkingSetSize;
	SIZE_T        WorkingSetSize;
	SIZE_T        QuotaPeakPagedPoolUsage;
	SIZE_T        QuotaPagedPoolUsage;
	SIZE_T        QuotaPeakNonPagedPoolUsage;
	SIZE_T        QuotaNonPagedPoolUsage;
	SIZE_T        PagefileUsage;
	SIZE_T        PeakPagefileUsage;
}VM_COUNTERS;

typedef struct _SYSTEM_THREAD_INFORMATION {
	LARGE_INTEGER KernelTime;
	LARGE_INTEGER UserTime;
	LARGE_INTEGER CreateTime;
	ULONG WaitTime;
	PVOID StartAddress;
	CLIENT_ID ClientId;
	KPRIORITY Priority;
	LONG BasePriority;
	ULONG ContextSwitchCount;
	ULONG ThreadState;
	KWAIT_REASON WaitReason;
}SYSTEM_THREAD_INFORMATION, *PSYSTEM_THREAD_INFORMATION;

typedef struct _SYSTEM_EXTENDED_THREAD_INFORMATION
{
	SYSTEM_THREAD_INFORMATION ThreadInfo;
	PVOID StackBase;
	PVOID StackLimit;
	PVOID Win32StartAddress;
	PVOID TebAddress; /* This is only filled in on Vista and above */
	ULONG Reserved1;
	ULONG Reserved2;
	ULONG Reserved3;
} SYSTEM_EXTENDED_THREAD_INFORMATION, *PSYSTEM_EXTENDED_THREAD_INFORMATION;

typedef struct _SYSTEM_HANDLE_TABLE_ENTRY_INFO
{
	USHORT UniqueProcessId;
	USHORT CreatorBackTraceIndex;
	UCHAR ObjectTypeIndex;
	UCHAR HandleAttributes;
	USHORT HandleValue;
	PVOID Object;
	ULONG GrantedAccess;
} SYSTEM_HANDLE_TABLE_ENTRY_INFO, *PSYSTEM_HANDLE_TABLE_ENTRY_INFO;

typedef enum _OBJECT_INFORMATION_CLASS {
	ObjectBasicInformation,
	ObjectNameInformation,
	ObjectTypeInformation,
	ObjectAllInformation,
	ObjectDataInformation
} OBJECT_INFORMATION_CLASS, *POBJECT_INFORMATION_CLASS;

typedef struct _OBJECT_BASIC_INFORMATION {
	ULONG Attributes;
	ACCESS_MASK DesiredAccess;
	ULONG HandleCount;
	ULONG ReferenceCount;
	ULONG PagedPoolUsage;
	ULONG NonPagedPoolUsage;
	ULONG Reserved[3];
	ULONG NameInformationLength;
	ULONG TypeInformationLength;
	ULONG SecurityDescriptorLength;
	LARGE_INTEGER CreationTime;
} OBJECT_BASIC_INFORMATION, *POBJECT_BASIC_INFORMATION;

typedef struct __PUBLIC_OBJECT_TYPE_INFORMATION {
	UNICODE_STRING TypeName;
	ULONG          Reserved[22];
} PUBLIC_OBJECT_TYPE_INFORMATION, *PPUBLIC_OBJECT_TYPE_INFORMATION;

typedef struct _SYSTEM_HANDLE_INFORMATION
{
	ULONG NumberOfHandles;
	SYSTEM_HANDLE_TABLE_ENTRY_INFO Handles[1];
} SYSTEM_HANDLE_INFORMATION, *PSYSTEM_HANDLE_INFORMATION;

typedef struct _SYSTEM_PROCESS_INFORMATION {
	ULONG                   NextEntryOffset;
	ULONG                   NumberOfThreads;
	LARGE_INTEGER           Reserved[3];
	LARGE_INTEGER           CreateTime;
	LARGE_INTEGER           UserTime;
	LARGE_INTEGER           KernelTime;
	UNICODE_STRING          ImageName;
	KPRIORITY               BasePriority;
	UINT_PTR                  ProcessId;		//进程ID
	UINT_PTR                  InheritedFromProcessId;		//父进程ID
	ULONG                   HandleCount;
	ULONG                   Reserved2[2];
	ULONG                   PrivatePageCount;
	VM_COUNTERS             VirtualMemoryCounters;
	IO_COUNTERS             IoCounters;
#ifdef _WIN64
	UINT_PTR Reserved3;
#endif // _WIN64
	SYSTEM_THREAD_INFORMATION           Threads[1];
} SYSTEM_PROCESS_INFORMATION, *PSYSTEM_PROCESS_INFORMATION;

typedef struct _SYSTEM_EXTENDED_PROCESS_INFORMATION
{
	ULONG NextEntryOffset;
	ULONG NumberOfThreads;
	LARGE_INTEGER SpareLi1;
	LARGE_INTEGER SpareLi2;
	LARGE_INTEGER SpareLi3;
	LARGE_INTEGER CreateTime;
	LARGE_INTEGER UserTime;
	LARGE_INTEGER KernelTime;
	UNICODE_STRING ImageName;
	KPRIORITY BasePriority;
	ULONG ProcessId;
	ULONG InheritedFromUniqueProcessId;
	ULONG HandleCount;
	ULONG SessionId;
	PVOID PageDirectoryBase;
	VM_COUNTERS VirtualMemoryCounters;
	SIZE_T PrivatePageCount;
	IO_COUNTERS IoCounters;
	SYSTEM_EXTENDED_THREAD_INFORMATION Threads[1];
} SYSTEM_EXTENDED_PROCESS_INFORMATION, *PSYSTEM_EXTENDED_PROCESS_INFORMATION;


typedef 
NTSTATUS
(WINAPI 
*ZwQuerySystemInformation)(
	_In_      SYSTEM_INFORMATION_CLASS SystemInformationClass,
	_Inout_   PVOID                    SystemInformation,
	_In_      ULONG                    SystemInformationLength,
	_Out_opt_ PULONG                   ReturnLength
	);

typedef
NTSTATUS
(
NTAPI
*ZwOpenProcess)
(
OUT PHANDLE            ProcessHandle,
IN ACCESS_MASK          AccessMask,
IN POBJECT_ATTRIBUTES  ObjectAttributes,
IN PCLIENT_ID          ClientId
);

typedef
NTSTATUS
(NTAPI
*ZwDuplicateObject)(
_In_      HANDLE      SourceProcessHandle,
_In_      HANDLE      SourceHandle,
_In_opt_  HANDLE      TargetProcessHandle,
_Out_opt_ PHANDLE     TargetHandle,
_In_      ACCESS_MASK DesiredAccess,
_In_      ULONG       HandleAttributes,
_In_      ULONG       Options
);

typedef
NTSTATUS
(NTAPI
*ZwQueryObject)
(
_In_opt_  HANDLE                   Handle,
_In_      OBJECT_INFORMATION_CLASS ObjectInformationClass,
_Out_opt_ PVOID                    ObjectInformation,
_In_      ULONG                    ObjectInformationLength,
_Out_opt_ PULONG                   ReturnLength
);

typedef
NTSTATUS
(WINAPI
*ZwClose)
(
_In_ HANDLE Handle
);

typedef 
NTSTATUS
(NTAPI 
*ZwCreateThreadEx)(
	OUT PHANDLE ThreadHandle,
	IN ACCESS_MASK DesiredAccess,
	IN POBJECT_ATTRIBUTES ObjectAttributes,
	IN HANDLE ProcessHandle,
	IN LPVOID lpStartAddress,
	IN LPVOID lpParameter,
	IN BOOL CreateSuspended,
	IN ULONG StackZeroBits,
	IN ULONG SizeOfStackCommit,
	IN ULONG SizeOfStackReserve,
	OUT LPVOID lpBytesBuffer
	);

typedef 
NTSTATUS
(WINAPI 
*ZwResumeThread)(
	IN HANDLE ThreadHandle,
	OUT PULONG PreviousSuspendCount OPTIONAL
	);

typedef
NTSTATUS (NTAPI *ZwQueryVirtualMemory)(
	IN HANDLE                  ProcessHandle,                 //目标进程句柄  
	IN PVOID                  BaseAddress,               //目标内存地址  
	IN MEMORY_INFORMATION_CLASS  MemoryInformationClass,       //查询内存信息的类别  
	OUT PVOID                  Buffer,                      //用于存储获取到的内存信息的结构地址  
	IN ULONG                  Length,                      //Buffer的最大长度  
	OUT PULONG                  ResultLength OPTIONAL);        //存储该函数处理返回的信息的长度的ULONG的地址   

typedef
NTSTATUS
(WINAPI
*ZwUnmapViewOfSection) (
_In_     HANDLE ProcessHandle,
_In_	 PVOID  BaseAddress
);

typedef NTSTATUS(NTAPI *ZwReadVirtualMemory)(
	IN HANDLE ProcessHandle,
	IN PVOID BaseAddress,
	OUT PVOID Buffer,
	IN ULONG BufferLength,
	OUT PULONG ReturnLength OPTIONAL
	);

#endif
