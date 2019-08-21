#pragma once
#pragma region NT_Types

typedef enum _MEMORY_INFORMATION_CLASS {
	MemoryBasicInformation
} MEMORY_INFORMATION_CLASS;

//typedef struct _UNICODE_STRING {
//	USHORT Length;
//	USHORT MaximumLength;
//	PWSTR  Buffer;
//} UNICODE_STRING;
typedef UNICODE_STRING *PUNICODE_STRING;
typedef const UNICODE_STRING *PCUNICODE_STRING;

//typedef struct _RTL_USER_PROCESS_PARAMETERS {
//	BYTE Reserved1[16];
//	PVOID Reserved2[10];
//	UNICODE_STRING ImagePathName;
//	UNICODE_STRING CommandLine;
//} RTL_USER_PROCESS_PARAMETERS, *PRTL_USER_PROCESS_PARAMETERS;

//typedef struct _PEB_LDR_DATA {
//	BYTE Reserved1[8];
//	PVOID Reserved2[3];
//	LIST_ENTRY InMemoryOrderModuleList;
//} PEB_LDR_DATA, *PPEB_LDR_DATA;

typedef
VOID
( NTAPI *PPS_POST_PROCESS_INIT_ROUTINE ) (
	VOID
	);

//typedef struct _PEB {
//	BYTE Reserved1[2];
//	BYTE BeingDebugged;
//	BYTE Reserved2[1];
//	PVOID Reserved3[2];
//	PPEB_LDR_DATA Ldr;
//	PRTL_USER_PROCESS_PARAMETERS ProcessParameters;
//	PVOID Reserved4[3];
//	PVOID AtlThunkSListPtr;
//	PVOID Reserved5;
//	ULONG Reserved6;
//	PVOID Reserved7;
//	ULONG Reserved8;
//	ULONG AtlThunkSListPtr32;
//	PVOID Reserved9[45];
//	BYTE Reserved10[96];
//	PPS_POST_PROCESS_INIT_ROUTINE PostProcessInitRoutine;
//	BYTE Reserved11[128];
//	PVOID Reserved12[1];
//	ULONG SessionId;
//} PEB, *PPEB;

//typedef struct _TEB {
//	PVOID Reserved1[12];
//	PPEB ProcessEnvironmentBlock;
//	PVOID Reserved2[399];
//	BYTE Reserved3[1952];
//	PVOID TlsSlots[64];
//	BYTE Reserved4[8];
//	PVOID Reserved5[26];
//	PVOID ReservedForOle;  // Windows 2000 only
//	PVOID Reserved6[4];
//	PVOID TlsExpansionSlots;
//} TEB, *PTEB;

//typedef enum _PROCESSINFOCLASS {
//	ProcessBasicInformation = 0,
//	ProcessDebugPort = 7,
//	ProcessWow64Information = 26,
//	ProcessImageFileName = 27,
//	ProcessBreakOnTermination = 29
//} PROCESSINFOCLASS;

typedef enum _THREAD_INFO_CLASS_ {
	ThreadBasicInformation,
	ThreadTimes,
	ThreadPriority,
	ThreadBasePriority,
	ThreadAffinityMask,
	ThreadImpersonationToken,
	ThreadDescriptorTableEntry,
	ThreadEnableAlignmentFaultFixup,
	ThreadEventPair,
	ThreadQuerySetWin32StartAddress,
	ThreadZeroTlsCell,
	ThreadPerformanceCount,
	ThreadAmILastThread,
	ThreadIdealProcessor,
	ThreadPriorityBoost,
	ThreadSetTlsArrayAddress,
	//ThreadIsIoPending,
	ThreadHideFromDebugger
} THREAD_INFO_CLASS_, *PTHREAD_INFO_CLASS_;

//typedef struct _PROCESS_BASIC_INFORMATION {
//	PVOID Reserved1;
//	PPEB PebBaseAddress;
//	PVOID Reserved2[2];
//	ULONG_PTR UniqueProcessId;
//	PVOID Reserved3;
//} PROCESS_BASIC_INFORMATION;
//typedef PROCESS_BASIC_INFORMATION *PPROCESS_BASIC_INFORMATION;

typedef unsigned short RTL_ATOM, *PRTL_ATOM;
typedef struct atom_table *RTL_ATOM_TABLE, **PRTL_ATOM_TABLE;

typedef enum _KEY_INFORMATION_CLASS {
	KeyBasicInformation,
	KeyNodeInformation,
	KeyFullInformation,
	KeyNameInformation,
	KeyCachedInformation,
	KeyFlagsInformation,
	KeyVirtualizationInformation,
	KeyHandleTagsInformation,
	KeyTrustInformation,
	KeyLayerInformation,
	MaxKeyInfoClass
} KEY_INFORMATION_CLASS;

typedef enum _KEY_VALUE_INFORMATION_CLASS {
	KeyValueBasicInformation,
	KeyValueFullInformation,
	KeyValuePartialInformation,
	KeyValueFullInformationAlign64,
	KeyValuePartialInformationAlign64,
	KeyValueLayerInformation,
	MaxKeyValueInfoClass
} KEY_VALUE_INFORMATION_CLASS;

typedef enum _KPROFILE_SOURCE {
	ProfileTime,
	ProfileAlignmentFixup,
	ProfileTotalIssues,
	ProfilePipelineDry,
	ProfileLoadInstructions,
	ProfilePipelineFrozen,
	ProfileBranchInstructions,
	ProfileTotalNonissues,
	ProfileDcacheMisses,
	ProfileIcacheMisses,
	ProfileCacheMisses,
	ProfileBranchMispredictions,
	ProfileStoreInstructions,
	ProfileFpInstructions,
	ProfileIntegerInstructions,
	Profile2Issue,
	Profile3Issue,
	Profile4Issue,
	ProfileSpecialInstructions,
	ProfileTotalCycles,
	ProfileIcacheIssues,
	ProfileDcacheAccesses,
	ProfileMemoryBarrierCycles,
	ProfileLoadLinkedIssues,
	ProfileMaximum
} KPROFILE_SOURCE, *PKPROFILE_SOURCE;

typedef enum _MUTANT_INFORMATION_CLASS
{
	MutantBasicInformation
} MUTANT_INFORMATION_CLASS, *PMUTANT_INFORMATION_CLASS;

typedef struct _INITIAL_TEB {
	PVOID                StackBase;
	PVOID                StackLimit;
	PVOID                StackCommit;
	PVOID                StackCommitMax;
	PVOID                StackReserved;
} INITIAL_TEB, *PINITIAL_TEB;

typedef enum _SECTION_INHERIT {
	ViewShare = 1,
	ViewUnmap = 2
} SECTION_INHERIT, *PSECTION_INHERIT;

typedef struct _FILE_BASIC_INFORMATION {
	LARGE_INTEGER           CreationTime;
	LARGE_INTEGER           LastAccessTime;
	LARGE_INTEGER           LastWriteTime;
	LARGE_INTEGER           ChangeTime;
	ULONG                   FileAttributes;
} FILE_BASIC_INFORMATION, *PFILE_BASIC_INFORMATION;

typedef struct _OBJDIR_INFORMATION {
	UNICODE_STRING          ObjectName;
	UNICODE_STRING          ObjectTypeName;
	BYTE                    Data[1];
} OBJDIR_INFORMATION, *POBJDIR_INFORMATION;

typedef enum _EVENT_INFORMATION_CLASS {
	EventBasicInformation
} EVENT_INFORMATION_CLASS, *PEVENT_INFORMATION_CLASS;

typedef enum _ATOM_INFORMATION_CLASS {
	AtomBasicInformation,
	AtomTableInformation
} ATOM_INFORMATION_CLASS, *PATOM_INFORMATION_CLASS;

typedef enum _PORT_INFORMATION_CLASS {
	PortNoInformation
} PORT_INFORMATION_CLASS, *PPORT_INFORMATION_CLASS;

typedef enum _IO_COMPLETION_INFORMATION_CLASS {
	IoCompletionBasicInformation
} IO_COMPLETION_INFORMATION_CLASS, *PIO_COMPLETION_INFORMATION_CLASS;

typedef struct _KEY_MULTIPLE_VALUE_INFORMATION {
	PUNICODE_STRING         ValueName;
	ULONG                   DataLength;
	ULONG                   DataOffset;
	ULONG                   Type;
} KEY_MULTIPLE_VALUE_INFORMATION, *PKEY_MULTIPLE_VALUE_INFORMATION;

typedef enum _SECTION_INFORMATION_CLASS {
	SectionBasicInformation,
	SectionImageInformation
} SECTION_INFORMATION_CLASS, *PSECTION_INFORMATION_CLASS;

typedef enum _SEMAPHORE_INFORMATION_CLASS {
	SemaphoreBasicInformation
} SEMAPHORE_INFORMATION_CLASS, *PSEMAPHORE_INFORMATION_CLASS;

typedef enum _FS_INFORMATION_CLASS {
	FileFsVolumeInformation = 1,
	FileFsLabelInformation,
	FileFsSizeInformation,
	FileFsDeviceInformation,
	FileFsAttributeInformation,
	FileFsControlInformation,
	FileFsFullSizeInformation,
	FileFsObjectIdInformation,
	FileFsMaximumInformation
} FS_INFORMATION_CLASS, *PFS_INFORMATION_CLASS;

typedef enum _TIMER_INFORMATION_CLASS {
	TimerBasicInformation
} TIMER_INFORMATION_CLASS, *PTIMER_INFORMATION_CLASS;

typedef enum _HARDERROR_RESPONSE_OPTION {
	OptionAbortRetryIgnore,
	OptionOk,
	OptionOkCancel,
	OptionRetryCancel,
	OptionYesNo,
	OptionYesNoCancel,
	OptionShutdownSystem
} HARDERROR_RESPONSE_OPTION, *PHARDERROR_RESPONSE_OPTION;

typedef enum _HARDERROR_RESPONSE {
	ResponseReturnToCaller,
	ResponseNotHandled,
	ResponseAbort,
	ResponseCancel,
	ResponseIgnore,
	ResponseNo,
	ResponseOk,
	ResponseRetry,
	ResponseYes
} HARDERROR_RESPONSE, *PHARDERROR_RESPONSE;

typedef void( *PTIMER_APC_ROUTINE )(IN PVOID TimerContext, IN ULONG TimerLowValue, IN LONG TimerHighValue);

typedef enum _SHUTDOWN_ACTION {
	ShutdownNoReboot,
	ShutdownReboot,
	ShutdownPowerOff
} SHUTDOWN_ACTION, *PSHUTDOWN_ACTION;

typedef enum _SYSDBG_COMMAND {
	SysDbgQueryModuleInformation = 1,
	SysDbgQueryTraceInformation,
	SysDbgSetTracepoint,
	SysDbgSetSpecialCall,
	SysDbgClearSpecialCalls,
	SysDbgQuerySpecialCalls
} SYSDBG_COMMAND, *PSYSDBG_COMMAND;

typedef enum _OBJECT_WAIT_TYPE {
	WaitAllObject,
	WaitAnyObject
} OBJECT_WAIT_TYPE, *POBJECT_WAIT_TYPE;

typedef enum _TIMER_TYPE {
	NotificationTimer,
	SynchronizationTimer
} TIMER_TYPE;

//typedef enum _FILE_INFORMATION_CLASS {
//	FileDirectoryInformation = 1,
//	FileFullDirectoryInformation,
//	FileBothDirectoryInformation,
//	FileBasicInformation,
//	FileStandardInformation,
//	FileInternalInformation,
//	FileEaInformation,
//	FileAccessInformation,
//	FileNameInformation,
//	FileRenameInformation,
//	FileLinkInformation,
//	FileNamesInformation,
//	FileDispositionInformation,
//	FilePositionInformation,
//	FileFullEaInformation,
//	FileModeInformation,
//	FileAlignmentInformation,
//	FileAllInformation,
//	FileAllocationInformation,
//	FileEndOfFileInformation,
//	FileAlternateNameInformation,
//	FileStreamInformation,
//	FilePipeInformation,
//	FilePipeLocalInformation,
//	FilePipeRemoteInformation,
//	FileMailslotQueryInformation,
//	FileMailslotSetInformation,
//	FileCompressionInformation,
//	FileCopyOnWriteInformation,
//	FileCompletionInformation,
//	FileMoveClusterInformation,
//	FileQuotaInformation,
//	FileReparsePointInformation,
//	FileNetworkOpenInformation,
//	FileObjectIdInformation,
//	FileTrackingInformation,
//	FileOleDirectoryInformation,
//	FileContentIndexInformation,
//	FileInheritContentIndexInformation,
//	FileOleInformation,
//	FileMaximumInformation
//} FILE_INFORMATION_CLASS, *PFILE_INFORMATION_CLASS;


//typedef enum _OBJECT_INFORMATION_CLASS {
//	ObjectBasicInformation,
//	ObjectNameInformation,
//	ObjectTypeInformation,
//	ObjectAllInformation,
//	ObjectDataInformation
//} OBJECT_INFORMATION_CLASS, *POBJECT_INFORMATION_CLASS;

//typedef enum _SYSTEM_INFORMATION_CLASS {
//	SystemBasicInformation,
//	SystemProcessorInformation,
//	SystemPerformanceInformation,
//	SystemTimeOfDayInformation,
//	SystemPathInformation,
//	SystemProcessInformation,
//	SystemCallCountInformation,
//	SystemDeviceInformation,
//	SystemProcessorPerformanceInformation,
//	SystemFlagsInformation,
//	SystemCallTimeInformation,
//	SystemModuleInformation,
//	SystemLocksInformation,
//	SystemStackTraceInformation,
//	SystemPagedPoolInformation,
//	SystemNonPagedPoolInformation,
//	SystemHandleInformation,
//	SystemObjectInformation,
//	SystemPageFileInformation,
//	SystemVdmInstemulInformation,
//	SystemVdmBopInformation,
//	SystemFileCacheInformation,
//	SystemPoolTagInformation,
//	SystemInterruptInformation,
//	SystemDpcBehaviorInformation,
//	SystemFullMemoryInformation,
//	SystemLoadGdiDriverInformation,
//	SystemUnloadGdiDriverInformation,
//	SystemTimeAdjustmentInformation,
//	SystemSummaryMemoryInformation,
//	SystemNextEventIdInformation,
//	SystemEventIdsInformation,
//	SystemCrashDumpInformation,
//	SystemExceptionInformation,
//	SystemCrashDumpStateInformation,
//	SystemKernelDebuggerInformation,
//	SystemContextSwitchInformation,
//	SystemRegistryQuotaInformation,
//	SystemExtendServiceTableInformation,
//	SystemPrioritySeperation,
//	SystemPlugPlayBusInformation,
//	SystemDockInformation,
//	SystemPowerInfo,
//	SystemProcessorSpeedInformation,
//	SystemCurrentTimeZoneInformation,
//	SystemLookasideInformation
//} SYSTEM_INFORMATION_CLASS, *PSYSTEM_INFORMATION_CLASS;

//typedef enum _KEY_SET_INFORMATION_CLASS {
//	KeyWriteTimeInformation,
//	KeyWow64FlagsInformation,
//	KeyControlFlagsInformation,
//	KeySetVirtualizationInformation,
//	KeySetDebugInformation,
//	KeySetHandleTagsInformation,
//	KeySetLayerInformation,
//	MaxKeySetInfoClass  // MaxKeySetInfoClass should always be the last enum
//} KEY_SET_INFORMATION_CLASS;

//typedef struct _OBJECT_ATTRIBUTES {
//	ULONG           Length;
//	HANDLE          RootDirectory;
//	PUNICODE_STRING ObjectName;
//	ULONG           Attributes;
//	PVOID           SecurityDescriptor;
//	PVOID           SecurityQualityOfService;
//} OBJECT_ATTRIBUTES, *POBJECT_ATTRIBUTES;

//typedef struct _CLIENT_ID
//{
//	PVOID UniqueProcess;
//	PVOID UniqueThread;
//} CLIENT_ID_, *PCLIENT_ID_;
//
//typedef struct _TOKEN_GROUPS {
//	DWORD              GroupCount;
//	SID_AND_ATTRIBUTES *Groups[];
//} TOKEN_GROUPS, *PTOKEN_GROUPS;

typedef DWORD EVENT_TYPE;
typedef void* PLPC_MESSAGE;
typedef void* PLPC_SECTION_MEMORY;
typedef void* PLPC_SECTION_OWNER_MEMORY;
typedef void* PCLIENT_ID;
//typedef void* POBJECT_ATTRIBUTES;
//typedef void* PIO_STATUS_BLOCK;
//typedef void* PIO_APC_ROUTINE;

#ifdef NTAPI
#undef NTAPI
#endif

#ifdef _WIN64
#define NTAPI __fastcall
#else
#define NTAPI __stdcall
#endif

#pragma endregion

#pragma region NtFuncTypes

using fnNtAcceptConnectPort = NTSTATUS( NTAPI* )(OUT PHANDLE ServerPortHandle, IN HANDLE AlternativeReceivePortHandle, IN PLPC_MESSAGE ConnectionReply, IN BOOLEAN AcceptConnection, IN OUT PLPC_SECTION_OWNER_MEMORY ServerSharedMemory, OUT PLPC_SECTION_MEMORY ClientSharedMemory);
using fnNtAccessCheck = NTSTATUS( NTAPI* )(IN PSECURITY_DESCRIPTOR SecurityDescriptor, IN HANDLE ClientToken, IN ACCESS_MASK DesiredAccess, IN PGENERIC_MAPPING GenericMapping, OUT PPRIVILEGE_SET RequiredPrivilegesBuffer, IN OUT PULONG BufferLength, OUT PACCESS_MASK GrantedAccess, OUT PNTSTATUS AccessStatus);
using fnNtAccessCheckAndAuditAlarm = NTSTATUS( NTAPI* )(IN PUNICODE_STRING SubsystemName, IN HANDLE ObjectHandle, IN PUNICODE_STRING ObjectTypeName, IN PUNICODE_STRING ObjectName, IN PSECURITY_DESCRIPTOR SecurityDescriptor, IN ACCESS_MASK DesiredAccess, IN PGENERIC_MAPPING GenericMapping, IN BOOLEAN ObjectCreation, OUT PULONG GrantedAccess, OUT PULONG AccessStatus, OUT PBOOLEAN GenerateOnClose);
using fnNtAddAtom = NTSTATUS( NTAPI* )(IN PWCHAR AtomName, OUT PRTL_ATOM Atom);
using fnNtAdjustGroupsToken = NTSTATUS( NTAPI* )(IN HANDLE TokenHandle, IN BOOLEAN ResetToDefault, IN PTOKEN_GROUPS TokenGroups, IN ULONG PreviousGroupsLength, OUT PTOKEN_GROUPS PreviousGroups, OUT PULONG RequiredLength);
using fnNtAdjustPrivilegesToken = NTSTATUS( NTAPI* )(IN HANDLE TokenHandle, IN BOOLEAN DisableAllPrivileges, IN PTOKEN_PRIVILEGES TokenPrivileges, IN ULONG PreviousPrivilegesLength, OUT PTOKEN_PRIVILEGES PreviousPrivileges, OUT PULONG RequiredLength);
using fnNtAlertResumeThread = NTSTATUS( NTAPI* )(IN HANDLE ThreadHandle, OUT PULONG SuspendCount);
using fnNtAlertThread = NTSTATUS( NTAPI* )(IN HANDLE ThreadHandle);
using fnNtAllocateLocallyUniqueId = NTSTATUS( NTAPI* )(OUT PLUID LocallyUniqueId);
using fnNtAllocateUuids = NTSTATUS( NTAPI* )(OUT PLARGE_INTEGER Time, OUT PULONG Range, OUT PULONG Sequence);
using fnNtAllocateVirtualMemory = NTSTATUS( NTAPI* )(IN HANDLE ProcessHandle, IN OUT PVOID *BaseAddress, IN ULONG ZeroBits, IN OUT PULONG RegionSize, IN ULONG AllocationType, IN ULONG Protect);
using fnNtCallbackReturn = NTSTATUS( NTAPI* )(IN PVOID Result, IN ULONG ResultLength, IN NTSTATUS Status);
using fnNtCancelIoFile = NTSTATUS( NTAPI* )(IN HANDLE FileHandle, OUT PIO_STATUS_BLOCK IoStatusBlock);
using fnNtCancelTimer = NTSTATUS( NTAPI* )(IN HANDLE TimerHandle, OUT PBOOLEAN CurrentState);
using fnNtClearEvent = NTSTATUS( NTAPI* )(IN HANDLE EventHandle);
using fnNtClose = NTSTATUS( NTAPI* )(IN HANDLE ObjectHandle);
using fnNtCloseObjectAuditAlarm = NTSTATUS( NTAPI* )(IN PUNICODE_STRING SubsystemName, IN HANDLE ObjectHandle, IN BOOLEAN GenerateOnClose);
using fnNtCompactKeys = NTSTATUS( NTAPI* )(IN ULONG NrOfKeys, IN HANDLE KeysArray[]);
using fnNtCompleteConnectPort = NTSTATUS( NTAPI* )(IN HANDLE PortHandle);
using fnNtCompressKey = NTSTATUS( NTAPI* )(IN HANDLE Key);
using fnNtConnectPort = NTSTATUS( NTAPI* )(OUT PHANDLE ClientPortHandle, IN PUNICODE_STRING ServerPortName, IN PSECURITY_QUALITY_OF_SERVICE SecurityQos, IN OUT PLPC_SECTION_OWNER_MEMORY ClientSharedMemory, OUT PLPC_SECTION_MEMORY ServerSharedMemory, OUT PULONG MaximumMessageLength, IN void* ConnectionInfo, IN PULONG ConnectionInfoLength);
using fnNtContinue = NTSTATUS( NTAPI* )(IN PCONTEXT ThreadContext, IN BOOLEAN RaiseAlert);
using fnNtCreateDebugObject = NTSTATUS( NTAPI* )(OUT PHANDLE DebugObjectHandle, IN ACCESS_MASK DesiredAccess, IN POBJECT_ATTRIBUTES ObjectAttributes, IN BOOLEAN KillProcessOnExit);
using fnNtCreateDirectoryObject = NTSTATUS( NTAPI* )(OUT PHANDLE DirectoryHandle, IN ACCESS_MASK DesiredAccess, IN POBJECT_ATTRIBUTES ObjectAttributes);
using fnNtCreateEvent = NTSTATUS( NTAPI* )(OUT PHANDLE EventHandle, IN ACCESS_MASK DesiredAccess, IN POBJECT_ATTRIBUTES ObjectAttributes, IN EVENT_TYPE EventType, IN BOOLEAN InitialState);
using fnNtCreateEventPair = NTSTATUS( NTAPI* )(OUT PHANDLE EventPairHandle, IN ACCESS_MASK DesiredAccess, IN POBJECT_ATTRIBUTES ObjectAttributes);
using fnNtCreateFile = NTSTATUS( NTAPI* )(OUT PHANDLE FileHandle, IN ACCESS_MASK DesiredAccess, IN POBJECT_ATTRIBUTES ObjectAttributes, OUT PIO_STATUS_BLOCK IoStatusBlock, IN PLARGE_INTEGER AllocationSize, IN ULONG FileAttributes, IN ULONG ShareAccess, IN ULONG CreateDisposition, IN ULONG CreateOptions, IN PVOID EaBuffer, IN ULONG EaLength);
using fnNtCreateIoCompletion = NTSTATUS( NTAPI* )(OUT PHANDLE IoCompletionHandle, IN ACCESS_MASK DesiredAccess, IN POBJECT_ATTRIBUTES ObjectAttributes, IN ULONG NumberOfConcurrentThreads);
using fnNtCreateKey = NTSTATUS( NTAPI* )(OUT PHANDLE pKeyHandle, IN ACCESS_MASK DesiredAccess, IN POBJECT_ATTRIBUTES ObjectAttributes, IN ULONG TitleIndex, IN PUNICODE_STRING Class, IN ULONG CreateOptions, OUT PULONG Disposition);
using fnNtCreateKeyedEvent = NTSTATUS( NTAPI* )(OUT PHANDLE KeyedEventHandle, IN ACCESS_MASK DesiredAccess, IN POBJECT_ATTRIBUTES ObjectAttributes, IN ULONG Reserved);
using fnNtCreateMailslotFile = NTSTATUS( NTAPI* )(OUT PHANDLE MailslotFileHandle, IN ACCESS_MASK DesiredAccess, IN POBJECT_ATTRIBUTES ObjectAttributes, OUT PIO_STATUS_BLOCK IoStatusBlock, IN ULONG CreateOptions, IN ULONG MailslotQuota, IN ULONG MaxMessageSize, IN PLARGE_INTEGER ReadTimeOut);
//using fnNtCreateMutant = NTSTATUS( NTAPI* )(OUT PHANDLE MutantHandle, IN ACCESS_MASK DesiredAccess, IN POBJECT_ATTRIBUTES ObjectAttributes, IN BOOLEAN InitialOwner);
using fnNtCreateNamedPipeFile = NTSTATUS( NTAPI* )(OUT PHANDLE NamedPipeFileHandle, IN ACCESS_MASK DesiredAccess, IN POBJECT_ATTRIBUTES ObjectAttributes, OUT PIO_STATUS_BLOCK IoStatusBlock, IN ULONG ShareAccess, IN ULONG CreateDisposition, IN ULONG CreateOptions, IN BOOLEAN WriteModeMessage, IN BOOLEAN ReadModeMessage, IN BOOLEAN NonBlocking, IN ULONG MaxInstances, IN ULONG InBufferSize, IN ULONG OutBufferSize, IN PLARGE_INTEGER DefaultTimeOut);
using fnNtCreatePagingFile = NTSTATUS( NTAPI* )(IN PUNICODE_STRING PageFileName, IN PLARGE_INTEGER MiniumSize, IN PLARGE_INTEGER MaxiumSize, OUT PLARGE_INTEGER ActualSize);
using fnNtCreatePort = NTSTATUS( NTAPI* )(OUT PHANDLE PortHandle, IN POBJECT_ATTRIBUTES ObjectAttributes, IN ULONG MaxConnectInfoLength, IN ULONG MaxDataLength, IN OUT PULONG Reserved);
using fnNtCreateProcess = NTSTATUS( NTAPI* )(OUT PHANDLE ProcessHandle, IN ACCESS_MASK DesiredAccess, IN POBJECT_ATTRIBUTES ObjectAttributes, IN HANDLE ParentProcess, IN BOOLEAN InheritObjectTable, IN HANDLE SectionHandle, IN HANDLE DebugPort, IN HANDLE ExceptionPort);
using fnNtCreateProfile = NTSTATUS( NTAPI* )(OUT PHANDLE ProfileHandle, IN HANDLE Process, IN PVOID ImageBase, IN ULONG ImageSize, IN ULONG BucketSize, IN PVOID Buffer, IN ULONG BufferSize, IN KPROFILE_SOURCE ProfileSource, IN KAFFINITY Affinity);
using fnNtCreateSection = NTSTATUS( NTAPI* )(OUT PHANDLE SectionHandle, IN ULONG DesiredAccess, IN POBJECT_ATTRIBUTES ObjectAttributes, IN PLARGE_INTEGER MaximumSize, IN ULONG PageAttributess, IN ULONG SectionAttributes, IN HANDLE FileHandle);
using fnNtCreateSemaphore = NTSTATUS( NTAPI* )(OUT PHANDLE SemaphoreHandle, IN ACCESS_MASK DesiredAccess, IN POBJECT_ATTRIBUTES ObjectAttributes, IN ULONG InitialCount, IN ULONG MaximumCount);
using fnNtCreateSymbolicLinkObject = NTSTATUS( NTAPI* )(OUT PHANDLE pHandle, IN ACCESS_MASK DesiredAccess, IN POBJECT_ATTRIBUTES ObjectAttributes, IN PUNICODE_STRING DestinationName);
using fnNtCreateThread = NTSTATUS( NTAPI* )(OUT PHANDLE ThreadHandle, IN ACCESS_MASK DesiredAccess, IN POBJECT_ATTRIBUTES ObjectAttributes, IN HANDLE ProcessHandle, OUT PCLIENT_ID ClientId, IN PCONTEXT ThreadContext, IN PINITIAL_TEB InitialTeb, IN BOOLEAN CreateSuspended);
using fnNtCreateTimer = NTSTATUS( NTAPI* )(OUT PHANDLE TimerHandle, IN ACCESS_MASK DesiredAccess, IN POBJECT_ATTRIBUTES ObjectAttributes, IN TIMER_TYPE TimerType);
using fnNtCreateToken = NTSTATUS( NTAPI* )(OUT PHANDLE TokenHandle, IN ACCESS_MASK DesiredAccess, IN POBJECT_ATTRIBUTES ObjectAttributes, IN TOKEN_TYPE TokenType, IN PLUID AuthenticationId, IN PLARGE_INTEGER ExpirationTime, IN PTOKEN_USER TokenUser, IN PTOKEN_GROUPS TokenGroups, IN PTOKEN_PRIVILEGES TokenPrivileges, IN PTOKEN_OWNER TokenOwner, IN PTOKEN_PRIMARY_GROUP TokenPrimaryGroup, IN PTOKEN_DEFAULT_DACL TokenDefaultDacl, IN PTOKEN_SOURCE TokenSource);
using fnNtDebugActiveProcess = NTSTATUS( NTAPI* )(IN HANDLE ProcessHandle, IN HANDLE DebugObjectHandle);
using fnNtDelayExecution = NTSTATUS( NTAPI* )(IN BOOLEAN Alertable, IN PLARGE_INTEGER DelayInterval);
using fnNtDeleteAtom = NTSTATUS( NTAPI* )(IN RTL_ATOM Atom);
using fnNtDeleteFile = NTSTATUS( NTAPI* )(IN POBJECT_ATTRIBUTES ObjectAttributes);
using fnNtDeleteKey = NTSTATUS( NTAPI* )(IN HANDLE KeyHandle);
using fnNtDeleteObjectAuditAlarm = NTSTATUS( NTAPI* )(IN PUNICODE_STRING SubsystemName, IN HANDLE ObjectHandle, IN BOOLEAN GenerateOnClose);
using fnNtDeleteValueKey = NTSTATUS( NTAPI* )(IN HANDLE KeyHandle, IN PUNICODE_STRING ValueName);
using fnNtDeviceIoControlFile = NTSTATUS( NTAPI* )(IN HANDLE FileHandle, IN HANDLE Event, IN PIO_APC_ROUTINE ApcRoutine, IN PVOID ApcContext, OUT PIO_STATUS_BLOCK IoStatusBlock, IN ULONG IoControlCode, IN PVOID InputBuffer, IN ULONG InputBufferLength, OUT PVOID OutputBuffer, IN ULONG OutputBufferLength);
using fnNtDisplayString = NTSTATUS( NTAPI* )(IN PUNICODE_STRING String);
using fnNtDuplicateObject = NTSTATUS( NTAPI* )(IN HANDLE SourceProcessHandle, IN PHANDLE SourceHandle, IN HANDLE TargetProcessHandle, OUT PHANDLE TargetHandle, IN ACCESS_MASK DesiredAccess, IN BOOLEAN InheritHandle, IN ULONG Options);
using fnNtDuplicateToken = NTSTATUS( NTAPI* )(IN HANDLE ExistingToken, IN ACCESS_MASK DesiredAccess, IN POBJECT_ATTRIBUTES ObjectAttributes, IN SECURITY_IMPERSONATION_LEVEL ImpersonationLevel, IN TOKEN_TYPE TokenType, OUT PHANDLE NewToken);
using fnNtEnumerateKey = NTSTATUS( NTAPI* )(IN HANDLE KeyHandle, IN ULONG Index, IN KEY_INFORMATION_CLASS KeyInformationClass, OUT PVOID KeyInformation, IN ULONG Length, OUT PULONG ResultLength);
using fnNtEnumerateValueKey = NTSTATUS( NTAPI* )(IN HANDLE KeyHandle, IN ULONG Index, IN KEY_VALUE_INFORMATION_CLASS KeyValueInformationClass, OUT PVOID KeyValueInformation, IN ULONG Length, OUT PULONG ResultLength);
using fnNtExtendSection = NTSTATUS( NTAPI* )(IN HANDLE SectionHandle, IN PLARGE_INTEGER NewSectionSize);
using fnNtFindAtom = NTSTATUS( NTAPI* )(IN PWCHAR AtomName, OUT PRTL_ATOM Atom);
using fnNtFlushBuffersFile = NTSTATUS( NTAPI* )(IN HANDLE FileHandle, OUT PIO_STATUS_BLOCK IoStatusBlock);
using fnNtFlushInstructionCache = NTSTATUS( NTAPI* )(IN HANDLE ProcessHandle, IN PVOID BaseAddress, IN ULONG NumberOfBytesToFlush);
using fnNtFlushKey = NTSTATUS( NTAPI* )(IN HANDLE KeyHandle);
using fnNtFlushVirtualMemory = NTSTATUS( NTAPI* )(IN HANDLE ProcessHandle, IN OUT PVOID *BaseAddress, IN OUT PULONG NumberOfBytesToFlush, OUT PIO_STATUS_BLOCK IoStatusBlock);
using fnNtFlushWriteBuffer = NTSTATUS( NTAPI* )(VOID);
using fnNtFreeVirtualMemory = NTSTATUS( NTAPI* )(IN HANDLE ProcessHandle, IN PVOID *BaseAddress, IN OUT PULONG RegionSize, IN ULONG FreeType);
using fnNtFsControlFile = NTSTATUS( NTAPI* )(IN HANDLE FileHandle, IN HANDLE Event, IN PIO_APC_ROUTINE ApcRoutine, IN PVOID ApcContext, OUT PIO_STATUS_BLOCK IoStatusBlock, IN ULONG FsControlCode, IN PVOID InputBuffer, IN ULONG InputBufferLength, OUT PVOID OutputBuffer, IN ULONG OutputBufferLength);
using fnNtGetContextThread = NTSTATUS( NTAPI* )(IN HANDLE ThreadHandle, OUT PCONTEXT pContext);
using fnNtImpersonateClientOfPort = NTSTATUS( NTAPI* )(IN HANDLE PortHandle, IN PLPC_MESSAGE Request);
using fnNtImpersonateThread = NTSTATUS( NTAPI* )(IN HANDLE ThreadHandle, IN HANDLE ThreadToImpersonate, IN PSECURITY_QUALITY_OF_SERVICE SecurityQualityOfService);
using fnNtListenPort = NTSTATUS( NTAPI* )(IN HANDLE PortHandle, OUT PLPC_MESSAGE ConnectionRequest);
using fnNtLoadDriver = NTSTATUS( NTAPI* )(IN PUNICODE_STRING DriverServiceName);
using fnNtLoadKey = NTSTATUS( NTAPI* )(IN POBJECT_ATTRIBUTES DestinationKeyName, IN POBJECT_ATTRIBUTES HiveFileName);
using fnNtLoadKey2 = NTSTATUS( NTAPI* )(IN POBJECT_ATTRIBUTES DestinationKeyName, IN POBJECT_ATTRIBUTES HiveFileName, IN ULONG Flags);
using fnNtLockFile = NTSTATUS( NTAPI* )(IN HANDLE FileHandle, IN HANDLE LockGrantedEvent, IN PIO_APC_ROUTINE ApcRoutine, IN PVOID ApcContext, OUT PIO_STATUS_BLOCK IoStatusBlock, IN PLARGE_INTEGER ByteOffset, IN PLARGE_INTEGER Length, IN PULONG Key, IN BOOLEAN ReturnImmediately, IN BOOLEAN ExclusiveLock);
using fnNtLockVirtualMemory = NTSTATUS( NTAPI* )(IN HANDLE ProcessHandle, IN PVOID *BaseAddress, IN OUT PULONG NumberOfBytesToLock, IN ULONG LockOption);
using fnNtMakeTemporaryObject = NTSTATUS( NTAPI* )(IN HANDLE ObjectHandle);
using fnNtMapViewOfSection = NTSTATUS( NTAPI* )(IN HANDLE SectionHandle, IN HANDLE ProcessHandle, IN OUT PVOID *BaseAddress, IN ULONG ZeroBits, IN ULONG CommitSize, IN OUT PLARGE_INTEGER SectionOffset, IN OUT PULONG ViewSize, IN SECTION_INHERIT InheritDisposition, IN ULONG AllocationType, IN ULONG Protect);
using fnNtNotifyChangeDirectoryFile = NTSTATUS( NTAPI* )(IN HANDLE FileHandle, IN HANDLE Event, IN PIO_APC_ROUTINE ApcRoutine, IN PVOID ApcContext, OUT PIO_STATUS_BLOCK IoStatusBlock, OUT PVOID Buffer, IN ULONG BufferSize, IN ULONG CompletionFilter, IN BOOLEAN WatchTree);
using fnNtNotifyChangeKey = NTSTATUS( NTAPI* )(IN HANDLE KeyHandle, IN HANDLE EventHandle, IN PIO_APC_ROUTINE ApcRoutine, IN PVOID ApcRoutineContext, IN PIO_STATUS_BLOCK IoStatusBlock, IN ULONG NotifyFilter, IN BOOLEAN WatchSubtree, OUT PVOID RegChangesDataBuffer, IN ULONG RegChangesDataBufferLength, IN BOOLEAN Asynchronous);
using fnNtOpenDirectoryObject = NTSTATUS( NTAPI* )(OUT PHANDLE DirectoryObjectHandle, IN ACCESS_MASK DesiredAccess, IN POBJECT_ATTRIBUTES ObjectAttributes);
using fnNtOpenEvent = NTSTATUS( NTAPI* )(OUT PHANDLE EventHandle, IN ACCESS_MASK DesiredAccess, IN POBJECT_ATTRIBUTES ObjectAttributes);
using fnNtOpenEventPair = NTSTATUS( NTAPI* )(OUT PHANDLE EventPairHandle, IN ACCESS_MASK DesiredAccess, IN POBJECT_ATTRIBUTES ObjectAttributes);
using fnNtOpenFile = NTSTATUS( NTAPI* )(OUT PHANDLE FileHandle, IN ACCESS_MASK DesiredAccess, IN POBJECT_ATTRIBUTES ObjectAttributes, OUT PIO_STATUS_BLOCK IoStatusBlock, IN ULONG ShareAccess, IN ULONG OpenOptions);
using fnNtOpenIoCompletion = NTSTATUS( NTAPI* )(OUT PHANDLE IoCompletionHandle, IN ACCESS_MASK DesiredAccess, IN POBJECT_ATTRIBUTES ObjectAttributes);
using fnNtOpenKey = NTSTATUS( NTAPI* )(OUT PHANDLE pKeyHandle, IN ACCESS_MASK DesiredAccess, IN POBJECT_ATTRIBUTES ObjectAttributes);
using fnNtOpenKeyedEvent = NTSTATUS( NTAPI* )(OUT PHANDLE KeyedEventHandle, IN ACCESS_MASK DesiredAccess, IN POBJECT_ATTRIBUTES ObjectAttributes);
using fnNtOpenMutant = NTSTATUS( NTAPI* )(OUT PHANDLE MutantHandle, IN ACCESS_MASK DesiredAccess, IN POBJECT_ATTRIBUTES ObjectAttributes);
using fnNtOpenObjectAuditAlarm = NTSTATUS( NTAPI* )(IN PUNICODE_STRING SubsystemName, IN PHANDLE ObjectHandle, IN PUNICODE_STRING ObjectTypeName, IN PUNICODE_STRING ObjectName, IN PSECURITY_DESCRIPTOR SecurityDescriptor, IN HANDLE ClientToken, IN ACCESS_MASK DesiredAccess, IN ACCESS_MASK GrantedAccess, IN PPRIVILEGE_SET Privileges, IN BOOLEAN ObjectCreation, IN BOOLEAN AccessGranted, OUT PBOOLEAN GenerateOnClose);
using fnNtOpenProcess = NTSTATUS( NTAPI* )(OUT PHANDLE ProcessHandle, IN ACCESS_MASK AccessMask, IN POBJECT_ATTRIBUTES ObjectAttributes, IN PCLIENT_ID ClientId);
using fnNtOpenProcessToken = NTSTATUS( NTAPI* )(IN HANDLE ProcessHandle, IN ACCESS_MASK DesiredAccess, OUT PHANDLE TokenHandle);
using fnNtOpenSection = NTSTATUS( NTAPI* )(OUT PHANDLE SectionHandle, IN ACCESS_MASK DesiredAccess, IN POBJECT_ATTRIBUTES ObjectAttributes);
using fnNtOpenSemaphore = NTSTATUS( NTAPI* )(OUT PHANDLE SemaphoreHandle, IN ACCESS_MASK DesiredAccess, IN POBJECT_ATTRIBUTES ObjectAttributes);
using fnNtOpenSymbolicLinkObject = NTSTATUS( NTAPI* )(OUT PHANDLE pHandle, IN ACCESS_MASK DesiredAccess, IN POBJECT_ATTRIBUTES ObjectAttributes);
using fnNtOpenThread = NTSTATUS( NTAPI* )(OUT PHANDLE ThreadHandle, IN ACCESS_MASK AccessMask, IN POBJECT_ATTRIBUTES ObjectAttributes, IN PCLIENT_ID ClientId);
using fnNtOpenThreadToken = NTSTATUS( NTAPI* )(IN HANDLE ThreadHandle, IN ACCESS_MASK DesiredAccess, IN BOOLEAN OpenAsSelf, OUT PHANDLE TokenHandle);
using fnNtOpenTimer = NTSTATUS( NTAPI* )(OUT PHANDLE TimerHandle, IN ACCESS_MASK DesiredAccess, IN POBJECT_ATTRIBUTES ObjectAttributes);
using fnNtPrivilegeCheck = NTSTATUS( NTAPI* )(IN HANDLE TokenHandle, IN PPRIVILEGE_SET RequiredPrivileges, IN PBOOLEAN Result);
using fnNtPrivilegeObjectAuditAlarm = NTSTATUS( NTAPI* )(IN PUNICODE_STRING SubsystemName, IN HANDLE ObjectHandle, IN HANDLE ClientToken, IN ULONG DesiredAccess, IN PPRIVILEGE_SET ClientPrivileges, IN BOOLEAN AccessGranted);
using fnNtPrivilegedServiceAuditAlarm = NTSTATUS( NTAPI* )(IN PUNICODE_STRING SubsystemName, IN PUNICODE_STRING ServiceName, IN HANDLE ClientToken, IN PPRIVILEGE_SET ClientPrivileges, IN BOOLEAN AccessGranted);
using fnNtProtectVirtualMemory = NTSTATUS( NTAPI* )(IN HANDLE ProcessHandle, IN OUT PVOID *BaseAddress, IN OUT PSIZE_T NumberOfBytesToProtect, IN ULONG NewAccessProtection, OUT PULONG OldAccessProtection);
using fnNtPulseEvent = NTSTATUS( NTAPI* )(IN HANDLE EventHandle, OUT PLONG PreviousState);
using fnNtQueryAttributesFile = NTSTATUS( NTAPI* )(IN POBJECT_ATTRIBUTES ObjectAttributes, OUT PFILE_BASIC_INFORMATION FileAttributes);
using fnNtQueryDefaultLocale = NTSTATUS( NTAPI* )(IN BOOLEAN UserProfile, OUT PLCID DefaultLocaleId);
using fnNtQueryDirectoryFile = NTSTATUS( NTAPI* )(IN HANDLE FileHandle, IN HANDLE Event, IN PIO_APC_ROUTINE ApcRoutine, IN PVOID ApcContext, OUT PIO_STATUS_BLOCK IoStatusBlock, OUT PVOID FileInformation, IN ULONG Length, IN FILE_INFORMATION_CLASS FileInformationClass, IN BOOLEAN ReturnSingleEntry, IN PUNICODE_STRING FileMask, IN BOOLEAN RestartScan);
using fnNtQueryDirectoryObject = NTSTATUS( NTAPI* )(IN HANDLE DirectoryObjectHandle, OUT POBJDIR_INFORMATION DirObjInformation, IN ULONG BufferLength, IN BOOLEAN GetNextIndex, IN BOOLEAN IgnoreInputIndex, IN OUT PULONG ObjectIndex, OUT PULONG DataWritten);
using fnNtQueryEaFile = NTSTATUS( NTAPI* )(IN HANDLE FileHandle, OUT PIO_STATUS_BLOCK IoStatusBlock, OUT PVOID Buffer, IN ULONG Length, IN BOOLEAN ReturnSingleEntry, IN PVOID EaList, IN ULONG EaListLength, IN PULONG EaIndex, IN BOOLEAN RestartScan);
using fnNtQueryEvent = NTSTATUS( NTAPI* )(IN HANDLE EventHandle, IN EVENT_INFORMATION_CLASS EventInformationClass, OUT PVOID EventInformation, IN ULONG EventInformationLength, OUT PULONG ReturnLength);
using fnNtQueryFullAttributesFile = NTSTATUS( NTAPI* )(IN POBJECT_ATTRIBUTES ObjectAttributes, OUT PVOID Attributes);
using fnNtQueryInformationAtom = NTSTATUS( NTAPI* )(IN RTL_ATOM Atom, IN ATOM_INFORMATION_CLASS AtomInformationClass, OUT PVOID AtomInformation, IN ULONG AtomInformationLength, OUT PULONG ReturnLength);
using fnNtQueryInformationFile = NTSTATUS( NTAPI* )(IN HANDLE FileHandle, OUT PIO_STATUS_BLOCK IoStatusBlock, OUT PVOID FileInformation, IN ULONG Length, IN FILE_INFORMATION_CLASS FileInformationClass);
using fnNtQueryInformationPort = NTSTATUS( NTAPI* )(IN HANDLE PortHandle, IN PORT_INFORMATION_CLASS PortInformationClass, OUT PVOID PortInformation, IN ULONG Length, OUT PULONG ResultLength);
using fnNtQueryInformationProcess = NTSTATUS( NTAPI* )(IN  HANDLE, IN  UINT, OUT PVOID, IN ULONG, OUT PULONG);
using fnNtQueryInformationThread = NTSTATUS( NTAPI* )(HANDLE, UINT, PVOID, ULONG, PULONG);
using fnNtQueryInformationToken = NTSTATUS( NTAPI* )(IN HANDLE TokenHandle, IN TOKEN_INFORMATION_CLASS TokenInformationClass, OUT PVOID TokenInformation, IN ULONG TokenInformationLength, OUT PULONG ReturnLength);
using fnNtQueryIntervalProfile = NTSTATUS( NTAPI* )(IN KPROFILE_SOURCE ProfileSource, OUT PULONG Interval);
using fnNtQueryIoCompletion = NTSTATUS( NTAPI* )(IN HANDLE IoCompletionHandle, IN IO_COMPLETION_INFORMATION_CLASS InformationClass, OUT PVOID IoCompletionInformation, IN ULONG InformationBufferLength, OUT PULONG RequiredLength);
using fnNtQueryKey = NTSTATUS( NTAPI* )(IN HANDLE KeyHandle, IN KEY_INFORMATION_CLASS KeyInformationClass, OUT PVOID KeyInformation, IN ULONG Length, OUT PULONG ResultLength);
using fnNtQueryMultipleValueKey = NTSTATUS( NTAPI* )(IN HANDLE KeyHandle, IN OUT PKEY_MULTIPLE_VALUE_INFORMATION ValuesList, IN ULONG NumberOfValues, OUT PVOID DataBuffer, IN OUT ULONG BufferLength, OUT PULONG RequiredLength);
using fnNtQueryMutant = NTSTATUS( NTAPI* )(IN HANDLE MutantHandle, IN MUTANT_INFORMATION_CLASS MutantInformationClass, OUT PVOID MutantInformation, IN ULONG MutantInformationLength, OUT PULONG ResultLength);
using fnNtQueryObject = NTSTATUS( NTAPI* )(IN HANDLE, IN UINT, OUT PVOID, IN ULONG, OUT PULONG);
using fnNtQueryPerformanceCounter = NTSTATUS( NTAPI* )(OUT PLARGE_INTEGER PerformanceCounter, OUT PLARGE_INTEGER PerformanceFrequency);
using fnNtQuerySection = NTSTATUS( NTAPI* )(IN HANDLE SectionHandle, IN SECTION_INFORMATION_CLASS InformationClass, OUT PVOID InformationBuffer, IN ULONG InformationBufferSize, OUT PULONG ResultLength);
using fnNtQuerySecurityObject = NTSTATUS( NTAPI* )(IN HANDLE ObjectHandle, IN SECURITY_INFORMATION SecurityInformationClass, OUT PSECURITY_DESCRIPTOR DescriptorBuffer, IN ULONG DescriptorBufferLength, OUT PULONG RequiredLength);
using fnNtQuerySemaphore = NTSTATUS( NTAPI* )(IN HANDLE SemaphoreHandle, IN SEMAPHORE_INFORMATION_CLASS SemaphoreInformationClass, OUT PVOID SemaphoreInformation, IN ULONG SemaphoreInformationLength, OUT PULONG ReturnLength);
using fnNtQuerySymbolicLinkObject = NTSTATUS( NTAPI* )(IN HANDLE SymbolicLinkHandle, OUT PUNICODE_STRING pLinkName, OUT PULONG pDataWritten);
using fnNtQuerySystemEnvironmentValue = NTSTATUS( NTAPI* )(IN PUNICODE_STRING VariableName, OUT PWCHAR Value, IN ULONG ValueBufferLength, OUT PULONG RequiredLength);
using fnNtQuerySystemInformation = NTSTATUS( NTAPI* )(IN UINT, OUT PVOID, IN ULONG, OUT PULONG);
using fnNtQueryTimer = NTSTATUS( NTAPI* )(IN HANDLE TimerHandle, IN TIMER_INFORMATION_CLASS TimerInformationClass, OUT PVOID TimerInformation, IN ULONG TimerInformationLength, OUT PULONG ReturnLength);
using fnNtQueryTimerResolution = NTSTATUS( NTAPI* )(OUT PULONG MinimumResolution, OUT PULONG MaximumResolution, OUT PULONG CurrentResolution);
using fnNtQueryValueKey = NTSTATUS( NTAPI* )(IN HANDLE KeyHandle, IN PUNICODE_STRING ValueName, IN KEY_VALUE_INFORMATION_CLASS KeyValueInformationClass, OUT PVOID KeyValueInformation, IN ULONG Length, OUT PULONG ResultLength);
using fnNtQueryVirtualMemory = NTSTATUS( NTAPI* )(IN HANDLE ProcessHandle, IN PVOID BaseAddress, IN MEMORY_INFORMATION_CLASS MemoryInformationClass, OUT PVOID Buffer, IN SIZE_T Length, OUT PSIZE_T ResultLength);
using fnNtQueryVolumeInformationFile = NTSTATUS( NTAPI* )(IN HANDLE FileHandle, OUT PIO_STATUS_BLOCK IoStatusBlock, OUT PVOID FileSystemInformation, IN ULONG Length, IN FS_INFORMATION_CLASS FileSystemInformationClass);
using fnNtQueueApcThread = NTSTATUS( NTAPI* )(IN HANDLE ThreadHandle, IN PIO_APC_ROUTINE ApcRoutine, IN PVOID ApcRoutineContext, IN PIO_STATUS_BLOCK ApcStatusBlock, IN ULONG ApcReserved);
using fnNtRaiseException = NTSTATUS( NTAPI* )(IN PEXCEPTION_RECORD ExceptionRecord, IN PCONTEXT ThreadContext, IN BOOLEAN HandleException);
using fnNtRaiseHardError = NTSTATUS( NTAPI* )(IN NTSTATUS ErrorStatus, IN ULONG NumberOfParameters, IN PUNICODE_STRING UnicodeStringParameterMask, IN PVOID *Parameters, IN HARDERROR_RESPONSE_OPTION ResponseOption, OUT PHARDERROR_RESPONSE Response);
using fnNtReadFile = NTSTATUS( NTAPI* )(IN HANDLE FileHandle, IN HANDLE Event, IN PIO_APC_ROUTINE ApcRoutine, IN PVOID ApcContext, OUT PIO_STATUS_BLOCK IoStatusBlock, OUT PVOID Buffer, IN ULONG Length, IN PLARGE_INTEGER ByteOffset, IN PULONG Key);
using fnNtReadFileScatter = NTSTATUS( NTAPI* )(IN HANDLE FileHandle, IN HANDLE Event, IN PIO_APC_ROUTINE ApcRoutine, IN PVOID ApcContext, OUT PIO_STATUS_BLOCK IoStatusBlock, IN FILE_SEGMENT_ELEMENT SegmentArray, IN ULONG Length, IN PLARGE_INTEGER ByteOffset, IN PULONG Key);
using fnNtReadRequestData = NTSTATUS( NTAPI* )(IN HANDLE PortHandle, IN PLPC_MESSAGE Request, IN ULONG DataIndex, OUT PVOID Buffer, IN ULONG Length, OUT PULONG ResultLength);
using fnNtReadVirtualMemory = NTSTATUS( NTAPI* )(IN HANDLE ProcessHandle, IN PVOID BaseAddress, OUT PVOID Buffer, IN ULONG NumberOfBytesToRead, OUT PULONG NumberOfBytesReaded);
using fnNtRegisterThreadTerminatePort = NTSTATUS( NTAPI* )(IN HANDLE PortHandle);
using fnNtReleaseKeyedEvent = NTSTATUS( NTAPI* )(IN HANDLE KeyedEventHandle, IN PVOID Key, IN BOOLEAN Alertable, IN PLARGE_INTEGER Timeout);
using fnNtReleaseMutant = NTSTATUS( NTAPI* )(IN HANDLE MutantHandle, OUT PLONG PreviousCount);
using fnNtReleaseSemaphore = NTSTATUS( NTAPI* )(IN HANDLE SemaphoreHandle, IN ULONG ReleaseCount, OUT PULONG PreviousCount);
using fnNtRemoveIoCompletion = NTSTATUS( NTAPI* )(IN HANDLE IoCompletionHandle, OUT PULONG CompletionKey, OUT PULONG CompletionValue, OUT PIO_STATUS_BLOCK IoStatusBlock, IN PLARGE_INTEGER Timeout);
using fnNtRemoveProcessDebug = NTSTATUS( NTAPI* )(IN HANDLE ProcessHandle, IN HANDLE DebugObjectHandle);
using fnNtReplaceKey = NTSTATUS( NTAPI* )(IN POBJECT_ATTRIBUTES NewHiveFileName, IN HANDLE KeyHandle, IN POBJECT_ATTRIBUTES BackupHiveFileName);
using fnNtReplyPort = NTSTATUS( NTAPI* )(IN HANDLE PortHandle, IN PLPC_MESSAGE Reply);
using fnNtReplyWaitReceivePort = NTSTATUS( NTAPI* )(IN HANDLE PortHandle, OUT PHANDLE ReceivePortHandle, IN PLPC_MESSAGE Reply, OUT PLPC_MESSAGE IncomingRequest);
using fnNtReplyWaitReplyPort = NTSTATUS( NTAPI* )(IN HANDLE PortHandle, IN OUT PLPC_MESSAGE Reply);
using fnNtRequestPort = NTSTATUS( NTAPI* )(IN HANDLE PortHandle, IN PLPC_MESSAGE Request);
using fnNtRequestWaitReplyPort = NTSTATUS( NTAPI* )(IN HANDLE PortHandle, IN PLPC_MESSAGE Request, OUT PLPC_MESSAGE IncomingReply);
using fnNtResetEvent = NTSTATUS( NTAPI* )(IN HANDLE EventHandle, OUT PLONG PreviousState);
using fnNtRestoreKey = NTSTATUS( NTAPI* )(IN HANDLE KeyHandle, IN HANDLE FileHandle, IN ULONG RestoreOption);
using fnNtResumeThread = NTSTATUS( NTAPI* )(IN HANDLE ThreadHandle, OUT PULONG SuspendCount);
using fnNtSaveKey = NTSTATUS( NTAPI* )(IN HANDLE KeyHandle, IN HANDLE FileHandle);
using fnNtSetContextThread = NTSTATUS( NTAPI* )(IN HANDLE ThreadHandle, IN PCONTEXT Context);
using fnNtSetDefaultHardErrorPort = NTSTATUS( NTAPI* )(IN HANDLE PortHandle);
using fnNtSetDefaultLocale = NTSTATUS( NTAPI* )(IN BOOLEAN UserProfile, IN LCID DefaultLocaleId);
using fnNtSetEaFile = NTSTATUS( NTAPI* )(IN HANDLE FileHandle, OUT PIO_STATUS_BLOCK IoStatusBlock, IN PVOID EaBuffer, IN ULONG EaBufferSize);
using fnNtSetEvent = NTSTATUS( NTAPI* )(IN HANDLE EventHandle, OUT PLONG PreviousState);
using fnNtSetEventBoostPriority = NTSTATUS( NTAPI* )(IN HANDLE EventHandle);
using fnNtSetHighEventPair = NTSTATUS( NTAPI* )(IN HANDLE EventPairHandle);
using fnNtSetHighWaitLowEventPair = NTSTATUS( NTAPI* )(IN HANDLE EventPairHandle);
using fnNtSetInformationFile = NTSTATUS( NTAPI* )(IN HANDLE FileHandle, OUT PIO_STATUS_BLOCK IoStatusBlock, IN PVOID FileInformation, IN ULONG Length, IN FILE_INFORMATION_CLASS FileInformationClass);
using fnNtSetInformationKey = NTSTATUS( NTAPI* )(IN HANDLE KeyHandle, IN KEY_SET_INFORMATION_CLASS InformationClass, IN PVOID KeyInformationData, IN ULONG DataLength);
using fnNtSetInformationObject = NTSTATUS( NTAPI* )(IN HANDLE ObjectHandle, IN OBJECT_INFORMATION_CLASS ObjectInformationClass, IN PVOID ObjectInformation, IN ULONG Length);
using fnNtSetInformationProcess = NTSTATUS( NTAPI* )(IN HANDLE ProcessHandle, IN PROCESS_INFORMATION_CLASS ProcessInformationClass, IN PVOID ProcessInformation, IN ULONG ProcessInformationLength);
using fnNtSetInformationThread = NTSTATUS( NTAPI* )(HANDLE, UINT, PVOID, ULONG);
using fnNtSetInformationToken = NTSTATUS( NTAPI* )(IN HANDLE TokenHandle, IN TOKEN_INFORMATION_CLASS TokenInformationClass, OUT PVOID TokenInformation, IN ULONG TokenInformationLength);
using fnNtSetIntervalProfile = NTSTATUS( NTAPI* )(IN ULONG Interval, IN KPROFILE_SOURCE Source);
using fnNtSetIoCompletion = NTSTATUS( NTAPI* )(IN HANDLE IoCompletionHandle, IN ULONG CompletionKey, OUT PIO_STATUS_BLOCK IoStatusBlock, IN NTSTATUS CompletionStatus, IN ULONG NumberOfBytesTransfered);
using fnNtSetLowEventPair = NTSTATUS( NTAPI* )(IN HANDLE EventPairHandle);
using fnNtSetLowWaitHighEventPair = NTSTATUS( NTAPI* )(IN HANDLE EventPairHandle);
using fnNtSetSecurityObject = NTSTATUS( NTAPI* )(IN HANDLE ObjectHandle, IN SECURITY_INFORMATION SecurityInformationClass, IN PSECURITY_DESCRIPTOR DescriptorBuffer);
using fnNtSetSystemEnvironmentValue = NTSTATUS( NTAPI* )(IN PUNICODE_STRING VariableName, IN PUNICODE_STRING Value);
using fnNtSetSystemInformation = NTSTATUS( NTAPI* )(IN SYSTEM_INFORMATION_CLASS SystemInformationClass, IN PVOID SystemInformation, IN ULONG SystemInformationLength);
using fnNtSetSystemTime = NTSTATUS( NTAPI* )(IN PLARGE_INTEGER SystemTime, OUT PLARGE_INTEGER PreviousTime);
using fnNtSetTimer = NTSTATUS( NTAPI* )(IN HANDLE TimerHandle, IN PLARGE_INTEGER DueTime, IN PTIMER_APC_ROUTINE TimerApcRoutine, IN PVOID TimerContext, IN BOOLEAN ResumeTimer, IN LONG Period, OUT PBOOLEAN PreviousState);
using fnNtSetTimerResolution = NTSTATUS( NTAPI* )(IN ULONG DesiredResolution, IN BOOLEAN SetResolution, OUT PULONG CurrentResolution);
using fnNtSetValueKey = NTSTATUS( NTAPI* )(IN HANDLE KeyHandle, IN PUNICODE_STRING ValueName, IN ULONG TitleIndex, IN ULONG Type, IN PVOID Data, IN ULONG DataSize);
using fnNtSetVolumeInformationFile = NTSTATUS( NTAPI* )(IN HANDLE FileHandle, OUT PIO_STATUS_BLOCK IoStatusBlock, IN PVOID FileSystemInformation, IN ULONG Length, IN FS_INFORMATION_CLASS FileSystemInformationClass);
using fnNtShutdownSystem = NTSTATUS( NTAPI* )(IN SHUTDOWN_ACTION Action);
using fnNtSignalAndWaitForSingleObject = NTSTATUS( NTAPI* )(IN HANDLE ObjectToSignal, IN HANDLE WaitableObject, IN BOOLEAN Alertable, IN PLARGE_INTEGER Time);
using fnNtStartProfile = NTSTATUS( NTAPI* )(IN HANDLE ProfileHandle);
using fnNtStopProfile = NTSTATUS( NTAPI* )(IN HANDLE ProfileHandle);
using fnNtSuspendThread = NTSTATUS( NTAPI* )(IN HANDLE ThreadHandle, OUT PULONG PreviousSuspendCount);
using fnNtSystemDebugControl = NTSTATUS( NTAPI* )(IN SYSDBG_COMMAND Command, IN PVOID InputBuffer, IN ULONG InputBufferLength, OUT PVOID OutputBuffer, IN ULONG OutputBufferLength, OUT PULONG ReturnLength);
using fnNtTerminateProcess = NTSTATUS( NTAPI* )(IN HANDLE ProcessHandle, IN NTSTATUS ExitStatus);
using fnNtTerminateThread = NTSTATUS( NTAPI* )(IN HANDLE ThreadHandle, IN NTSTATUS ExitStatus);
using fnNtTestAlert = NTSTATUS( NTAPI* )(VOID);
using fnNtUnloadDriver = NTSTATUS( NTAPI* )(IN PUNICODE_STRING DriverServiceName);
using fnNtUnloadKey = NTSTATUS( NTAPI* )(IN POBJECT_ATTRIBUTES DestinationKeyName);
using fnNtUnlockFile = NTSTATUS( NTAPI* )(IN HANDLE FileHandle, OUT PIO_STATUS_BLOCK IoStatusBlock, IN PLARGE_INTEGER ByteOffset, IN PLARGE_INTEGER Length, IN PULONG Key);
using fnNtUnlockVirtualMemory = NTSTATUS( NTAPI* )(IN HANDLE ProcessHandle, IN PVOID *BaseAddress, IN OUT PULONG NumberOfBytesToUnlock, IN ULONG LockType);
using fnNtUnmapViewOfSection = NTSTATUS( NTAPI* )(IN HANDLE ProcessHandle, IN PVOID BaseAddress);
using fnNtWaitForKeyedEvent = NTSTATUS( NTAPI* )(IN HANDLE KeyedEventHandle, IN PVOID Key, IN BOOLEAN Alertable, IN PLARGE_INTEGER Timeout);
using fnNtWaitForMultipleObjects = NTSTATUS( NTAPI* )(IN ULONG ObjectCount, IN PHANDLE ObjectsArray, IN OBJECT_WAIT_TYPE WaitType, IN BOOLEAN Alertable, IN PLARGE_INTEGER TimeOut);
using fnNtWaitForSingleObject = NTSTATUS( NTAPI* )(IN HANDLE ObjectHandle, IN BOOLEAN Alertable, IN PLARGE_INTEGER TimeOut);
using fnNtWaitHighEventPair = NTSTATUS( NTAPI* )(IN HANDLE EventPairHandle);
using fnNtWaitLowEventPair = NTSTATUS( NTAPI* )(IN HANDLE EventPairHandle);
using fnNtWriteFile = NTSTATUS( NTAPI* )(IN HANDLE FileHandle, IN HANDLE Event, IN PIO_APC_ROUTINE ApcRoutine, IN PVOID ApcContext, OUT PIO_STATUS_BLOCK IoStatusBlock, IN PVOID Buffer, IN ULONG Length, IN PLARGE_INTEGER ByteOffset, IN PULONG Key);
using fnNtWriteFileGather = NTSTATUS( NTAPI* )(IN HANDLE FileHandle, IN HANDLE Event, IN PIO_APC_ROUTINE ApcRoutine, IN PVOID ApcContext, OUT PIO_STATUS_BLOCK IoStatusBlock, IN FILE_SEGMENT_ELEMENT SegmentArray, IN ULONG Length, IN PLARGE_INTEGER ByteOffset, IN PULONG Key);
using fnNtWriteRequestData = NTSTATUS( NTAPI* )(IN HANDLE PortHandle, IN PLPC_MESSAGE Request, IN ULONG DataIndex, IN PVOID Buffer, IN ULONG Length, OUT PULONG ResultLength);
using fnNtWriteVirtualMemory = NTSTATUS( NTAPI* )(IN HANDLE ProcessHandle, IN PVOID BaseAddress, IN PVOID Buffer, IN ULONG NumberOfBytesToWrite, OUT PULONG NumberOfBytesWritten);
using fnNtYieldExecution = NTSTATUS( NTAPI* )(VOID);

#pragma endregion