#pragma once

#include <ntifs.h>


#define SEC_IMAGE                 0x01000000

typedef struct _SYSTEM_BASIC_INFORMATION {
    ULONG Reserved;
    ULONG TimerResolution;
    ULONG PageSize;
    ULONG NumberOfPhysicalPages;
    ULONG LowestPhysicalPageNumber;
    ULONG HighestPhysicalPageNumber;
    ULONG AllocationGranularity;
    ULONG_PTR MinimumUserModeAddress;
    ULONG_PTR MaximumUserModeAddress;
    ULONG_PTR ActiveProcessorsAffinityMask;
    CCHAR NumberOfProcessors;
} SYSTEM_BASIC_INFORMATION, * PSYSTEM_BASIC_INFORMATION;


typedef struct _SYSTEM_MODULE_ENTRY
{
    HANDLE  Section;
    PVOID   MappedBase;
    PVOID   Base;
    ULONG   Size;
    ULONG   Flags;
    USHORT  LoadOrderIndex;
    USHORT  InitOrderIndex;
    USHORT  LoadCount;
    USHORT  OffsetToFileName;
    UCHAR   ImageName[256];
} SYSTEM_MODULE_ENTRY, * PSYSTEM_MODULE_ENTRY;


typedef struct _SYSTEM_MODULE_INFORMATION
{
    ULONG Count;
    SYSTEM_MODULE_ENTRY Modules[ANYSIZE_ARRAY];
} SYSTEM_MODULE_INFORMATION, *PSYSTEM_MODULE_INFORMATION;

typedef struct _SYSTEM_BIGPOOL_ENTRY
{
    union {
        PVOID VirtualAddress;
        ULONG_PTR NonPaged : 1;
    };

    ULONG_PTR SizeInBytes;

    union {
        UCHAR Tag[4];
        ULONG TagUlong;
    };

} SYSTEM_BIGPOOL_ENTRY, * PSYSTEM_BIGPOOL_ENTRY;

typedef struct _SYSTEM_BIGPOOL_INFORMATION
{
    ULONG Count;
    SYSTEM_BIGPOOL_ENTRY AllocatedInfo[ANYSIZE_ARRAY];
} SYSTEM_BIGPOOL_INFORMATION, * PSYSTEM_BIGPOOL_INFORMATION;


typedef enum _SYSTEM_INFORMATION_CLASS {
    SystemBasicInformation,
    SystemProcessorInformation,
    SystemPerformanceInformation,
    SystemTimeOfDayInformation,
    SystemNotImplemented1,
    SystemProcessesInformation,
    SystemCallCounts,
    SystemConfigurationInformation,
    SystemProcessorTimes,
    SystemGlobalFlag,
    SystemNotImplemented2,
    SystemModuleInformation,
    SystemLockInformation,
    SystemNotImplemented3,
    SystemNotImplemented4,
    SystemNotImplemented5,
    SystemHandleInformation,
    SystemObjectInformation,
    SystemPagefileInformation,
    SystemInstructionEmulationCounts,
    SystemInvalidInfoClass1,
    SystemCacheInformation,
    SystemPoolTagInformation,
    SystemProcessorStatistics,
    SystemDpcInformation,
    SystemNotImplemented6,
    SystemLoadImage,
    SystemUnloadImage,
    SystemTimeAdjustment,
    SystemNotImplemented7,
    SystemNotImplemented8,
    SystemNotImplemented9,
    SystemCrashDumpInformation,
    SystemExceptionInformation,
    SystemCrashDumpStateInformation,
    SystemKernelDebuggerInformation,
    SystemContextSwitchInformation,
    SystemRegistryQuotaInformation,
    SystemLoadAndCallImage,
    SystemPrioritySeparation,
    SystemNotImplemented10,
    SystemNotImplemented11,
    SystemInvalidInfoClass2,
    SystemInvalidInfoClass3,
    SystemCurrentTimeZoneInformation,
    SystemLookasideInformation,
    SystemSetTimeSlipEvent,
    SystemCreateSession,
    SystemDeleteSession,
    SystemInvalidInfoClass4,
    SystemRangeStartInformation,
    SystemVerifierInformation,
    SystemAddVerifier,
    SystemSessionProcessesInformation,
    SystemLoadGdiDriverInSystemSpace = 0x0036,
    SystemNumaProcessorMap = 0x0037,
    SystemPrefetcherInformation = 0x0038,
    SystemExtendedProcessInformation = 0x0039,
    SystemRecommendedSharedDataAlignment = 0x003A,
    SystemComPlusPackage = 0x003B,
    SystemNumaAvailableMemory = 0x003C,
    SystemProcessorPowerInformation = 0x003D,
    SystemEmulationBasicInformation = 0x003E,
    SystemEmulationProcessorInformation = 0x003F,
    SystemExtendedHandleInformation = 0x0040,
    SystemLostDelayedWriteInformation = 0x0041,
    SystemBigPoolInformation = 0x0042,
    SystemSessionPoolTagInformation = 0x0043,
    SystemSessionMappedViewInformation = 0x0044,
    SystemHotpatchInformation = 0x0045,
    SystemObjectSecurityMode = 0x0046,
    SystemWatchdogTimerHandler = 0x0047,
    SystemWatchdogTimerInformation = 0x0048,
    SystemLogicalProcessorInformation = 0x0049,
    SystemWow64SharedInformationObsolete = 0x004A,
    SystemRegisterFirmwareTableInformationHandler = 0x004B,
    SystemFirmwareTableInformation = 0x004C,
    SystemModuleInformationEx = 0x004D,
    SystemVerifierTriageInformation = 0x004E,
    SystemSuperfetchInformation = 0x004F,
    SystemMemoryListInformation = 0x0050,
    SystemFileCacheInformationEx = 0x0051,
    SystemThreadPriorityClientIdInformation = 0x0052,
    SystemProcessorIdleCycleTimeInformation = 0x0053,
    SystemVerifierCancellationInformation = 0x0054,
    SystemProcessorPowerInformationEx = 0x0055,
    SystemRefTraceInformation = 0x0056,
    SystemSpecialPoolInformation = 0x0057,
    SystemProcessIdInformation = 0x0058,
    SystemErrorPortInformation = 0x0059,
    SystemBootEnvironmentInformation = 0x005A,
    SystemHypervisorInformation = 0x005B,
    SystemVerifierInformationEx = 0x005C,
    SystemTimeZoneInformation = 0x005D,
    SystemImageFileExecutionOptionsInformation = 0x005E,
    SystemCoverageInformation = 0x005F,
    SystemPrefetchPatchInformation = 0x0060,
    SystemVerifierFaultsInformation = 0x0061,
    SystemSystemPartitionInformation = 0x0062,
    SystemSystemDiskInformation = 0x0063,
    SystemProcessorPerformanceDistribution = 0x0064,
    SystemNumaProximityNodeInformation = 0x0065,
    SystemDynamicTimeZoneInformation = 0x0066,
    SystemCodeIntegrityInformation = 0x0067,
    SystemProcessorMicrocodeUpdateInformation = 0x0068,
    SystemProcessorBrandString = 0x0069,
    SystemVirtualAddressInformation = 0x006A,
    SystemLogicalProcessorAndGroupInformation = 0x006B,
    SystemProcessorCycleTimeInformation = 0x006C,
    SystemStoreInformation = 0x006D,
    SystemRegistryAppendString = 0x006E,
    SystemAitSamplingValue = 0x006F,
    SystemVhdBootInformation = 0x0070,
    SystemCpuQuotaInformation = 0x0071,
    SystemNativeBasicInformation = 0x0072,
    SystemErrorPortTimeouts = 0x0073,
    SystemLowPriorityIoInformation = 0x0074,
    SystemBootEntropyInformation = 0x0075,
    SystemVerifierCountersInformation = 0x0076,
    SystemPagedPoolInformationEx = 0x0077,
    SystemSystemPtesInformationEx = 0x0078,
    SystemNodeDistanceInformation = 0x0079,
    SystemAcpiAuditInformation = 0x007A,
    SystemBasicPerformanceInformation = 0x007B,
    SystemQueryPerformanceCounterInformation = 0x007C,
    SystemSessionBigPoolInformation = 0x007D,
    SystemBootGraphicsInformation = 0x007E,
    SystemScrubPhysicalMemoryInformation = 0x007F,
    SystemBadPageInformation = 0x0080,
    SystemProcessorProfileControlArea = 0x0081,
    SystemCombinePhysicalMemoryInformation = 0x0082,
    SystemEntropyInterruptTimingInformation = 0x0083,
    SystemConsoleInformation = 0x0084,
    SystemPlatformBinaryInformation = 0x0085,
    SystemThrottleNotificationInformation = 0x0086,
    SystemHypervisorProcessorCountInformation = 0x0087,
    SystemDeviceDataInformation = 0x0088,
    SystemDeviceDataEnumerationInformation = 0x0089,
    SystemMemoryTopologyInformation = 0x008A,
    SystemMemoryChannelInformation = 0x008B,
    SystemBootLogoInformation = 0x008C,
    SystemProcessorPerformanceInformationEx = 0x008D,
    SystemSpare0 = 0x008E,
    SystemSecureBootPolicyInformation = 0x008F,
    SystemPageFileInformationEx = 0x0090,
    SystemSecureBootInformation = 0x0091,
    SystemEntropyInterruptTimingRawInformation = 0x0092,
    SystemPortableWorkspaceEfiLauncherInformation = 0x0093,
    SystemFullProcessInformation = 0x0094,
    MaxSystemInfoClass = 0x0095

} SYSTEM_INFORMATION_CLASS, * PSYSTEM_INFORMATION_CLASS;

typedef struct _LDR_DATA_TABLE_ENTRY64
{
    LIST_ENTRY  InLoadOrderModuleList;
    LIST_ENTRY  InMemoryOrderModuleList;
    LIST_ENTRY  InInitializationOrderModuleList;
    PVOID DllBase;
    PVOID EntryPoint;
    ULONG SizeOfImage;
    UNICODE_STRING FullDllName;
    UNICODE_STRING BaseDllName;
    ULONG Flags;
    USHORT LoadCount;
    USHORT TlsIndex;
    union
    {
        LIST_ENTRY HashLinks;
        struct
        {
            PVOID SectionPointer;
            ULONG CheckSum;
        };
    };
    union
    {
        ULONG TimeDateStamp;
        PVOID LoadedImports;
    };
    PVOID EntryPointActivationContext;
    PVOID PatchInformation;
    LIST_ENTRY ForwarderLinks;
    LIST_ENTRY ServiceTagLinks;
    LIST_ENTRY StaticLinks;
} LDR_DATA_TABLE_ENTRY, * PLDR_DATA_TABLE_ENTRY;

typedef struct _LDR_DATA_TABLE_ENTRY32 {
    LIST_ENTRY32 InLoadOrderModuleList;
    LIST_ENTRY32 InMemoryOrderModuleList;
    LIST_ENTRY32 InInitializationOrderModuleList;
    ULONG DllBase;
    ULONG EntryPoint;
    ULONG SizeOfImage;
    UNICODE_STRING32 FullDllName;
    UNICODE_STRING32 BaseDllName;
    ULONG Flags;
    USHORT LoadCount;
    USHORT TlsIndex;
    union {
        LIST_ENTRY32 HashLinks;
        struct {
            ULONG SectionPointer;
            ULONG CheckSum;
        };
    };
    union {
        struct {
            ULONG TimeDateStamp;
        };
        struct {
            ULONG LoadedImports;
        };
    };

    ULONG EntryPointActivationContext;
    ULONG PatchInformation;
    LIST_ENTRY32 ForwarderLinks;
    LIST_ENTRY32 ServiceTagLinks;
    LIST_ENTRY32 StaticLinks;

} LDR_DATA_TABLE_ENTRY32, * PLDR_DATA_TABLE_ENTRY32;

typedef struct _POOL_HEADER {
    union {
        struct {
            USHORT PreviousSize : 9;
            USHORT PoolIndex : 7;
            USHORT BlockSize : 9;
            USHORT PoolType : 7;
        };
        ULONG Ulong1;   // used for InterlockedCompareExchange required by Alpha
    };
#if defined (_WIN64)
    ULONG PoolTag;
#endif
    union {
        PEPROCESS ProcessBilled;
#if !defined (_WIN64)
        ULONG PoolTag;
#endif
        struct {
            USHORT AllocatorBackTraceIndex;
            USHORT PoolTagHash;
        };
    };
} POOL_HEADER, * PPOOL_HEADER;


typedef struct _MMVIEW_WIN7 // 0x30
{
    ULONGLONG Entry; // +0x0(0x8)
    ULONGLONG Writable; // +0x8(0x8)
    struct CONTROL_AREA* ControlArea; // +0x8(0x8)
    LIST_ENTRY ViewLinks; // +0x10(0x10)
    PVOID SessionViewVa; // +0x20(0x8)
    ULONG SessionId; // +0x28(0x4)

} MMVIEW_WIN7, * PMMVIEW_WIN7;

typedef struct _MMSESSION_WIN7 // 0x58
{
    KGUARDED_MUTEX SystemSpaceViewLock; // +0x0(0x38)
    KGUARDED_MUTEX* SystemSpaceViewLockPointer; // +0x38(0x8)
    MMVIEW_WIN7* SystemSpaceViewTable; // +0x40(0x8)
    ULONG SystemSpaceHashSize; // +0x48(0x4)
    ULONG SystemSpaceHashEntries; // +0x4c(0x4)
    ULONG SystemSpaceHashKey; // +0x50(0x4)
    ULONG BitmapFailures; // +0x54(0x4)

} MMSESSION_WIN7, * PMMSESSION_WIN7;


typedef struct _MMVIEW_WIN10
{
    RTL_BALANCED_NODE SectionNode;
    ULONG64 Unkown1;              // +0x18
    ULONG_PTR ViewSize;           // +0x20
    ULONG_PTR Unkown2;            // +0x28
    PVOID ControlArea;            // +0x30
    PVOID FileObject;             // +0x38
    ULONG_PTR Unknown3;           // +0x40
    ULONG_PTR Unknown4;           // +0x48
    PVOID SessionViewVa;          // +0x50
    ULONG Unknown5;
    ULONG Unknown6;

} MMVIEW_WIN10, * PMMVIEW_WIN10;

typedef struct _MMVIEW_WIN10_NEW
{
    RTL_BALANCED_NODE SectionNode;
    ULONG64 Unkown1;              // +0x18
    ULONG_PTR ViewSize;           // +0x20
    ULONG_PTR Unkown2;            // +0x28
    PVOID ControlArea;            // +0x30
    ULONG ControlAreaFlag;        // +0x38
    PVOID FileObject;             // +0x40
    ULONG_PTR Unknown3;           // +0x48
    ULONG_PTR Unknown4;           // +0x50
    PVOID SessionViewVa;          // +0x58
    ULONG Unknown5;
    ULONG Unknown6;

} MMVIEW_WIN10_NEW, * PMMVIEW_WIN10_NEW;

typedef struct _RTL_AVL_TREE
{
    PRTL_BALANCED_NODE Root; // +0x0(0x8)

} RTL_AVL_TREE, * PRTL_AVL_TREE;

typedef struct _MMSESSION_WIN10
{
    EX_PUSH_LOCK SystemSpaceViewLock;
    PEX_PUSH_LOCK SystemSpaceViewLockPointer;
    RTL_AVL_TREE ViewRoot;
    ULONG ViewCount;
    ULONG BitmapFailures;

}MMSESSION_WIN10, * PMMSESSION_WIN10;

typedef struct _MI_SYSTEM_VA_ASSIGNMENT
{
    VOID* BaseAddress;                                                      //0x0
    ULONGLONG NumberOfBytes;                                                //0x8
} MI_SYSTEM_VA_ASSIGNMENT, * PMI_SYSTEM_VA_ASSIGNMENT;

enum _MI_ASSIGNED_REGION_TYPES
{
    AssignedRegionNonPagedPool = 0,
    AssignedRegionPagedPool = 1,
    AssignedRegionSystemCache = 2,
    AssignedRegionSystemPtes = 3,
    AssignedRegionUltraZero = 4,
    AssignedRegionPfnDatabase = 5,
    AssignedRegionCfg = 6,
    AssignedRegionHyperSpace = 7,
    AssignedRegionKernelStacks = 8,
    AssignedRegionPageTables = 9,
    AssignedRegionSession = 10,
    AssignedRegionSecureNonPagedPool = 11,
    AssignedRegionSystemImages = 12,
    AssignedRegionMaximum = 13
};

#pragma warning(disable : 4214)
typedef struct _MMPTE_HARDWARE64
{
    ULONGLONG Valid : 1;
    ULONGLONG Dirty1 : 1;
    ULONGLONG Owner : 1;
    ULONGLONG WriteThrough : 1;
    ULONGLONG CacheDisable : 1;
    ULONGLONG Accessed : 1;
    ULONGLONG Dirty : 1;
    ULONGLONG LargePage : 1;
    ULONGLONG Global : 1;
    ULONGLONG CopyOnWrite : 1;
    ULONGLONG Unused : 1;
    ULONGLONG Write : 1;
    ULONGLONG PageFrameNumber : 36;
    ULONGLONG reserved1 : 4;
    ULONGLONG SoftwareWsIndex : 11;
    ULONGLONG NoExecute : 1;
} MMPTE_HARDWARE64, * PMMPTE_HARDWARE64;

typedef struct _MMPTE
{
    union
    {
        ULONG_PTR Long;
        MMPTE_HARDWARE64 Hard;
    } u;
} MMPTE;
typedef MMPTE* PMMPTE;

//
// This structure is used by the debugger for all targets
// It is the same size as DBGKD_DATA_HEADER on all systems
//
typedef struct _DBGKD_DEBUG_DATA_HEADER64 {

    //
    // Link to other blocks
    //

    LIST_ENTRY64 List;

    //
    // This is a unique tag to identify the owner of the block.
    // If your component only uses one pool tag, use it for this, too.
    //

    ULONG           OwnerTag;

    //
    // This must be initialized to the size of the data block,
    // including this structure.
    //

    ULONG           Size;

} DBGKD_DEBUG_DATA_HEADER64, * PDBGKD_DEBUG_DATA_HEADER64;


//
// This structure is the same size on all systems.  The only field
// which must be translated by the debugger is Header.List.
//

//
// DO NOT ADD OR REMOVE FIELDS FROM THE MIDDLE OF THIS STRUCTURE!!!
//
// If you remove a field, replace it with an "unused" placeholder.
// Do not reuse fields until there has been enough time for old debuggers
// and extensions to age out.
//
typedef struct _KDDEBUGGER_DATA64 {

    DBGKD_DEBUG_DATA_HEADER64 Header;

    //
    // Base address of kernel image
    //

    ULONG64   KernBase;

    //
    // DbgBreakPointWithStatus is a function which takes an argument
    // and hits a breakpoint.  This field contains the address of the
    // breakpoint instruction.  When the debugger sees a breakpoint
    // at this address, it may retrieve the argument from the first
    // argument register, or on x86 the eax register.
    //

    ULONG64   BreakpointWithStatus;       // address of breakpoint

    //
    // Address of the saved context record during a bugcheck
    //
    // N.B. This is an automatic in KeBugcheckEx's frame, and
    // is only valid after a bugcheck.
    //

    ULONG64   SavedContext;

    //
    // help for walking stacks with user callbacks:
    //

    //
    // The address of the thread structure is provided in the
    // WAIT_STATE_CHANGE packet.  This is the offset from the base of
    // the thread structure to the pointer to the kernel stack frame
    // for the currently active usermode callback.
    //

    USHORT  ThCallbackStack;            // offset in thread data

    //
    // these values are offsets into that frame:
    //

    USHORT  NextCallback;               // saved pointer to next callback frame
    USHORT  FramePointer;               // saved frame pointer

    //
    // pad to a quad boundary
    //
    USHORT  PaeEnabled;

    //
    // Address of the kernel callout routine.
    //

    ULONG64   KiCallUserMode;             // kernel routine

    //
    // Address of the usermode entry point for callbacks.
    //

    ULONG64   KeUserCallbackDispatcher;   // address in ntdll


    //
    // Addresses of various kernel data structures and lists
    // that are of interest to the kernel debugger.
    //

    ULONG64   PsLoadedModuleList;
    ULONG64   PsActiveProcessHead;
    ULONG64   PspCidTable;

    ULONG64   ExpSystemResourcesList;
    ULONG64   ExpPagedPoolDescriptor;
    ULONG64   ExpNumberOfPagedPools;

    ULONG64   KeTimeIncrement;
    ULONG64   KeBugCheckCallbackListHead;
    ULONG64   KiBugcheckData;

    ULONG64   IopErrorLogListHead;

    ULONG64   ObpRootDirectoryObject;
    ULONG64   ObpTypeObjectType;

    ULONG64   MmSystemCacheStart;
    ULONG64   MmSystemCacheEnd;
    ULONG64   MmSystemCacheWs;

    ULONG64   MmPfnDatabase;
    ULONG64   MmSystemPtesStart;
    ULONG64   MmSystemPtesEnd;
    ULONG64   MmSubsectionBase;
    ULONG64   MmNumberOfPagingFiles;

    ULONG64   MmLowestPhysicalPage;
    ULONG64   MmHighestPhysicalPage;
    ULONG64   MmNumberOfPhysicalPages;

    ULONG64   MmMaximumNonPagedPoolInBytes;
    ULONG64   MmNonPagedSystemStart;
    ULONG64   MmNonPagedPoolStart;
    ULONG64   MmNonPagedPoolEnd;

    ULONG64   MmPagedPoolStart;
    ULONG64   MmPagedPoolEnd;
    ULONG64   MmPagedPoolInformation;
    ULONG64   MmPageSize;

    ULONG64   MmSizeOfPagedPoolInBytes;

    ULONG64   MmTotalCommitLimit;
    ULONG64   MmTotalCommittedPages;
    ULONG64   MmSharedCommit;
    ULONG64   MmDriverCommit;
    ULONG64   MmProcessCommit;
    ULONG64   MmPagedPoolCommit;
    ULONG64   MmExtendedCommit;

    ULONG64   MmZeroedPageListHead;
    ULONG64   MmFreePageListHead;
    ULONG64   MmStandbyPageListHead;
    ULONG64   MmModifiedPageListHead;
    ULONG64   MmModifiedNoWritePageListHead;
    ULONG64   MmAvailablePages;
    ULONG64   MmResidentAvailablePages;

    ULONG64   PoolTrackTable;
    ULONG64   NonPagedPoolDescriptor;

    ULONG64   MmHighestUserAddress;
    ULONG64   MmSystemRangeStart;
    ULONG64   MmUserProbeAddress;

    ULONG64   KdPrintCircularBuffer;
    ULONG64   KdPrintCircularBufferEnd;
    ULONG64   KdPrintWritePointer;
    ULONG64   KdPrintRolloverCount;

    ULONG64   MmLoadedUserImageList;

    // NT 5.1 Addition

    ULONG64   NtBuildLab;
    ULONG64   KiNormalSystemCall;

    // NT 5.0 hotfix addition

    ULONG64   KiProcessorBlock;
    ULONG64   MmUnloadedDrivers;
    ULONG64   MmLastUnloadedDriver;
    ULONG64   MmTriageActionTaken;
    ULONG64   MmSpecialPoolTag;
    ULONG64   KernelVerifier;
    ULONG64   MmVerifierData;
    ULONG64   MmAllocatedNonPagedPool;
    ULONG64   MmPeakCommitment;
    ULONG64   MmTotalCommitLimitMaximum;
    ULONG64   CmNtCSDVersion;

    // NT 5.1 Addition

    ULONG64   MmPhysicalMemoryBlock;
    ULONG64   MmSessionBase;
    ULONG64   MmSessionSize;
    ULONG64   MmSystemParentTablePage;

    // Server 2003 addition

    ULONG64   MmVirtualTranslationBase;

    USHORT    OffsetKThreadNextProcessor;
    USHORT    OffsetKThreadTeb;
    USHORT    OffsetKThreadKernelStack;
    USHORT    OffsetKThreadInitialStack;

    USHORT    OffsetKThreadApcProcess;
    USHORT    OffsetKThreadState;
    USHORT    OffsetKThreadBStore;
    USHORT    OffsetKThreadBStoreLimit;

    USHORT    SizeEProcess;
    USHORT    OffsetEprocessPeb;
    USHORT    OffsetEprocessParentCID;
    USHORT    OffsetEprocessDirectoryTableBase;

    USHORT    SizePrcb;
    USHORT    OffsetPrcbDpcRoutine;
    USHORT    OffsetPrcbCurrentThread;
    USHORT    OffsetPrcbMhz;

    USHORT    OffsetPrcbCpuType;
    USHORT    OffsetPrcbVendorString;
    USHORT    OffsetPrcbProcStateContext;
    USHORT    OffsetPrcbNumber;

    USHORT    SizeEThread;

    ULONG64   KdPrintCircularBufferPtr;
    ULONG64   KdPrintBufferSize;

    ULONG64   KeLoaderBlock;

    USHORT    SizePcr;
    USHORT    OffsetPcrSelfPcr;
    USHORT    OffsetPcrCurrentPrcb;
    USHORT    OffsetPcrContainedPrcb;

    USHORT    OffsetPcrInitialBStore;
    USHORT    OffsetPcrBStoreLimit;
    USHORT    OffsetPcrInitialStack;
    USHORT    OffsetPcrStackLimit;

    USHORT    OffsetPrcbPcrPage;
    USHORT    OffsetPrcbProcStateSpecialReg;
    USHORT    GdtR0Code;
    USHORT    GdtR0Data;

    USHORT    GdtR0Pcr;
    USHORT    GdtR3Code;
    USHORT    GdtR3Data;
    USHORT    GdtR3Teb;

    USHORT    GdtLdt;
    USHORT    GdtTss;
    USHORT    Gdt64R3CmCode;
    USHORT    Gdt64R3CmTeb;

    ULONG64   IopNumTriageDumpDataBlocks;
    ULONG64   IopTriageDumpDataBlocks;

    // Longhorn addition

    ULONG64   VfCrashDataBlock;
    ULONG64   MmBadPagesDetected;
    ULONG64   MmZeroedPageSingleBitErrorsDetected;

    // Windows 7 addition

    ULONG64   EtwpDebuggerData;
    USHORT    OffsetPrcbContext;

    // Windows 8 addition

    USHORT    OffsetPrcbMaxBreakpoints;
    USHORT    OffsetPrcbMaxWatchpoints;

    ULONG     OffsetKThreadStackLimit;
    ULONG     OffsetKThreadStackBase;
    ULONG     OffsetKThreadQueueListEntry;
    ULONG     OffsetEThreadIrpList;

    USHORT    OffsetPrcbIdleThread;
    USHORT    OffsetPrcbNormalDpcState;
    USHORT    OffsetPrcbDpcStack;
    USHORT    OffsetPrcbIsrStack;

    USHORT    SizeKDPC_STACK_FRAME;

    // Windows 8.1 Addition

    USHORT    OffsetKPriQueueThreadListHead;
    USHORT    OffsetKThreadWaitReason;

    // Windows 10 RS1 Addition

    USHORT    Padding;
    ULONG64   PteBase;

    // Windows 10 RS5 Addition

    ULONG64 RetpolineStubFunctionTable;
    ULONG RetpolineStubFunctionTableSize;
    ULONG RetpolineStubOffset;
    ULONG RetpolineStubSize;

} KDDEBUGGER_DATA64, * PKDDEBUGGER_DATA64;


typedef struct _DUMP_HEADER
{
    ULONG Signature;
    ULONG ValidDump;
    ULONG MajorVersion;
    ULONG MinorVersion;
    ULONG_PTR DirectoryTableBase;
    ULONG_PTR PfnDataBase;
    PLIST_ENTRY PsLoadedModuleList;
    PLIST_ENTRY PsActiveProcessHead;
    ULONG MachineImageType;
    ULONG NumberProcessors;
    ULONG BugCheckCode;
    ULONG_PTR BugCheckParameter1;
    ULONG_PTR BugCheckParameter2;
    ULONG_PTR BugCheckParameter3;
    ULONG_PTR BugCheckParameter4;
    CHAR VersionUser[32];
    struct _KDDEBUGGER_DATA64* KdDebuggerDataBlock;
} DUMP_HEADER, * PDUMP_HEADER;