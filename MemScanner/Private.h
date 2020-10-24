#pragma once

#include <ntifs.h>
#include "NativeStruct.h"


#ifndef _WIN64
#define DUMP_BLOCK_SIZE        0x20000
#else
#define DUMP_BLOCK_SIZE        0x40000
#endif

#ifndef _WIN64
#define KDDEBUGGER_DATA_OFFSET 0x1068
#else
#define KDDEBUGGER_DATA_OFFSET 0x2080
#endif

#define MMS_POOL_TAG           'cSmM'

#define PHYSICAL_ADDRESS_BITS  40


//
// PTE protection values
//
#define MM_ZERO_ACCESS            0
#define MM_READONLY               1
#define MM_EXECUTE                2
#define MM_EXECUTE_READ           3
#define MM_READWRITE              4
#define MM_WRITECOPY              5
#define MM_EXECUTE_READWRITE      6
#define MM_EXECUTE_WRITECOPY      7

#define MM_PTE_VALID_MASK         0x1
#define MM_PTE_WRITE_MASK         0x800
#define MM_PTE_OWNER_MASK         0x4
#define MM_PTE_WRITE_THROUGH_MASK 0x8
#define MM_PTE_CACHE_DISABLE_MASK 0x10
#define MM_PTE_ACCESS_MASK        0x20
#define MM_PTE_DIRTY_MASK         0x42
#define MM_PTE_LARGE_PAGE_MASK    0x80
#define MM_PTE_GLOBAL_MASK        0x100
#define MM_PTE_COPY_ON_WRITE_MASK 0x200
#define MM_PTE_PROTOTYPE_MASK     0x400
#define MM_PTE_TRANSITION_MASK    0x800


#define MI_SYSTEM_RANGE_START (ULONG_PTR)(0xFFFF080000000000) // start of system space

#define KI_USER_SHARED_DATA 0xFFFFF78000000000UI64

#define SharedUserData ((KUSER_SHARED_DATA * const)KI_USER_SHARED_DATA)

#ifndef PTE_SHIFT
#define PTE_SHIFT 3
#endif
#ifndef PTI_SHIFT
#define PTI_SHIFT 12
#endif
#ifndef PDI_SHIFT
#define PDI_SHIFT 21
#endif
#ifndef PPI_SHIFT
#define PPI_SHIFT 30
#endif
#ifndef PXI_SHIFT
#define PXI_SHIFT 39
#endif

#ifndef PXE_BASE
#define PXE_BASE    0xFFFFF6FB7DBED000UI64
#endif
#ifndef PXE_SELFMAP
#define PXE_SELFMAP 0xFFFFF6FB7DBEDF68UI64
#endif
#ifndef PPE_BASE
#define PPE_BASE    0xFFFFF6FB7DA00000UI64
#endif
#ifndef PDE_BASE
#define PDE_BASE    0xFFFFF6FB40000000UI64
#endif
#ifndef PTE_BASE
#define PTE_BASE    0xFFFFF68000000000UI64
#endif

#define VIRTUAL_ADDRESS_BITS 48
#define VIRTUAL_ADDRESS_MASK ((((ULONG_PTR)1) << VIRTUAL_ADDRESS_BITS) - 1)

#define PTE_PER_PAGE 512
#define PDE_PER_PAGE 512
#define PPE_PER_PAGE 512
#define PXE_PER_PAGE 512

#define PPI_MASK (PPE_PER_PAGE - 1)
#define PXI_MASK (PXE_PER_PAGE - 1)

#define MiGetPxeOffset(va) \
    ((ULONG)(((ULONG_PTR)(va) >> PXI_SHIFT) & PXI_MASK))

#define MiGetPxeAddress(va)   \
    ((PMMPTE)PXE_BASE + MiGetPxeOffset(va))

#define MiGetPpeAddress(va)   \
    ((PMMPTE)(((((ULONG_PTR)(va) & VIRTUAL_ADDRESS_MASK) >> PPI_SHIFT) << PTE_SHIFT) + PPE_BASE))

#define MiGetPdeAddress(va) \
    ((PMMPTE)(((((ULONG_PTR)(va) & VIRTUAL_ADDRESS_MASK) >> PDI_SHIFT) << PTE_SHIFT) + PDE_BASE))

#define MiGetPteAddress(va) \
    ((PMMPTE)(((((ULONG_PTR)(va) & VIRTUAL_ADDRESS_MASK) >> PTI_SHIFT) << PTE_SHIFT) + PTE_BASE))

#define VA_SHIFT (63 - 47)              // address sign extend shift count

#define MiGetVirtualAddressMappedByPte(PTE) \
    ((PVOID)((LONG_PTR)(((LONG_PTR)(PTE) - PTE_BASE) << (PAGE_SHIFT + VA_SHIFT - PTE_SHIFT)) >> VA_SHIFT))

#define MI_IS_PHYSICAL_ADDRESS(Va) \
     ((MiGetPxeAddress(Va)->u.Hard.Valid == 1) && \
     (MiGetPpeAddress(Va)->u.Hard.Valid == 1) && \
     ((MiGetPdeAddress(Va)->u.Long & 0x81) == 0x81) || (MiGetPteAddress(Va)->u.Hard.Valid == 1))



typedef enum _WinVer
{
    WINVER_7       = 0x0610,
    WINVER_7_SP1   = 0x0611,
    WINVER_8       = 0x0620,
    WINVER_81      = 0x0630,
    WINVER_10      = 0x0A00,
    WINVER_10_TH1  = 0x0A01, //
    WINVER_10_TH2  = 0x0A02,
    WINVER_10_RS1  = 0x0A03, // Anniversary update
    WINVER_10_RS2  = 0x0A04, // Creators update
    WINVER_10_RS3  = 0x0A05, // Fall creators update
    WINVER_10_RS4  = 0x0A06, // Spring creators update
    WINVER_10_RS5  = 0x0A07, // October 2018 update
    WINVER_10_19H1 = 0x0A08, // May 2019 update 19H1
    WINVER_10_19H2 = 0x0A09, // November 2019 update 19H2
    WINVER_10_20H1 = 0x0A0A, // April 2020 update 20H1

} WinVer;

typedef struct _DYNAMIC_DATA
{
    WinVer ver;            // OS version
    ULONG  buildNo;        // OS build revision

    PVOID  MmPteSpaceStart;
    PVOID  MmPteSpacecEnd;

    PVOID  MmHyperSpaceStart;
    PVOID  MmHyperSpaceEnd;

    PVOID  MmSharedSystemPageStart;
    PVOID  MmSharedSystemPageEnd;

    PVOID  MmSystemCacheWorkingSetStart;
    PVOID  MmSystemCacheWorkingSetEnd;

    PVOID  MmSystemPtesStart;
    PVOID  MmSystemPtesEnd;

    PVOID  MmDriverImageStart;
    PVOID  MmDriverImageEnd;

    PVOID  MmPagedPoolStart;
    PVOID  MmPagedPoolEnd;

    PVOID  MmNonpagedPoolStart;
    PVOID  MmNonpagedPoolEnd;

    PVOID  MmSessionSpaceStart;
    PVOID  MmSessionSpaceEnd;

    PVOID  MmDynamicVASpaceStart;   // MiVaSystemCache/MiVaSpecialPoolPaged/MiVaSpecialPoolNonPaged
    PVOID  MmDynamicVASpaceEnd;

    PVOID  MmSystemCacheStart;
    PVOID  MmSystemCacheEnd;

    PVOID  MmSpecialPoolStart;
    PVOID  MmSpecialPoolEnd;

    PVOID  MmPfnDatabaseStart;
    PVOID  MmPfnDatabaseEnd;

    PVOID  DYN_PDE_BASE;   // Win10 AU+ relocated PDE base VA
    PVOID  DYN_PTE_BASE;   // Win10 AU+ relocated PTE base VA

} DYNAMIC_DATA, * PDYNAMIC_DATA;

PVOID    GetKernelBase(OUT PULONG pSize);
VOID     InitializeDebuggerBlock();
NTSTATUS MmsInitLdrData(IN PLDR_DATA_TABLE_ENTRY pThisModule);

extern KDDEBUGGER_DATA64 g_KdBlock;