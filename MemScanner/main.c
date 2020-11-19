#include "NativeStruct.h"
#include "Private.h"
#include "Import.h"
#include "Utils.h"
#include "DriverScanner.h"
#include "SectionScanner.h"
#include <ntimage.h>



KEVENT           g_ScannerFinishEvent;

// OS Dependant data
DYNAMIC_DATA     g_dynData        = { 0 };
PDRIVER_OBJECT   g_DriverObject = NULL;

CHAR* g_szAssignedRegionNames[] = {
    "AssignedRegionNonPagedPool",
    "AssignedRegionPagedPool",
    "AssignedRegionSystemCache",
    "AssignedRegionSystemPtes",
    "AssignedRegionUltraZero",
    "AssignedRegionPfnDatabase",
    "AssignedRegionCfg",
    "AssignedRegionHyperSpace",
    "AssignedRegionKernelStacks",
    "AssignedRegionPageTables",
    "AssignedRegionSession",
    "AssignedRegionSecureNonPagedPool",
    "AssignedRegionSystemImages",
    "AssignedRegionMaximum"
};

extern POBJECT_TYPE* MmSectionObjectType;

extern PKDDEBUGGER_DATA64 g_KdDebuggerDataBlock;

//---------------------------------------------------------------------------------------------------------
NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath);
VOID     DriverUnload(PDRIVER_OBJECT DriverObject);
NTSTATUS MmsGetBuildNO(OUT PULONG pBuildNo);
NTSTATUS MmsScanSection(IN PCCHAR section, IN PCUCHAR pattern, IN UCHAR wildcard, IN ULONG_PTR len, OUT PVOID* ppFound);
NTSTATUS MmsInitDynamicData(IN OUT PDYNAMIC_DATA pData);
NTSTATUS MmsInitMemoryLayoutForWin7AndWin8(IN OUT PDYNAMIC_DATA pData);
NTSTATUS MmsInitMemoryLayoutForWin8_1ToWin10TH2(IN OUT PDYNAMIC_DATA pData);
NTSTATUS MmsInitMemoryLayoutForWin10RS1AndLater(IN OUT PDYNAMIC_DATA pData);

VOID     MmsTestAllocateMemory();
VOID     MmsScannerThread(IN PVOID StartContext);
//---------------------------------------------------------------------------------------------------------
NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath)
{
    NTSTATUS Status       = STATUS_SUCCESS;
    HANDLE   ThreadHandle = NULL;

    UNREFERENCED_PARAMETER(RegistryPath);

    InitializeDebuggerBlock();
    Status = MmsInitDynamicData(&g_dynData);
    if (!NT_SUCCESS(Status))
    {
        return Status;
    }

    Status = MmsInitLdrData((PLDR_DATA_TABLE_ENTRY)DriverObject->DriverSection);
    if (!NT_SUCCESS(Status))
    {
        return Status;
    }

    g_DriverObject = DriverObject;

    DriverObject->DriverUnload = DriverUnload;
    
    MmsTestAllocateMemory();

    KeInitializeEvent(&g_ScannerFinishEvent, NotificationEvent, FALSE);
    PsCreateSystemThread(&ThreadHandle,
        0,
        NULL,
        NtCurrentProcess(),
        NULL,
        MmsScannerThread,
        NULL);

    if (ThreadHandle)
    {
        ZwClose(ThreadHandle);
    }

    return STATUS_SUCCESS;
}
//---------------------------------------------------------------------------------------------------------
VOID MmsScannerThread(IN PVOID StartContext)
{
    LARGE_INTEGER liDelayTime = { 0 };

    liDelayTime.QuadPart = -1000 * 10000;
    KeDelayExecutionThread(KernelMode, FALSE, &liDelayTime);

    ScanDriver();
    ScanSection();

    KeSetEvent(&g_ScannerFinishEvent, IO_NO_INCREMENT, FALSE);

    PsTerminateSystemThread(STATUS_SUCCESS);
}
//---------------------------------------------------------------------------------------------------------
VOID DriverUnload(PDRIVER_OBJECT DriverObject)
{
    UNREFERENCED_PARAMETER(DriverObject);

    DbgPrint("[%s] Unloading\n", __FUNCTION__);

    KeWaitForSingleObject(&g_ScannerFinishEvent, Executive, KernelMode, FALSE, NULL);

    DbgPrint("[%s] Unload Complete\n", __FUNCTION__);

    return;
}
//---------------------------------------------------------------------------------------------------------
NTSTATUS MmsScanSection(IN PCCHAR section, IN PCUCHAR pattern, IN UCHAR wildcard, IN ULONG_PTR len, OUT PVOID* ppFound)
{
    ASSERT(ppFound != NULL);
    if (ppFound == NULL)
        return STATUS_INVALID_PARAMETER;

    PVOID base = GetKernelBase(NULL);
    if (!base)
        return STATUS_NOT_FOUND;

    PIMAGE_NT_HEADERS64 pHdr = RtlImageNtHeader(base);
    if (!pHdr)
        return STATUS_INVALID_IMAGE_FORMAT;

    PIMAGE_SECTION_HEADER pFirstSection = (PIMAGE_SECTION_HEADER)(pHdr + 1);
    for (PIMAGE_SECTION_HEADER pSection = pFirstSection; pSection < pFirstSection + pHdr->FileHeader.NumberOfSections; pSection++)
    {
        ANSI_STRING s1, s2;
        RtlInitAnsiString(&s1, section);
        RtlInitAnsiString(&s2, (PCCHAR)pSection->Name);
        if (RtlCompareString(&s1, &s2, TRUE) == 0)
        {
            PVOID ptr = NULL;
            NTSTATUS status = MmsSearchPattern(pattern, wildcard, len, (PUCHAR)base + pSection->VirtualAddress, pSection->Misc.VirtualSize, &ptr);
            if (NT_SUCCESS(status))
                *ppFound = ptr;

            return status;
        }
    }

    return STATUS_NOT_FOUND;
}
//---------------------------------------------------------------------------------------------------------
NTSTATUS MmsGetBuildNO(OUT PULONG pBuildNo)
{
    ASSERT(pBuildNo != NULL);
    if (pBuildNo == NULL)
        return STATUS_INVALID_PARAMETER;

    NTSTATUS status = STATUS_SUCCESS;
    UNICODE_STRING strRegKey = RTL_CONSTANT_STRING(L"\\Registry\\Machine\\Software\\Microsoft\\Windows NT\\CurrentVersion");
    UNICODE_STRING strRegValue = RTL_CONSTANT_STRING(L"BuildLabEx");
    UNICODE_STRING strRegValue10 = RTL_CONSTANT_STRING(L"UBR");
    UNICODE_STRING strVerVal = { 0 };
    HANDLE hKey = NULL;
    OBJECT_ATTRIBUTES keyAttr = { 0 };

    InitializeObjectAttributes(&keyAttr, &strRegKey, OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE, NULL, NULL);

    status = ZwOpenKey(&hKey, KEY_READ, &keyAttr);
    if (NT_SUCCESS(status))
    {
        PKEY_VALUE_FULL_INFORMATION pValueInfo = ExAllocatePoolWithTag(PagedPool, PAGE_SIZE, MMS_POOL_TAG);
        ULONG bytes = 0;

        if (pValueInfo)
        {
            // Try query UBR value
            status = ZwQueryValueKey(hKey, &strRegValue10, KeyValueFullInformation, pValueInfo, PAGE_SIZE, &bytes);
            if (NT_SUCCESS(status))
            {
                *pBuildNo = *(PULONG)((PUCHAR)pValueInfo + pValueInfo->DataOffset);
                goto skip1;
            }

            status = ZwQueryValueKey(hKey, &strRegValue, KeyValueFullInformation, pValueInfo, PAGE_SIZE, &bytes);
            if (NT_SUCCESS(status))
            {
                PWCHAR pData = (PWCHAR)((PUCHAR)pValueInfo->Name + pValueInfo->NameLength);
                for (ULONG i = 0; i < pValueInfo->DataLength; i++)
                {
                    if (pData[i] == L'.')
                    {
                        for (ULONG j = i + 1; j < pValueInfo->DataLength; j++)
                        {
                            if (pData[j] == L'.')
                            {
                                strVerVal.Buffer = &pData[i] + 1;
                                strVerVal.Length = strVerVal.MaximumLength = (USHORT)((j - i) * sizeof(WCHAR));
                                status = RtlUnicodeStringToInteger(&strVerVal, 10, pBuildNo);

                                goto skip1;
                            }
                        }
                    }
                }

            skip1:;
            }

            ExFreePoolWithTag(pValueInfo, MMS_POOL_TAG);
        }
        else
            status = STATUS_NO_MEMORY;

        ZwClose(hKey);
    }
    else
        DbgPrint("[%s] ZwOpenKey failed with status 0x%X\n", __FUNCTION__, status);

    return status;
}
//---------------------------------------------------------------------------------------------------------
NTSTATUS MmsInitDynamicData(IN OUT PDYNAMIC_DATA pData)
{
    NTSTATUS             status = STATUS_SUCCESS;
    RTL_OSVERSIONINFOEXW verInfo = { 0 };

    if (pData == NULL)
    {
        return STATUS_INVALID_ADDRESS;
    }

    RtlZeroMemory(pData, sizeof(DYNAMIC_DATA));
    pData->DYN_PDE_BASE = (PVOID)PDE_BASE;
    pData->DYN_PTE_BASE = (PVOID)PTE_BASE;

    verInfo.dwOSVersionInfoSize = sizeof(verInfo);
    status = RtlGetVersion((PRTL_OSVERSIONINFOW)&verInfo);

    if (status != STATUS_SUCCESS)
    {
        return status;
    }

    ULONG ver_short = (verInfo.dwMajorVersion << 8) | (verInfo.dwMinorVersion << 4) | verInfo.wServicePackMajor;
    pData->ver = (WinVer)ver_short;

    // Get kernel build number
    status = MmsGetBuildNO(&pData->buildNo);

    DbgPrint(
        "[%s] OS version %d.%d.%d.%d.%d - 0x%x\n",
        __FUNCTION__,
        verInfo.dwMajorVersion,
        verInfo.dwMinorVersion,
        verInfo.dwBuildNumber,
        verInfo.wServicePackMajor,
        pData->buildNo,
        ver_short
    );

    switch (ver_short)
    {
        // Windows 7
        // Windows 7 SP1
    case WINVER_7:
    case WINVER_7_SP1:
        break;

        // Windows 8
    case WINVER_8:
        break;

        // Windows 8.1
    case WINVER_81:
        break;

        // Windows 10, build 16299/15063/14393/10586/10140
    case WINVER_10:

        if (verInfo.dwBuildNumber == 10240)
        {
            pData->ver = WINVER_10_TH1;
            break;
        }
        else if (verInfo.dwBuildNumber == 10586)
        {
            pData->ver = WINVER_10_TH2;
            break;
        }
        else if (verInfo.dwBuildNumber == 14393)
        {
            pData->ver = WINVER_10_RS1;
            break;
        }
        else if (verInfo.dwBuildNumber == 15063)
        {
            pData->ver = WINVER_10_RS2;
            break;
        }
        else if (verInfo.dwBuildNumber == 16299)
        {
            pData->ver = WINVER_10_RS3;
            break;
        }
        else if (verInfo.dwBuildNumber == 17134)
        {
            pData->ver = WINVER_10_RS4;
            break;
        }
        else if (verInfo.dwBuildNumber == 17763)
        {
            pData->ver = WINVER_10_RS5;
            break;
        }
        else if (verInfo.dwBuildNumber == 18362 || verInfo.dwBuildNumber == 18363)
        {
            pData->ver = verInfo.dwBuildNumber == 18362 ? WINVER_10_19H1 : WINVER_10_19H2;
            break;
        }
        else if (verInfo.dwBuildNumber == 19041)
        {
            pData->ver = WINVER_10_20H1;
            break;
        }
        else
        {
            return STATUS_NOT_SUPPORTED;
        }
    default:
        break;
    }

    if (pData->ver >= WINVER_7 && pData->ver <= WINVER_8)
    {
        status = MmsInitMemoryLayoutForWin7AndWin8(pData);
    }
    else if (pData->ver >= WINVER_81 && pData->ver <= WINVER_10_TH2)
    {
        status = MmsInitMemoryLayoutForWin8_1ToWin10TH2(pData);
    }
    else if (pData->ver >= WINVER_10_RS1)
    {
        status = MmsInitMemoryLayoutForWin10RS1AndLater(pData);

        DbgPrint("[%s] g_KdBlock->KernBase: %p, GetKernelBase() = 0x%p\n", __FUNCTION__, g_KdBlock.KernBase, GetKernelBase(NULL));

        ULONGLONG mask = (1ll << (PHYSICAL_ADDRESS_BITS - 1)) - 1;
        g_dynData.DYN_PTE_BASE = (PVOID)g_KdBlock.PteBase;
        g_dynData.DYN_PDE_BASE = (PVOID)((g_KdBlock.PteBase & ~mask) | ((g_KdBlock.PteBase >> 9) & mask));
    }

    DbgPrint("[%s] MmPagedPoolStart: 0x%p, MmPagedPoolEnd = 0x%p \n",       __FUNCTION__, pData->MmPagedPoolStart, pData->MmPagedPoolEnd);
    DbgPrint("[%s] MmNonpagedPoolStart: 0x%p, MmNonpagedPoolEnd = 0x%p \n", __FUNCTION__, pData->MmNonpagedPoolStart, pData->MmNonpagedPoolEnd);
    DbgPrint("[%s] MmSystemPtesStart: 0x%p, MmSystemPtesEnd = 0x%p \n",     __FUNCTION__, pData->MmSystemPtesStart, pData->MmSystemPtesEnd);
    DbgPrint("[%s] MmDriverImageStart: 0x%p, MmDriverImageEnd = 0x%p \n",   __FUNCTION__, pData->MmDriverImageStart, pData->MmDriverImageEnd);
    DbgPrint("[%s] PDE_BASE: %p, PTE_BASE: %p\n",                           __FUNCTION__, pData->DYN_PDE_BASE, pData->DYN_PTE_BASE);

    if ((ULONG_PTR)pData->DYN_PDE_BASE < MI_SYSTEM_RANGE_START || (ULONG_PTR)pData->DYN_PTE_BASE < MI_SYSTEM_RANGE_START)
    {
        DbgPrint("[%s] Invalid PDE/PTE base, aborting\n", __FUNCTION__);
        return STATUS_UNSUCCESSFUL;
    }

    return status;

}
//---------------------------------------------------------------------------------------------------------
NTSTATUS MmsInitMemoryLayoutForWin7AndWin8(IN OUT PDYNAMIC_DATA pData)
{
    if (!pData)
    {
        return STATUS_INVALID_ADDRESS;
    }

    if (!g_KdBlock.MmNonPagedPoolStart || !g_KdBlock.MmMaximumNonPagedPoolInBytes)
    {
        return STATUS_UNSUCCESSFUL;
    }

    // 可扩展区域
    pData->MmNonpagedPoolStart = *(PVOID*)g_KdBlock.MmNonPagedPoolStart;
    pData->MmNonpagedPoolEnd   = (PVOID)((PUCHAR)pData->MmNonpagedPoolStart + *(PULONG_PTR)g_KdBlock.MmMaximumNonPagedPoolInBytes - 1);

    pData->MmPteSpaceStart   = (PVOID)0xFFFFF68000000000;
    pData->MmPteSpacecEnd    = (PVOID)0xFFFFF6FFFFFFFFFF;

    pData->MmHyperSpaceStart = (PVOID)0xFFFFF70000000000;
    pData->MmHyperSpaceEnd   = (PVOID)0xFFFFF77FFFFFFFFF;

    pData->MmSharedSystemPageStart = (PVOID)0xFFFFF78000000000;
    pData->MmSharedSystemPageEnd   = (PVOID)0xFFFFF78000000FFF;

    pData->MmSystemCacheWorkingSetStart = (PVOID)0xFFFFF78000001000;
    pData->MmSystemCacheWorkingSetEnd   = (PVOID)0xFFFFF7FFFFFFFFFF;

    pData->MmDriverImageStart = (PVOID)0xFFFFF80000000000;
    pData->MmDriverImageEnd   = (PVOID)0xFFFFF87FFFFFFFFF;

    pData->MmSystemPtesStart  = (PVOID)0xFFFFF88000000000;
    pData->MmSystemPtesEnd    = (PVOID)0xFFFFF89FFFFFFFFF;

    pData->MmPagedPoolStart   = (PVOID)0xFFFFF8A000000000;
    pData->MmPagedPoolEnd     = (PVOID)0xFFFFF8BFFFFFFFFF;

    pData->MmSessionSpaceStart = (PVOID)0xFFFFF90000000000;
    pData->MmSessionSpaceEnd   = (PVOID)0xFFFFF97FFFFFFFFF;

    pData->MmDynamicVASpaceStart = (PVOID)0xFFFFF98000000000;
    pData->MmDynamicVASpaceEnd   = (PVOID)0xFFFFFA70FFFFFFFF;

    pData->MmPfnDatabaseStart = (PVOID)0xFFFFFA8000000000;
    pData->MmPfnDatabaseEnd   = (PVOID)((ULONG_PTR)pData->MmNonpagedPoolStart - 1);

    return STATUS_SUCCESS;
}
//---------------------------------------------------------------------------------------------------------
NTSTATUS MmsInitMemoryLayoutForWin8_1ToWin10TH2(IN OUT PDYNAMIC_DATA pData)
{
    if (!pData)
    {
        return STATUS_INVALID_ADDRESS;
    }

    pData->MmPteSpaceStart = (PVOID)0xFFFFF68000000000;
    pData->MmPteSpacecEnd  = (PVOID)0xFFFFF6FFFFFFFFFF;

    pData->MmHyperSpaceStart = (PVOID)0xFFFFF70000000000;
    pData->MmHyperSpaceEnd   = (PVOID)0xFFFFF77FFFFFFFFF;

    pData->MmSharedSystemPageStart = (PVOID)0xFFFFF78000000000;
    pData->MmSharedSystemPageEnd   = (PVOID)0xFFFFF78000000FFF;

    pData->MmSystemCacheStart = (PVOID)0xFFFFB00000000000;
    pData->MmSystemCacheEnd   = (PVOID)0xFFFFBFFFFFFFFFFF;

    pData->MmPagedPoolStart = (PVOID)0xFFFFC00000000000;
    pData->MmPagedPoolEnd   = (PVOID)0xFFFFCF7FFFFFFFFF;

    pData->MmSpecialPoolStart = (PVOID)0xFFFFCF8000000000;
    pData->MmSpecialPoolEnd   = (PVOID)0xFFFFCFFFFFFFFFFF;

    pData->MmSystemPtesStart = (PVOID)0xFFFFD00000000000;
    pData->MmSystemPtesEnd   = (PVOID)0xFFFFDFFFFFFFFFFF;

    pData->MmNonpagedPoolStart = (PVOID)0xFFFFE00000000000;
    pData->MmNonpagedPoolEnd   = (PVOID)0xFFFFF00000000000;//等分成KeNumberNodes块

    pData->MmDriverImageStart = (PVOID)0xFFFFF80000000000;
    pData->MmDriverImageEnd   = (PVOID)0xFFFFF87FFFFFFFFF;

    pData->MmSessionSpaceStart = (PVOID)0xFFFFF90000000000;
    pData->MmSessionSpaceEnd   = (PVOID)0xFFFFF97FFFFFFFFF;

    pData->MmDynamicVASpaceStart = (PVOID)0xFFFFF98000000000;
    pData->MmDynamicVASpaceEnd   = (PVOID)0xFFFFFA70FFFFFFFF;

    pData->MmPfnDatabaseStart = (PVOID)0xFFFFFA8000000000;
    pData->MmPfnDatabaseEnd   = (PVOID)((ULONG_PTR)pData->MmNonpagedPoolStart - 1);

    return STATUS_SUCCESS;
}
//---------------------------------------------------------------------------------------------------------
NTSTATUS MmsInitMemoryLayoutForWin10RS1AndLater(IN OUT PDYNAMIC_DATA pData)
{
    ULONG                     ulIndex                = 0;
    PVOID                     lpTargetAddr           = NULL;
    PMI_SYSTEM_VA_ASSIGNMENT  lpMiSystemVaAssignment = NULL;

    if (!pData)
    {
        return STATUS_INVALID_ADDRESS;
    }

    MmsScanSection(".text", 
        (PCUCHAR)"\x48\x63\xC1\x48\x8D\x0D\xCC\xCC\xCC\xCC\x48\x03\xC0\x48\x8B\x04\xC1\xC3", 
        0xCC, 
        18, 
        (PVOID)&lpTargetAddr);

    if (!lpTargetAddr)
    {
        DbgPrint("[%s] MmsScanSection Failed\n", __FUNCTION__);
        return STATUS_NOT_FOUND;
    }

    lpMiSystemVaAssignment = (PMI_SYSTEM_VA_ASSIGNMENT)((PUCHAR)lpTargetAddr + *(PULONG)((PUCHAR)lpTargetAddr + 6) + 10);
    for (ulIndex = 0; ulIndex < AssignedRegionMaximum; ulIndex++)
    {
        DbgPrint("[%s] Names:%s, BaseAddr:%I64x, Size:%I64x\n", 
            __FUNCTION__, 
            g_szAssignedRegionNames[ulIndex],
            lpMiSystemVaAssignment[ulIndex].BaseAddress, 
            lpMiSystemVaAssignment[ulIndex].NumberOfBytes);
    }

    pData->MmPteSpaceStart = (PVOID)lpMiSystemVaAssignment[AssignedRegionPageTables].BaseAddress;
    pData->MmPteSpacecEnd  = (PVOID)((PUCHAR)lpMiSystemVaAssignment[AssignedRegionPageTables].BaseAddress + lpMiSystemVaAssignment[AssignedRegionPageTables].NumberOfBytes - 1);

    pData->MmHyperSpaceStart = (PVOID)lpMiSystemVaAssignment[AssignedRegionHyperSpace].BaseAddress;
    pData->MmHyperSpaceEnd   = (PVOID)((PUCHAR)lpMiSystemVaAssignment[AssignedRegionHyperSpace].BaseAddress + lpMiSystemVaAssignment[AssignedRegionHyperSpace].NumberOfBytes - 1);

    pData->MmSharedSystemPageStart = (PVOID)0xFFFFF78000000000;
    pData->MmSharedSystemPageEnd   = (PVOID)0xFFFFF78000000FFF;

    pData->MmSystemCacheStart = (PVOID)lpMiSystemVaAssignment[AssignedRegionSystemCache].BaseAddress;
    pData->MmSystemCacheEnd   = (PVOID)((PUCHAR)lpMiSystemVaAssignment[AssignedRegionSystemCache].BaseAddress + lpMiSystemVaAssignment[AssignedRegionSystemCache].NumberOfBytes - 1);

    pData->MmPagedPoolStart = (PVOID)lpMiSystemVaAssignment[AssignedRegionPagedPool].BaseAddress;
    pData->MmPagedPoolEnd   = (PVOID)((PUCHAR)lpMiSystemVaAssignment[AssignedRegionPagedPool].BaseAddress + lpMiSystemVaAssignment[AssignedRegionPagedPool].NumberOfBytes - 1);

    pData->MmSpecialPoolStart = (PVOID)NULL;
    pData->MmSpecialPoolEnd   = (PVOID)NULL;

    pData->MmSystemPtesStart = (PVOID)lpMiSystemVaAssignment[AssignedRegionSystemPtes].BaseAddress;
    pData->MmSystemPtesEnd   = (PVOID)((PUCHAR)lpMiSystemVaAssignment[AssignedRegionSystemPtes].BaseAddress + lpMiSystemVaAssignment[AssignedRegionSystemPtes].NumberOfBytes - 1);

    pData->MmNonpagedPoolStart = (PVOID)lpMiSystemVaAssignment[AssignedRegionNonPagedPool].BaseAddress;
    pData->MmNonpagedPoolEnd   = (PVOID)((PUCHAR)lpMiSystemVaAssignment[AssignedRegionNonPagedPool].BaseAddress + lpMiSystemVaAssignment[AssignedRegionNonPagedPool].NumberOfBytes - 1);//等分成KeNumberNodes块

    if (pData->ver == WINVER_10_RS1)
    {
        pData->MmDriverImageStart = (PVOID)lpMiSystemVaAssignment[13].BaseAddress;
        pData->MmDriverImageEnd   = (PVOID)((PUCHAR)lpMiSystemVaAssignment[13].BaseAddress + lpMiSystemVaAssignment[13].NumberOfBytes - 1);

        pData->MmSessionSpaceStart = (PVOID)lpMiSystemVaAssignment[10].BaseAddress;
        pData->MmSessionSpaceEnd   = (PVOID)((PUCHAR)lpMiSystemVaAssignment[10].BaseAddress + lpMiSystemVaAssignment[10].NumberOfBytes - 1);
    }
    else if (pData->ver == WINVER_10_RS2)
    {
        pData->MmDriverImageStart = (PVOID)lpMiSystemVaAssignment[12].BaseAddress;
        pData->MmDriverImageEnd   = (PVOID)((PUCHAR)lpMiSystemVaAssignment[12].BaseAddress + lpMiSystemVaAssignment[12].NumberOfBytes - 1);

        pData->MmSessionSpaceStart = (PVOID)lpMiSystemVaAssignment[11].BaseAddress;
        pData->MmSessionSpaceEnd   = (PVOID)((PUCHAR)lpMiSystemVaAssignment[11].BaseAddress + lpMiSystemVaAssignment[11].NumberOfBytes - 1);
    }
    else if (pData->ver >= WINVER_10_RS3 && pData->ver <= WINVER_10_RS5)
    {
        pData->MmDriverImageStart = (PVOID)lpMiSystemVaAssignment[13].BaseAddress;
        pData->MmDriverImageEnd   = (PVOID)((PUCHAR)lpMiSystemVaAssignment[13].BaseAddress + lpMiSystemVaAssignment[13].NumberOfBytes - 1);

        pData->MmSessionSpaceStart = (PVOID)lpMiSystemVaAssignment[12].BaseAddress;
        pData->MmSessionSpaceEnd   = (PVOID)((PUCHAR)lpMiSystemVaAssignment[12].BaseAddress + lpMiSystemVaAssignment[12].NumberOfBytes - 1);
    }
    else if (pData->ver == WINVER_10_19H1 || pData->ver == WINVER_10_19H2)
    {
        pData->MmDriverImageStart = (PVOID)lpMiSystemVaAssignment[11].BaseAddress;
        pData->MmDriverImageEnd   = (PVOID)((PUCHAR)lpMiSystemVaAssignment[11].BaseAddress + lpMiSystemVaAssignment[11].NumberOfBytes - 1);

        pData->MmSessionSpaceStart = (PVOID)lpMiSystemVaAssignment[10].BaseAddress;
        pData->MmSessionSpaceEnd   = (PVOID)((PUCHAR)lpMiSystemVaAssignment[10].BaseAddress + lpMiSystemVaAssignment[10].NumberOfBytes - 1);
    }
    else if (pData->ver >= WINVER_10_20H1)
    {
        pData->MmDriverImageStart = (PVOID)lpMiSystemVaAssignment[AssignedRegionSystemImages].BaseAddress;
        pData->MmDriverImageEnd   = (PVOID)((PUCHAR)lpMiSystemVaAssignment[AssignedRegionSystemImages].BaseAddress + lpMiSystemVaAssignment[AssignedRegionSystemImages].NumberOfBytes - 1);

        pData->MmSessionSpaceStart = (PVOID)lpMiSystemVaAssignment[10].BaseAddress;
        pData->MmSessionSpaceEnd   = (PVOID)((PUCHAR)lpMiSystemVaAssignment[10].BaseAddress + lpMiSystemVaAssignment[10].NumberOfBytes - 1);
    }

    pData->MmDynamicVASpaceStart = (PVOID)NULL;
    pData->MmDynamicVASpaceEnd   = (PVOID)NULL;

    pData->MmPfnDatabaseStart = (PVOID)lpMiSystemVaAssignment[AssignedRegionPfnDatabase].BaseAddress;
    pData->MmPfnDatabaseEnd   = (PVOID)((PUCHAR)lpMiSystemVaAssignment[AssignedRegionPfnDatabase].BaseAddress + lpMiSystemVaAssignment[AssignedRegionPfnDatabase].NumberOfBytes - 1);

    return STATUS_SUCCESS;
}
//---------------------------------------------------------------------------------------------------------
VOID MmsTestAllocatePagedPoolMemory()
{
    PVOID lpAddr = NULL;

    lpAddr = ExAllocatePoolWithTag(PagedPool, 256, MMS_POOL_TAG);
    if (lpAddr)
    {
        DbgPrint("[%s] AllocateAddress:%p\n", __FUNCTION__, lpAddr);
        ExFreePool(lpAddr);
    }
}
//---------------------------------------------------------------------------------------------------------
VOID MmsTestAllocateNonPagedPoolMemory()
{
    PVOID lpAddr = NULL;

    lpAddr = ExAllocatePoolWithTag(NonPagedPool, 256, MMS_POOL_TAG);
    if (lpAddr)
    {
        DbgPrint("[%s] AllocateAddress:%p\n", __FUNCTION__, lpAddr);
        ExFreePool(lpAddr);
    }
}
//---------------------------------------------------------------------------------------------------------
VOID MmsTestAllocateMDLMemory()
{
    PHYSICAL_ADDRESS Low = { 0 };
    PHYSICAL_ADDRESS High = { 0 };
    PHYSICAL_ADDRESS Skip = { 0 };
    SIZE_T           SizeOfBytes = 0x332000;

    High.QuadPart = 0x10000000000000;

    PMDL pMdl = MmAllocatePagesForMdl(Low, High, Skip, SizeOfBytes);
    if (pMdl)
    {
        PVOID lpMappedAddr = MmMapLockedPagesSpecifyCache(pMdl, KernelMode, MmNonCached, NULL, 0, 0);
        if (lpMappedAddr)
        {
            DbgPrint("[%s] AllocateAddress:%p\n", __FUNCTION__, lpMappedAddr);

            MmUnmapLockedPages(lpMappedAddr, pMdl);
            lpMappedAddr;
        }

        MmFreePagesFromMdl(pMdl);
        ExFreePool(pMdl);
    }
}
//---------------------------------------------------------------------------------------------------------
VOID MmsTestMapViewInSystemSpace()
{
    OBJECT_ATTRIBUTES oa;
    NTSTATUS          Status        = STATUS_SUCCESS;
    UNICODE_STRING    uniDllName    = { 0 };
    IO_STATUS_BLOCK   IoStatusblock = { 0 };
    HANDLE            hFileHandle   = NULL;
    HANDLE            hSection      = NULL;
    PVOID             SectionObject = NULL;
    PVOID             MappedAddr    = NULL;
    SIZE_T            MappedSize    = 0;

    RtlInitUnicodeString(&uniDllName, L"\\SystemRoot\\System32\\ntdll.dll");
    InitializeObjectAttributes(&oa, &uniDllName, OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE, NULL, NULL);

    Status = ZwCreateFile(&hFileHandle,
        FILE_READ_ACCESS,
        &oa,
        &IoStatusblock,
        NULL,
        0,
        FILE_SHARE_READ,
        FILE_OPEN,
        0,
        NULL,
        0);

    if (!NT_SUCCESS(Status))
    {
        return;
    }

    InitializeObjectAttributes(&oa, NULL, OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE, NULL, NULL);
    Status = ZwCreateSection(&hSection,
        STANDARD_RIGHTS_REQUIRED | SECTION_QUERY | SECTION_MAP_READ,
        &oa,
        NULL,
        PAGE_READONLY,
        SEC_IMAGE,
        hFileHandle);

    if (!NT_SUCCESS(Status))
    {
        goto Cleanup;
    }

    Status = ObReferenceObjectByHandle(hSection, 0, *MmSectionObjectType, KernelMode, &SectionObject, NULL);
    if (!NT_SUCCESS(Status))
    {
        goto Cleanup;
    }

    MmMapViewInSystemSpace(SectionObject, &MappedAddr, &MappedSize);
    DbgPrint("[%s] MappedAddr:%p MappedSize:%x\n", __FUNCTION__, MappedAddr, MappedSize);

Cleanup:

    if (MappedAddr)
    {
        MmUnmapViewInSystemSpace(MappedAddr);
        MappedAddr = NULL;
    }

    if (SectionObject)
    {
        ObDereferenceObject(SectionObject);
        SectionObject = NULL;
    }

    if (hSection)
    {
        ZwClose(hSection);
        hSection = NULL;
    }

    if (hFileHandle)
    {
        ZwClose(hFileHandle);
        hFileHandle = NULL;
    }

    return;
}
//---------------------------------------------------------------------------------------------------------
VOID MmsTestAllocateContiguousMemory()
{
    PVOID            lpVirtualAddr        = NULL;
    PHYSICAL_ADDRESS HighestAcceptAddress = {0};
    HighestAcceptAddress.QuadPart = 1000000000;

    // 申请连续的不可分页物理内存空间 并映射到系统空间
    lpVirtualAddr = MmAllocateContiguousMemory(PAGE_SIZE * 10, HighestAcceptAddress);
    if (lpVirtualAddr)
    {
        DbgPrint("[%s] lpVirtualAddr:%p\n", __FUNCTION__, lpVirtualAddr);
        MmFreeContiguousMemory(lpVirtualAddr);
    }
}
//---------------------------------------------------------------------------------------------------------
VOID MmsTestAllocateMemory()
{
    MmsTestAllocatePagedPoolMemory();
    MmsTestAllocateNonPagedPoolMemory();
    MmsTestMapViewInSystemSpace();
    MmsTestAllocateMDLMemory();
    MmsTestAllocateContiguousMemory();
}
//---------------------------------------------------------------------------------------------------------