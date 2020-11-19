#include "DriverScanner.h"
#include "Private.h"
#include "Utils.h"


extern POBJECT_TYPE* IoDriverObjectType;

extern DYNAMIC_DATA   g_dynData;
extern PDRIVER_OBJECT g_DriverObject;
//-------------------------------------------------------------------------------------------------------------------------------------
VOID ScanDriverByDriverObjectMemory()
{
    PVOID                    lpStartAddr     = NULL;
    SIZE_T                   ulSize          = 0;
    ULONG_PTR                lpSearchAddr    = 0;
    ULONG_PTR                lpEndAddr       = 0;
    ULONG                    ulEntrySize     = 0;
    ULONG                    ulCurrentSize   = 0;
    ULONG_PTR                pDriverObject   = 0;
    NTSTATUS                 status          = STATUS_SUCCESS;
    PKLDR_DATA_TABLE_ENTRY   pLdr            = NULL;


    if (g_dynData.ver >= WINVER_7)
    {
        lpStartAddr = g_DriverObject;
        lpStartAddr = (PVOID)((ULONG_PTR)lpStartAddr & 0xFFFFFFFF00000000);
        ulSize = 0x300000000;
    }
    else
    {
        return;
    }

    lpSearchAddr = (ULONG_PTR)lpStartAddr;
    lpEndAddr    = lpSearchAddr + ulSize - sizeof(DRIVER_OBJECT);

    KdPrint(("[%s] lpSearchAddr:%p lpEndAddr:%p\n", __FUNCTION__, lpSearchAddr, lpEndAddr));

    while (TRUE)
    {
        if (lpSearchAddr + PAGE_SIZE > lpEndAddr)
        {
            ulEntrySize = (ULONG)(lpEndAddr - lpSearchAddr);
        }
        else
        {
            ulEntrySize = PAGE_SIZE;
        }

        if (!MmsIsAddressValidLength((PVOID)lpSearchAddr, ulEntrySize))
        {
            goto NextLoop;
        }

        pDriverObject = lpSearchAddr;

        ulCurrentSize = 0;
        ulEntrySize  -= sizeof(DRIVER_OBJECT);

        while (ulCurrentSize < ulEntrySize)
        {
            if (MmsIsRealDriverObject((PDRIVER_OBJECT)pDriverObject))
            {
                pLdr = (PKLDR_DATA_TABLE_ENTRY)(((PDRIVER_OBJECT)pDriverObject)->DriverSection);
                KdPrint(("[%s] pDriverObject:%p FullName:%wZ, DllBase:%I64x, Size:%x\n", __FUNCTION__, pDriverObject, &pLdr->FullDllName, pLdr->DllBase, pLdr->SizeOfImage));

                ulCurrentSize += sizeof(DRIVER_OBJECT);
                pDriverObject += sizeof(DRIVER_OBJECT);
            }
            else
            {
                ulCurrentSize += sizeof(ULONG_PTR);
                pDriverObject += sizeof(ULONG_PTR);
            }
        }

    NextLoop:
        lpSearchAddr += PAGE_SIZE;
        if (lpSearchAddr >= lpEndAddr)
        {
            break;
        }
    }
}
//-------------------------------------------------------------------------------------------------------------------------------------
VOID ScanDriverByLdrDataTableEntryMemory()
{
    PVOID                  lpStartAddr  = NULL;
    SIZE_T                 ulSize       = 0;
    ULONG_PTR              lpSearchAddr = 0;
    ULONG_PTR              lpTargetAddr = 0;
    ULONG                  ulEntrySize  = 0;
    ULONG_PTR              lpEndAddr    = 0;
    PLDR_DATA_TABLE_ENTRY  lpLdrEntry   = NULL;
    PPOOL_HEADER           PoolHeader   = NULL;

    if (g_dynData.ver >= WINVER_7)
    {
        lpStartAddr = g_DriverObject->DriverSection;
        lpStartAddr = (PVOID)((ULONG_PTR)lpStartAddr & 0xFFFFFFFF00000000);
        ulSize = 0x300000000;
    }
    else
    {
        return;
    }

    if (!lpStartAddr)
    {
        return;
    }

    lpSearchAddr = (ULONG_PTR)lpStartAddr;
    lpEndAddr    = lpSearchAddr + ulSize - sizeof(POOL_HEADER);

    KdPrint(("[%s] lpSearchAddr:%p lpEndAddr:%p\n", __FUNCTION__, lpSearchAddr, lpEndAddr));

    // Search For _ldr_data_table_entry
    while (TRUE)
    {
        if (lpSearchAddr + PAGE_SIZE > lpEndAddr)
        {
            ulEntrySize = (ULONG)(lpEndAddr - lpSearchAddr);
        }
        else
        {
            ulEntrySize = PAGE_SIZE;
        }

        if (!MmsIsAddressValidLength((PVOID)lpSearchAddr, ulEntrySize))
        {
            goto NextLoop;
        }

        lpTargetAddr = lpSearchAddr;

        while (TRUE)
        {
            PoolHeader = (PPOOL_HEADER)lpTargetAddr;
            if (PoolHeader->PoolTag == 'dLmM')
            {
                lpLdrEntry = (PLDR_DATA_TABLE_ENTRY)(lpTargetAddr + sizeof(POOL_HEADER));
                if (lpTargetAddr + sizeof(LDR_DATA_TABLE_ENTRY) + sizeof(POOL_HEADER) > lpSearchAddr + ulEntrySize)
                {
                    if (!MmsIsAddressValidLength((PVOID)lpTargetAddr, sizeof(LDR_DATA_TABLE_ENTRY) + sizeof(POOL_HEADER)))
                    {
                        break;
                    }
                }

                if (MmsIsValidUnicodeString(&lpLdrEntry->FullDllName) &&
                    MmsIsValidUnicodeString(&lpLdrEntry->BaseDllName) &&
                    lpLdrEntry->DllBase &&
                    lpLdrEntry->SizeOfImage &&
                    MmIsAddressValid(lpLdrEntry->DllBase))
                {
                    KdPrint(("[%s] FullName:%wZ, BaseName:%wZ, DllBase:%p, Size:%x\n", __FUNCTION__, &lpLdrEntry->FullDllName, &lpLdrEntry->BaseDllName, lpLdrEntry->DllBase, lpLdrEntry->SizeOfImage));
                }

                lpTargetAddr += sizeof(LDR_DATA_TABLE_ENTRY) + sizeof(POOL_HEADER);
            }
            else
            {
                lpTargetAddr += sizeof(ULONG);
            }

            if (lpTargetAddr + sizeof(POOL_HEADER) >= lpSearchAddr + ulEntrySize)
            {
                break;
            }
        }

    NextLoop:
        lpSearchAddr += PAGE_SIZE;
        if (lpSearchAddr >= lpEndAddr)
        {
            break;
        }
    }
}
//-------------------------------------------------------------------------------------------------------------------------------------
VOID ScanDriverByBigPoolSuspiciousPE()
{
    //Not Implement
}
//-------------------------------------------------------------------------------------------------------------------------------------
VOID ScanDriverByMmSessionSuspiciousPE()
{
    //Not Implement
}
//-------------------------------------------------------------------------------------------------------------------------------------
VOID ScanDriverBySystemPtesSuspiciousPE()
{
    //Not Implement
}
//-------------------------------------------------------------------------------------------------------------------------------------
VOID ScanDriverByDriverImageSuspiciousPE()
{
    //Not Implement
}
//-------------------------------------------------------------------------------------------------------------------------------------
VOID ScanDriver()
{
    ScanDriverByDriverObjectMemory();

    ScanDriverByLdrDataTableEntryMemory();

    // 内存扫描
    // 1. For BigPool which allocated By ExAllocatePoolWithTag
    ScanDriverByBigPoolSuspiciousPE();

    // 2. For MmSession which allocated By MmMapViewInSystemSpace
    ScanDriverByMmSessionSuspiciousPE();

    // 3. For SystemPtes which allocated By MmMapLockPagesSpecifyCache
    ScanDriverBySystemPtesSuspiciousPE();

    // 4. For DriverImage which allocated By System Loader...
    ScanDriverByDriverImageSuspiciousPE();
}
//-------------------------------------------------------------------------------------------------------------------------------------
