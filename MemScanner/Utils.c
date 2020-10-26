#include "Utils.h"
#include "Private.h"

//-------------------------------------------------------------------------------------------------------------------------------------------------------------------
typedef
POBJECT_TYPE
(NTAPI* pfnObGetObjectType)(
    PVOID pObject
    );
//-------------------------------------------------------------------------------------------------------------------------------------------------------------------
pfnObGetObjectType g_ObGetObjectType = NULL;

extern POBJECT_TYPE* IoDriverObjectType;
extern POBJECT_TYPE* IoDeviceObjectType;
//-------------------------------------------------------------------------------------------------------------------------------------------------------------------
NTSTATUS MmsSearchPattern(IN PCUCHAR pattern, IN UCHAR wildcard, IN ULONG_PTR len, IN const VOID* base, IN ULONG_PTR size, OUT PVOID* ppFound)
{
    ASSERT(ppFound != NULL && pattern != NULL && base != NULL);
    if (ppFound == NULL || pattern == NULL || base == NULL)
    {
        return STATUS_INVALID_PARAMETER;
    }

    for (ULONG_PTR i = 0; i < size - len; i++)
    {
        BOOLEAN found = TRUE;
        for (ULONG_PTR j = 0; j < len; j++)
        {
            if (pattern[j] != wildcard && pattern[j] != ((PCUCHAR)base)[i + j])
            {
                found = FALSE;
                break;
            }
        }

        if (found != FALSE)
        {
            *ppFound = (PUCHAR)base + i;
            return STATUS_SUCCESS;
        }
    }

    return STATUS_NOT_FOUND;
}
//-------------------------------------------------------------------------------------------------------------------------------------------------------------------
POBJECT_TYPE MmsGetObjectType(PVOID pObject)
{
    UNICODE_STRING uniFuncName = { 0 };

    if (!g_ObGetObjectType)
    {
        RtlInitUnicodeString(&uniFuncName, L"ObGetObjectType");
        g_ObGetObjectType = (pfnObGetObjectType)MmGetSystemRoutineAddress(&uniFuncName);
    }

    if (g_ObGetObjectType)
    {
        return g_ObGetObjectType(pObject);
    }

    return NULL;
}
//-------------------------------------------------------------------------------------------------------------------------------------------------------------------
BOOLEAN MmsIsAddressValidLength(PVOID lpBuffer, ULONG Len)
{
    ULONG_PTR AddrStart = 0;
    ULONG_PTR AddrEnd   = 0;

    if (!MmIsAddressValid(lpBuffer))
    {
        return FALSE;
    }

    AddrStart = (ULONG_PTR)lpBuffer;
    AddrEnd   = AddrStart + Len;

    AddrStart = ALIGN_UP_BY(AddrStart, PAGE_SIZE);

    for (; AddrStart < AddrEnd; AddrStart += PAGE_SIZE)
    {
        if (!MmIsAddressValid((PVOID)AddrStart))
        {
            return FALSE;
        }
    }

    return TRUE;
}
//-------------------------------------------------------------------------------------------------------------------------------------------------------------------
BOOLEAN MmsIsRealDriverObject(PDRIVER_OBJECT DriverObject)
{
    BOOLEAN    bRet               = FALSE;
    ULONG_PTR  CurrentVirutalPage = 0;
    ULONG_PTR  PreVirtualPage     = 0;

    if (!DriverObject || !MmIsAddressValid(DriverObject))
    {
        return FALSE;
    }

    if (DriverObject->Type != 4 || DriverObject->Size != sizeof(DRIVER_OBJECT))
    {
        return FALSE;
    }

    CurrentVirutalPage = ALIGN_DOWN_BY(DriverObject, PAGE_SIZE);
    PreVirtualPage     = ALIGN_DOWN_BY((ULONG_PTR)DriverObject - 0x30, PAGE_SIZE); // Win7 ~ Win10 sizeof(_object_header) == 0x30

    if (PreVirtualPage != CurrentVirutalPage)
    {
        if (PreVirtualPage + PAGE_SIZE != CurrentVirutalPage)
        {
            // Impossible;
            return FALSE;
        }
        else
        {
            if (!MmIsAddressValid((PVOID)PreVirtualPage))
            {
                return FALSE;
            }
        }
    }

    // ObGetObjectType会访问到Object之前的内存空间，如果对象头内存与对象体内存不在一个页面，需要确保对象头所在页面也是有效的，正常情况绝不会不在同一个页面下
    if (MmsGetObjectType(DriverObject) != *IoDriverObjectType)
    {
        return FALSE;
    }

    if ((ULONG_PTR)DriverObject->DriverSection <= (ULONG_PTR)MmSystemRangeStart ||
        !MmIsAddressValid(DriverObject->DriverSection) ||
        (DriverObject->DriverSize & 0x1F) ||
        (ULONG_PTR)DriverObject->DriverStart <= (ULONG_PTR)MmSystemRangeStart ||
        ((ULONG_PTR)(DriverObject->DriverStart) & 0xFFF))
    {
        return FALSE;
    }

    PDEVICE_OBJECT DeviceObject = DriverObject->DeviceObject;
    if (DeviceObject)
    {
        if (MmIsAddressValid(DeviceObject) &&
            MmsGetObjectType(DeviceObject) == *IoDeviceObjectType &&
            DeviceObject->Type == 3 &&
            DeviceObject->Size >= sizeof(DEVICE_OBJECT))
        {
            bRet = TRUE;
        }
    }
    else
    {
        bRet = TRUE;
    }

    return bRet;
}
//-------------------------------------------------------------------------------------------------------------------------------------------------------------------
BOOLEAN MmsIsValidUnicodeString(PUNICODE_STRING lpuniStr)
{
    if (!lpuniStr ||
        !lpuniStr->Buffer ||
        !lpuniStr->Length ||
        lpuniStr->Length > lpuniStr->MaximumLength ||
        !MmsIsAddressValidLength(lpuniStr->Buffer, lpuniStr->Length))
    {
        return FALSE;
    }

    return TRUE;
}
//-------------------------------------------------------------------------------------------------------------------------------------------------------------------