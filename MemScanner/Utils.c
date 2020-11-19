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
extern POBJECT_TYPE* MmSectionObjectType;
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
ULONG MmsGetObjectName(PVOID Object, char* szBuffer, ULONG ulBufferSize)
{
    ULONG                   ulRetLen        = 0;
    ULONG                   ulRet           = 0;
    PUNICODE_STRING         lpUniObjectName = NULL;

    lpUniObjectName = (PUNICODE_STRING)ExAllocatePoolWithTag(NonPagedPool, 1024 + 2 * sizeof(OBJECT_NAME_INFORMATION), 'nOmM');
    if (!lpUniObjectName)
    {
        return 0;
    }

    memset(lpUniObjectName, 0, 1024 + 2 * sizeof(OBJECT_NAME_INFORMATION));
    lpUniObjectName->MaximumLength = 1024;

    if (NT_SUCCESS(ObQueryNameString(Object, (POBJECT_NAME_INFORMATION)lpUniObjectName, 1024, &ulRetLen)))
    {
        ULONG i, Len = lpUniObjectName->Length / 2;
        for (i = 0; i + 8 < Len && i + 1 < ulBufferSize; i++)
        {
            szBuffer[i] = (char)lpUniObjectName->Buffer[i + 8];
        }

        szBuffer[i++] = 0;
        ulRet = i;
    }

    ExFreePool(lpUniObjectName);
    return ulRet;
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
BOOLEAN MmsIsRealSectionObject(PSECTION_OBJECT SectionObject)
{
    BOOLEAN bRet = FALSE;

    if (MmsIsAddressValidLength((PVOID)((ULONG_PTR)SectionObject - sizeof(OBJECT_HEADER)), sizeof(OBJECT_HEADER) + sizeof(SECTION_OBJECT)) &&
        MmsGetObjectType(SectionObject) == *MmSectionObjectType &&
        (ULONG_PTR)SectionObject->Segment > (ULONG_PTR)MmSystemRangeStart &&
        MmsIsAddressValidLength((PVOID)((ULONG_PTR)SectionObject->Segment - sizeof(OBJECT_HEADER)), sizeof(OBJECT_HEADER) + sizeof(SEGMENT_OBJECT)) &&
        SectionObject->Segment->SizeOfSegment > 0 &&
        SectionObject->Segment->SizeOfSegment < (ULONG_PTR)MmSystemRangeStart &&
        SectionObject->Segment->TotalNumberOfPtes > 0 &&
        (ULONG_PTR)SectionObject->Segment->PrototypePte > (ULONG_PTR)MmSystemRangeStart)
    {
        PCONTROL_AREA ControlArea = (PCONTROL_AREA)SectionObject->Segment->ControlArea;
        if ((ULONG_PTR)ControlArea > (ULONG_PTR)MmSystemRangeStart && 
            MmsIsAddressValidLength(ControlArea, sizeof(CONTROL_AREA)) && // sizeof(CONTROL_AREA) == 0x70/0x78/0x80 ... in all windows version
            !ControlArea->u.Flags.BeingCreated &&
            !ControlArea->u.Flags.BeingDeleted)
        {
            return TRUE;
        }
    }

    return bRet;
}
//-------------------------------------------------------------------------------------------------------------------------------------------------------------------
BOOLEAN MmsIsRealSectionObject2(PSECTION SectionObject)
{
    BOOLEAN bRet = FALSE;

    if (MmsIsAddressValidLength((PVOID)((ULONG_PTR)SectionObject - sizeof(OBJECT_HEADER)), sizeof(OBJECT_HEADER) + sizeof(SECTION)) &&
        MmsGetObjectType(SectionObject) == *MmSectionObjectType &&
        SectionObject->SizeOfSection > 0 &&
        SectionObject->SizeOfSection < (ULONG_PTR)MmSystemRangeStart &&
        !SectionObject->u.Flags.BeingDeleted &&
        !SectionObject->u.Flags.BeingCreated)
    {
        PCONTROL_AREA ControlArea = (PCONTROL_AREA)((ULONG_PTR)SectionObject->u1.ControlArea & ~3);
        if ((ULONG_PTR)ControlArea > (ULONG_PTR)MmSystemRangeStart &&
            MmsIsAddressValidLength(ControlArea, sizeof(CONTROL_AREA)))
        {
            return TRUE;
        }
    }

    return bRet;
}
//-------------------------------------------------------------------------------------------------------------------------------------------------------------------
BOOLEAN MmsIsRealFileObject(PFILE_OBJECT FileObject)
{
    BOOLEAN bRet = FALSE;

    if (MmsIsAddressValidLength((PVOID)((ULONG_PTR)FileObject - sizeof(OBJECT_HEADER)), sizeof(OBJECT_HEADER) + sizeof(FILE_OBJECT)) &&
        MmsGetObjectType(FileObject) == *IoFileObjectType &&
        FileObject->Type == 5 &&
        FileObject->Size == sizeof(FILE_OBJECT) &&
        (ULONG_PTR)FileObject->DeviceObject > (ULONG_PTR)MmSystemRangeStart &&
        (ULONG_PTR)FileObject->SectionObjectPointer > (ULONG_PTR)MmSystemRangeStart)
    {
        if ((ULONG_PTR)FileObject->DeviceObject)
        {
            if ((ULONG_PTR)FileObject->DeviceObject > (ULONG_PTR)MmSystemRangeStart &&
                MmsIsAddressValidLength((PVOID)((ULONG_PTR)FileObject->DeviceObject - sizeof(OBJECT_HEADER)), sizeof(OBJECT_HEADER) + sizeof(DEVICE_OBJECT)) &&
                MmsGetObjectType(FileObject->DeviceObject) == *IoDeviceObjectType)
            {
                bRet = TRUE;
            }
            else
            {
                bRet = FALSE;
            }
        }

        if ((ULONG_PTR)FileObject->Vpb)
        {
            if ((ULONG_PTR)FileObject->Vpb > (ULONG_PTR)MmSystemRangeStart &&
                MmsIsAddressValidLength(FileObject->Vpb, sizeof(VPB)) &&
                (ULONG_PTR)FileObject->Vpb->DeviceObject > (ULONG_PTR)MmSystemRangeStart &&
                MmsIsAddressValidLength((PVOID)((ULONG_PTR)FileObject->Vpb->DeviceObject - sizeof(OBJECT_HEADER)), sizeof(OBJECT_HEADER) + sizeof(DEVICE_OBJECT)) &&
                MmsGetObjectType(FileObject->Vpb->DeviceObject) == *IoDeviceObjectType)
            {
                bRet = TRUE;
            }
            else
            {
                bRet = FALSE;
            }
        }
    }

    return bRet;
}
//-------------------------------------------------------------------------------------------------------------------------------------------------------------------
