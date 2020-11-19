#include "SectionScanner.h"
#include "Private.h"
#include "Utils.h"

//----------------------------------------------------------------------------------------------
extern POBJECT_TYPE*  MmSectionObjectType;
extern DYNAMIC_DATA   g_dynData;
//----------------------------------------------------------------------------------------------
VOID ScanImageFileObjectBySectionObjectMemory_Win7AndLater(PVOID lpStartAddr, SIZE_T ScanSize)
{
    SIZE_T                   ulSize         = 0;
    ULONG_PTR                lpSearchAddr   = 0;
    ULONG_PTR                lpEndAddr      = 0;
    ULONG                    ulEntrySize    = 0;
    ULONG                    ulCurrentSize  = 0;
    ULONG_PTR                pSectionObject = 0;
    NTSTATUS                 status         = STATUS_SUCCESS;

    lpSearchAddr = (ULONG_PTR)lpStartAddr;
    lpEndAddr    = (ULONG_PTR)lpStartAddr + ScanSize - sizeof(SECTION_OBJECT);

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

        pSectionObject = lpSearchAddr;

        ulCurrentSize  = 0;
        ulEntrySize   -= sizeof(SECTION_OBJECT);

        while (ulCurrentSize < ulEntrySize)
        {
            PSECTION_OBJECT pSection = (PSECTION_OBJECT)pSectionObject;
            if (MmsIsRealSectionObject(pSection))
            {
                PCONTROL_AREA ControlArea = pSection->Segment->ControlArea;
                if (ControlArea->u.Flags.File && ControlArea->u.Flags.Image)
                {
                    char          szName[128] = { 0 };
                    PFILE_OBJECT  FileObject = (PFILE_OBJECT)((ULONG_PTR)ControlArea->FilePointer.Value & ~0xF);

                    if (MmsIsRealFileObject(FileObject))
                    {
                        if (MmsGetObjectName(FileObject, szName, 128))
                        {
                            KdPrint(("[%s] SectionObj:%p FileObj:%p FileName:%s\n", __FUNCTION__, pSection, FileObject, szName));
                        }
                    }
                }

                ulCurrentSize  += sizeof(SECTION_OBJECT);
                pSectionObject += sizeof(SECTION_OBJECT);
            }
            else
            {
                ulCurrentSize  += sizeof(ULONG_PTR);
                pSectionObject += sizeof(ULONG_PTR);
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
//----------------------------------------------------------------------------------------------
VOID ScanImageFileObjectBySectionObjectMemory_Win10(PVOID lpStartAddr, SIZE_T ScanSize)
{
    SIZE_T                   ulSize         = 0;
    ULONG_PTR                lpSearchAddr   = 0;
    ULONG_PTR                lpEndAddr      = 0;
    ULONG                    ulEntrySize    = 0;
    ULONG                    ulCurrentSize  = 0;
    ULONG_PTR                pSectionObject = 0;
    NTSTATUS                 status         = STATUS_SUCCESS;


    lpSearchAddr = (ULONG_PTR)lpStartAddr;
    lpEndAddr    = (ULONG_PTR)lpStartAddr + ScanSize - sizeof(SECTION);

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

        pSectionObject = lpSearchAddr;

        ulCurrentSize = 0;
        ulEntrySize  -= sizeof(SECTION);

        while (ulCurrentSize < ulEntrySize)
        {
            PSECTION pSection = (PSECTION)pSectionObject;
            if (MmsIsRealSectionObject2(pSection))
            {
                if (pSection->u.Flags.File && pSection->u.Flags.Image)
                {
                    char          szName[128] = { 0 };
                    PCONTROL_AREA ControlArea = (PCONTROL_AREA)((ULONG_PTR)pSection->u1.ControlArea & ~3);
                    PFILE_OBJECT  FileObject = (PFILE_OBJECT)((ULONG_PTR)ControlArea->FilePointer.Value & ~0xF);

                    if (MmsIsRealFileObject(FileObject))
                    {
                        if (MmsGetObjectName(FileObject, szName, 128))
                        {
                            KdPrint(("[%s] SectionObj:%p FileObj:%p FileName:%s\n", __FUNCTION__, pSection, FileObject, szName));
                        }
                    }
                }

                ulCurrentSize  += sizeof(SECTION);
                pSectionObject += sizeof(SECTION);
            }
            else
            {
                ulCurrentSize  += sizeof(ULONG_PTR);
                pSectionObject += sizeof(ULONG_PTR);
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
//----------------------------------------------------------------------------------------------
VOID ScanImageFileObjectBySectionObjectMemory()
{
    SIZE_T                   ulSize         = 0;
    ULONG_PTR                lpSearchAddr   = 0;
    ULONG_PTR                lpEndAddr      = 0;
    ULONG                    ulEntrySize    = 0;
    ULONG                    ulCurrentSize  = 0;
    ULONG_PTR                pSectionObject = 0;
    NTSTATUS                 status         = STATUS_SUCCESS;

    if (g_dynData.ver >= WINVER_7 && g_dynData.ver <= WINVER_81)
    {
        ulSize = (ULONG_PTR)g_dynData.MmPagedPoolEnd - (ULONG_PTR)g_dynData.MmPagedPoolStart;
        ScanImageFileObjectBySectionObjectMemory_Win7AndLater(g_dynData.MmPagedPoolStart, ulSize);
    }
    else if (g_dynData.ver >= WINVER_10_TH1)
    {
        ulSize = (ULONG_PTR)g_dynData.MmPagedPoolEnd - (ULONG_PTR)g_dynData.MmPagedPoolStart;
        ScanImageFileObjectBySectionObjectMemory_Win10(g_dynData.MmPagedPoolStart, ulSize);
    }
}
//----------------------------------------------------------------------------------------------
VOID ScanSection()
{
    ScanImageFileObjectBySectionObjectMemory();
}
//----------------------------------------------------------------------------------------------
