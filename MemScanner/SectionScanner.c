#include "SectionScanner.h"
#include "Private.h"
#include "Utils.h"

//----------------------------------------------------------------------------------------------
extern POBJECT_TYPE*  MmSectionObjectType;
extern DYNAMIC_DATA   dynData;
//----------------------------------------------------------------------------------------------
VOID ScanDriverBySectionObjectMemory()
{
    SIZE_T                   ulSize         = 0;
    ULONG_PTR                lpSearchAddr   = 0;
    ULONG_PTR                lpEndAddr      = 0;
    ULONG                    ulEntrySize    = 0;
    ULONG                    ulCurrentSize  = 0;
    ULONG_PTR                pSectionObject = 0;
    NTSTATUS                 status         = STATUS_SUCCESS;

    if (dynData.ver >= WINVER_10_RS1)
    {
        lpSearchAddr = (ULONG_PTR)dynData.MmPagedPoolStart;
        lpEndAddr    = (ULONG_PTR)dynData.MmPagedPoolEnd;
    }
    else
    {
        return;
    }

    KdPrint(("MemScanner: %s: lpStartAddr:%p lpEndAddr:%p\n", __FUNCTION__, lpSearchAddr, lpEndAddr));

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

        if (ulEntrySize < sizeof(SECTION))
        {
            break;
        }

        if (!MmsIsAddressValidLength((PVOID)lpSearchAddr, ulEntrySize))
        {
            goto NextLoop;
        }

        pSectionObject = lpSearchAddr;

        ulCurrentSize = 0;
        ulEntrySize -= sizeof(SECTION);

        while (ulCurrentSize < ulEntrySize)
        {
            PSECTION pSection = (PSECTION)pSectionObject;
            if (MmsIsRealSectionObject(pSection))
            {
                if (pSection->u.Flags.File && pSection->u.Flags.Image)
                {
                    char          szName[128] = { 0 };
                    PCONTROL_AREA ControlArea = (PCONTROL_AREA)((ULONG_PTR)pSection->u1.ControlArea & ~3);
                    PFILE_OBJECT  FileObject  = (PFILE_OBJECT)((ULONG_PTR)ControlArea->FilePointer.Value & ~0xF);

                    if (MmsIsRealFileObject(FileObject))
                    {
                        if (MmsGetObjectName(FileObject, szName, 128))
                        {
                            KdPrint(("[%s] SectionObj:%p FileObj:%p FileName:%s\n", __FUNCTION__, pSection, FileObject, szName));
                        }
                    }
                }

                ulCurrentSize += sizeof(SECTION);
                pSectionObject += sizeof(SECTION);
            }
            else
            {
                ulCurrentSize += sizeof(ULONG_PTR);
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
VOID ScanSection()
{
    ScanDriverBySectionObjectMemory();
}
//----------------------------------------------------------------------------------------------
