#include "Private.h"
#include "NativeStruct.h"
#include "import.h"



NTSYSAPI
ULONG
NTAPI
KeCapturePersistentThreadState(
    IN PCONTEXT Context,
    IN PKTHREAD Thread,
    IN ULONG BugCheckCode,
    IN ULONG BugCheckParameter1,
    IN ULONG BugCheckParameter2,
    IN ULONG BugCheckParameter3,
    IN ULONG BugCheckParameter4,
    OUT PVOID VirtualAddress
);

//--------------------------------------------------------------------------------------------------------------
extern DYNAMIC_DATA g_dynData;
//--------------------------------------------------------------------------------------------------------------
PLIST_ENTRY        PsLoadedModuleList;
PVOID              g_KernelBase          = NULL;
ULONG              g_KernelSize          = 0;
KDDEBUGGER_DATA64  g_KdBlock             = { 0 };

//--------------------------------------------------------------------------------------------------------------
VOID InitializeDebuggerBlock()
{
    CONTEXT context = { 0 };
    context.ContextFlags = CONTEXT_FULL;
    RtlCaptureContext(&context);

    PDUMP_HEADER dumpHeader = (PDUMP_HEADER)ExAllocatePoolWithTag(NonPagedPool, DUMP_BLOCK_SIZE, MMS_POOL_TAG);
    if (dumpHeader)
    {
        KeCapturePersistentThreadState(&context, NULL, 0, 0, 0, 0, 0, dumpHeader);
        RtlCopyMemory(&g_KdBlock, (PUCHAR)dumpHeader + KDDEBUGGER_DATA_OFFSET, sizeof(g_KdBlock));

        ExFreePool(dumpHeader);
    }
}
//--------------------------------------------------------------------------------------------------------------
PVOID GetKernelBase(OUT PULONG pSize)
{
    NTSTATUS status = STATUS_SUCCESS;
    ULONG bytes = 0;
    PSYSTEM_MODULE_INFORMATION pMods = NULL;
    PVOID checkPtr = NULL;
    UNICODE_STRING routineName;

    // Already found
    if (g_KernelBase != NULL)
    {
        if (pSize)
        {
            *pSize = g_KernelSize;
        }

        return g_KernelBase;
    }

    RtlInitUnicodeString(&routineName, L"NtOpenFile");
    checkPtr = MmGetSystemRoutineAddress(&routineName);
    if (checkPtr == NULL)
    {
        return NULL;
    }

    // Protect from UserMode AV
    status = ZwQuerySystemInformation(SystemModuleInformation, 0, bytes, &bytes);
    if (bytes == 0)
    {
        DbgPrint("MemScanner: %s: Invalid SystemModuleInformation size\n", __FUNCTION__);
        return NULL;
    }

    pMods = (PSYSTEM_MODULE_INFORMATION)ExAllocatePoolWithTag(NonPagedPool, bytes, MMS_POOL_TAG);
    if (!pMods)
    {
        return NULL;
    }

    RtlZeroMemory(pMods, bytes);

    status = ZwQuerySystemInformation(SystemModuleInformation, pMods, bytes, &bytes);

    if (NT_SUCCESS(status))
    {
        PSYSTEM_MODULE_ENTRY pMod = pMods->Modules;

        for (ULONG i = 0; i < pMods->Count; i++)
        {
            // System routine is inside module
            if (checkPtr >= pMod[i].Base &&
                checkPtr < (PVOID)((PUCHAR)pMod[i].Base + pMod[i].Size))
            {
                g_KernelBase = pMod[i].Base;
                g_KernelSize = pMod[i].Size;
                if (pSize)
                {
                    *pSize = g_KernelSize;
                }

                break;
            }
        }
    }

    if (pMods)
    {
        ExFreePoolWithTag(pMods, MMS_POOL_TAG);
        pMods = NULL;
    }

    return g_KernelBase;
}
//--------------------------------------------------------------------------------------------------------------
NTSTATUS MmsInitLdrData(IN PLDR_DATA_TABLE_ENTRY pThisModule)
{
    PVOID kernelBase = GetKernelBase(NULL);
    if (kernelBase == NULL)
    {
        DbgPrint("MemScanner: %s: Failed to retrieve Kernel base address. Aborting\n", __FUNCTION__);
        return STATUS_NOT_FOUND;
    }

    for (PLIST_ENTRY pListEntry = pThisModule->InLoadOrderModuleList.Flink; pListEntry != &pThisModule->InLoadOrderModuleList; pListEntry = pListEntry->Flink)
    {
        PLDR_DATA_TABLE_ENTRY pEntry = CONTAINING_RECORD(pListEntry, LDR_DATA_TABLE_ENTRY, InLoadOrderModuleList);
        if (kernelBase == pEntry->DllBase)
        {
            if ((PVOID)pListEntry->Blink >= pEntry->DllBase && (PUCHAR)pListEntry->Blink < (PUCHAR)pEntry->DllBase + pEntry->SizeOfImage)
            {
                PsLoadedModuleList = pListEntry->Blink;
                break;
            }
        }
    }

    if (!PsLoadedModuleList)
    {
        DbgPrint("MemScanner: %s: Failed to retrieve PsLoadedModuleList address. Aborting\n", __FUNCTION__);
        return STATUS_NOT_FOUND;
    }

    return STATUS_SUCCESS;
}
//--------------------------------------------------------------------------------------------------------------