#pragma once
#include <ntifs.h>
#include "NativeStruct.h"

NTSTATUS     MmsSearchPattern(IN PCUCHAR pattern, IN UCHAR wildcard, IN ULONG_PTR len, IN const VOID* base, IN ULONG_PTR size, OUT PVOID* ppFound);
POBJECT_TYPE MmsGetObjectType(PVOID pObject);
ULONG        MmsGetObjectName(PVOID Object, char* szBuffer, ULONG ulBufferSize);
BOOLEAN      MmsIsAddressValidLength(PVOID lpBuffer, ULONG Len);
BOOLEAN      MmsIsRealDriverObject(PVOID pObject);
BOOLEAN      MmsIsRealSectionObject(PSECTION_OBJECT SectionObject);
BOOLEAN      MmsIsRealSectionObject2(PSECTION SectionObject);
BOOLEAN      MmsIsRealFileObject(PFILE_OBJECT FileObject);
BOOLEAN      MmsIsValidUnicodeString(PUNICODE_STRING lpuniStr);