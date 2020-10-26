#pragma once
#include <ntifs.h>

NTSTATUS     MmsSearchPattern(IN PCUCHAR pattern, IN UCHAR wildcard, IN ULONG_PTR len, IN const VOID* base, IN ULONG_PTR size, OUT PVOID* ppFound);
POBJECT_TYPE MmsGetObjectType(PVOID pObject);
BOOLEAN      MmsIsAddressValidLength(PVOID lpBuffer, ULONG Len);
BOOLEAN      MmsIsRealDriverObject(PVOID pObject);
BOOLEAN      MmsIsValidUnicodeString(PUNICODE_STRING lpuniStr);