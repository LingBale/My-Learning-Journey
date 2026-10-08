#pragma once

#include <windows.h>
#include <winternl.h>
#include "GetProcAddress.h"

typedef NTSTATUS (NTAPI* NtQueryInformationProcessFn)(
    HANDLE ProcessHandle,
    PROCESSINFOCLASS ProcessInformationClass,
    PVOID ProcessInformation,
    ULONG ProcessInformationLength,
    PULONG ReturnLength);

__declspec(noinline) inline bool IsDebuggingA() {
    // 用哈希解析 ntdll.dll 和 NtQueryInformationProcess
    BYTE* hNt = GetModuleBaseByHash(NHash32::hash("ntdll.dll"));
    if (!hNt) return false;

    NtQueryInformationProcessFn NtQuery = (NtQueryInformationProcessFn)
        GetProcAddressExImpl(hNt,
                             NHash32::hash("NtQueryInformationProcess"),
                             0);
    if (!NtQuery) return false;

    ULONG_PTR Debugging = 0;
    NTSTATUS status = NtQuery(GetCurrentProcess(),
                              (PROCESSINFOCLASS)7,   // ProcessDebugPort
                              &Debugging,
                              sizeof(ULONG_PTR),
                              NULL);
    if (status != 0) return false;

    return Debugging != 0;
}