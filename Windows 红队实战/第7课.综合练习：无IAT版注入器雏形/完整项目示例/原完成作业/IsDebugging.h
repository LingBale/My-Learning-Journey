#pragma once

#include <windows.h>
#include <winternl.h>

typedef bool (*IsDebugging)();

typedef NTSTATUS (NTAPI* NtQueryInformationProcessFn)(
    HANDLE ProcessHandle,
    PROCESSINFOCLASS ProcessInformationClass,
    PVOID ProcessInformation,
    ULONG ProcessInformationLength,
    PULONG ReturnLength);

__declspec(noinline) bool IsDebuggingA(){
    HMODULE hNt = GetModuleHandleA("ntdll.dll");
    if(!hNt){ return false; }
    NtQueryInformationProcessFn NtQuery = (NtQueryInformationProcessFn)
                                        GetProcAddress(hNt, "NtQueryInformationProcess");
    if(!NtQuery){ return false; }

    ULONG_PTR Debugging{0};
    NTSTATUS ntstatus = NtQuery(GetCurrentProcess(), (PROCESSINFOCLASS)7, &Debugging, sizeof(ULONG_PTR), NULL);
    if(ntstatus != 0){ return false; }

    return Debugging != 0;
}
__declspec(noinline) bool IsDebuggingEx(){
    IsDebugging debugging = IsDebuggingA;
    bool ISdebugging = debugging();
    return ISdebugging;
}