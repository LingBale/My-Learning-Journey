#include <windows.h>
#include <winternl.h>
#include <iostream>

// 动态获取 NtQueryInformationProcess
typedef NTSTATUS(NTAPI* pNtQueryInformationProcess)(
    HANDLE, PROCESSINFOCLASS, PVOID, ULONG, PULONG
);

bool IsBeingDebugged() {
    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    if (!hNtdll) return false;

    pNtQueryInformationProcess NtQuery = (pNtQueryInformationProcess)
        GetProcAddress(hNtdll, "NtQueryInformationProcess");
    if (!NtQuery) return false;

    DWORD debugPort = 0;
    NTSTATUS status = NtQuery(
        GetCurrentProcess(),
        (PROCESSINFOCLASS)7,   // ProcessDebugPort 的枚举值是 7
        &debugPort,
        sizeof(debugPort),
        NULL
    );

    if (status != 0) {
        std::cerr << "[-] NtQueryInformationProcess 调用失败" << std::endl;
        return false;
    }

    // debugPort != 0 说明被调试器附着
    return debugPort != 0;
}

int main() {
    if (IsBeingDebugged()) {
        std::cout << "[!] 检测到调试器附着！" << std::endl;
    } else {
        std::cout << "[+] 未被调试。" << std::endl;
    }
    system("pause");
    return 0;
}