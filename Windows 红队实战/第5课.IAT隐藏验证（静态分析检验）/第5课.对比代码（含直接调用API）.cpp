#include <windows.h>
#include <iostream>
#include <iomanip>
#include <string>
#include <winternl.h>

#ifdef _WIN64
    // 补全头文件缺失字段
    struct MY_LDR_DATA_TABLE_ENTRY {
        LIST_ENTRY InLoadOrderLinks;
        LIST_ENTRY InMemoryOrderLinks;
        LIST_ENTRY InInitializationOrderLinks;
        PVOID DllBase;
        PVOID EntryPoint;
        ULONG SizeOfImage;
        UNICODE_STRING FullDllName;
        UNICODE_STRING BaseDllName;
    };

    std::string WStringToUTF8(const std::wstring& wstr) {
        if (wstr.empty()) return {};
        int len = WideCharToMultiByte(
            CP_UTF8, WC_ERR_INVALID_CHARS,
            wstr.c_str(), static_cast<int>(wstr.size()),
            nullptr, 0, nullptr, nullptr);
        if (len <= 0) {
            DWORD err = GetLastError();
            return {};
        }
        std::string result(len, '\0');
        int converted = WideCharToMultiByte(
            CP_UTF8, WC_ERR_INVALID_CHARS,
            wstr.c_str(), static_cast<int>(wstr.size()),
            &result[0], len, nullptr, nullptr);
        if (converted == 0) {
            return {};
        }
        result.resize(converted);
        return result;
    }
    DWORD Ror13hash(const char* str){
        DWORD Hash{0};
        while(*str){
            Hash = (Hash >> 13)|(Hash << (32-13));
            Hash += (unsigned char)std::tolower(*str);
            str++;
        }
        return Hash;
    }

    // 获取模块地址
    void* GetModuleAddress(DWORD ModuleHash){
        PEB* pPeb = (PEB*)__readgsqword(0x60);
        PEB_LDR_DATA* pLdr = (PEB_LDR_DATA*)(pPeb->Ldr);

        LIST_ENTRY* pModuleHead = &pLdr->InMemoryOrderModuleList;
        LIST_ENTRY* pModuleList = pModuleHead->Flink;
        while(pModuleHead != pModuleList){
            MY_LDR_DATA_TABLE_ENTRY* pModule = CONTAINING_RECORD(pModuleList, MY_LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);
            UNICODE_STRING* pModuleName = &pModule->BaseDllName;
            if(pModuleName->Buffer && pModuleName->Length > 0){
                std::wstring LModuleName(pModuleName->Buffer, pModuleName->Length / 2);
                std::string ModuleName = WStringToUTF8(LModuleName);
                if(Ror13hash(ModuleName.c_str()) == ModuleHash){
                    PVOID dllBase = pModule->DllBase;
                    return dllBase;
                }
            }
            pModuleList = pModuleList->Flink;
        }
        return nullptr;
    }
    // 获取函数地址
    void* GetProcAddressR(HMODULE hModule, DWORD ProcHash){
        BYTE* dllBase = (BYTE*)hModule;
        if(!dllBase){ return nullptr; }

        IMAGE_DOS_HEADER* dllDos = (IMAGE_DOS_HEADER*)dllBase;                      // Dos头
        if(dllDos->e_magic != IMAGE_DOS_SIGNATURE){ return nullptr; }
        IMAGE_NT_HEADERS* dllNt = (IMAGE_NT_HEADERS*)(dllBase + dllDos->e_lfanew);  // Nt头
        if(dllNt->Signature != IMAGE_NT_SIGNATURE){ return nullptr; }
        IMAGE_OPTIONAL_HEADER* dllOptional = &dllNt->OptionalHeader;                // 可选头

        IMAGE_DATA_DIRECTORY* dllExportDirectory = &dllOptional->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
        if(dllExportDirectory->VirtualAddress == 0 || dllExportDirectory->Size == 0){ return nullptr; }
        IMAGE_EXPORT_DIRECTORY* dllExport = (IMAGE_EXPORT_DIRECTORY*)               // 导出表
                                            (dllBase + dllExportDirectory->VirtualAddress);
        if(!dllExport){ return nullptr; }

        DWORD ExportNumber = dllExport->NumberOfNames;                                  // 已加载模块总数
        if(ExportNumber == 0){ return nullptr; }
        DWORD* ExportFunctions = (DWORD*)(dllBase + dllExport->AddressOfFunctions);     // 函数地址
        DWORD* ExportNames = (DWORD*)(dllBase + dllExport->AddressOfNames);             // 函数名字地址
        WORD* ExportOrdinals = (WORD*)(dllBase + dllExport->AddressOfNameOrdinals);     // 函数序号地址

        for(DWORD i{0}; i < ExportNumber; i++){
            char* funcName = (char*)(dllBase + ExportNames[i]);
            if(Ror13hash(funcName) == ProcHash){
                WORD Ordinals = ExportOrdinals[i];
                DWORD Functions = ExportFunctions[Ordinals];
                return dllBase + Functions;
            }
        }
        return nullptr;
    }
    int main() {
        std::cout << "[*] 正在通过 PEB 遍历获取 kernel32.dll 基址..." << std::endl;
        // 用哈希值从 PEB 链表里找到 kernel32.dll 的基址
        DWORD kernel32Hash = Ror13hash("kernel32.dll");
        HMODULE hKernel32 = (HMODULE)GetModuleAddress(kernel32Hash);

        if (!hKernel32) {
            std::cerr << "[-] 未找到 kernel32.dll" << std::endl;
            system("pause");
            return 1;
        }
        std::cout << "[+] kernel32.dll 基址: 0x" << std::hex
                  << (uintptr_t)hKernel32 << std::dec << std::endl;
        // 用哈希值从导出表里找到 CreateRemoteThread 的地址
        DWORD hashCRT = Ror13hash("CreateRemoteThread");
        void* addrCRT = GetProcAddressR(hKernel32, hashCRT);

        if (!addrCRT) {
            std::cerr << "[-] 未找到 CreateRemoteThread" << std::endl;
            system("pause");
            return 1;
        }
        std::cout << "[+] GetProcAddressR 找到 CreateRemoteThread: 0x"
                  << std::hex << (uintptr_t)addrCRT << std::dec << std::endl;
        // 用原生 GetProcAddress 交叉验证
        FARPROC checkCRT = GetProcAddress(hKernel32, "CreateRemoteThread");
        std::cout << "[*] 原生 GetProcAddress 结果: 0x"
                  << std::hex << (uintptr_t)checkCRT << std::dec << std::endl;

        if (addrCRT == (void*)checkCRT) {
            std::cout << "[+] 验证成功！两个地址一致！" << std::endl;
        } else {
            std::cout << "[-] 验证失败！地址不一致！" << std::endl;
        }
        // 额外测试一个函数 VirtualAllocEx
        std::cout << "\n[*] 额外测试 VirtualAllocEx:" << std::endl;
        void* addrVAE = GetProcAddressR(hKernel32, Ror13hash("VirtualAllocEx"));
        FARPROC checkVAE = GetProcAddress(hKernel32, "VirtualAllocEx");
        std::cout << "    GetProcAddressR: 0x" << std::hex << (uintptr_t)addrVAE << std::dec << std::endl;
        std::cout << "    GetProcAddress:  0x" << std::hex << (uintptr_t)checkVAE << std::dec << std::endl;
        if (addrVAE == (void*)checkVAE) {
            std::cout << "[+] VirtualAllocEx 验证成功！" << std::endl;
        }
        std::cin.get();
    }
#endif

#ifndef _WIN64
    int main(){
        std::cout << "[*] 程序不支持x86架构" << std::endl;
    }
#endif