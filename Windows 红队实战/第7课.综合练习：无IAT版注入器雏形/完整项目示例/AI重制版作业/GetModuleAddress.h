#pragma once

#include <windows.h>
#include <winternl.h>
#include <intrin.h>
#include <string>
#include <cctype>
#include "Hash.h"

__declspec(noinline) inline std::string WStringToUTF8(const std::wstring& wstr) {
    if (wstr.empty()) return {};
    int len = WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS,
                                  wstr.c_str(),
                                  static_cast<int>(wstr.size()),
                                  nullptr, 0, nullptr, nullptr);
    if (len <= 0) return {};

    std::string result(len, '\0');
    int converted = WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS,
                                        wstr.c_str(),
                                        static_cast<int>(wstr.size()),
                                        &result[0], len, nullptr, nullptr);
    if (converted == 0) return {};
    result.resize(converted);
    return result;
}

__declspec(noinline) inline std::string ToLowerAscii(std::string s) {
    for (auto& c : s) {
        c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    }
    return s;
}

typedef struct _MY_LDR_DATA_TABLE_ENTRY {
    LIST_ENTRY InLoadOrderLinks;
    LIST_ENTRY InMemoryOrderLinks;
    LIST_ENTRY InInitializationOrderLinks;
    PVOID DllBase;
    PVOID EntryPoint;
    ULONG SizeOfImage;
    UNICODE_STRING FullDllName;
    UNICODE_STRING BaseDllName;
} MY_LDR_DATA_TABLE_ENTRY;

// 用函数指针间接调用（第6课的反制策略）
typedef PEB_LDR_DATA* (*LdrAddress)();
typedef LIST_ENTRY* (*ModuleList)(PEB_LDR_DATA*, DWORD);
typedef PVOID (*ModuleAddressFn)(LIST_ENTRY*);

__declspec(noinline) inline PEB_LDR_DATA* GetLdrAddress() {
    PEB* Peb = (PEB*)__readgsqword(0x60);
    return (PEB_LDR_DATA*)Peb->Ldr;
}

__declspec(noinline) inline LIST_ENTRY* GetModuleList(PEB_LDR_DATA* pLdr,
                                                       DWORD ModuleHash) {
    if (!pLdr) return nullptr;
    LIST_ENTRY* pHead = &pLdr->InMemoryOrderModuleList;
    LIST_ENTRY* pEntry = pHead->Flink;

    while (pHead != pEntry) {
        MY_LDR_DATA_TABLE_ENTRY* pModule = CONTAINING_RECORD(
            pEntry, MY_LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);

        std::wstring ModuleName(pModule->BaseDllName.Buffer,
                                pModule->BaseDllName.Length / 2);
        std::string ModuleNameStr = ToLowerAscii(WStringToUTF8(ModuleName));

        if (NHash32::hash(ModuleNameStr.c_str()) == ModuleHash) {
            return pEntry;
        }
        pEntry = pEntry->Flink;
    }
    return nullptr;
}

__declspec(noinline) inline PVOID GetModuleAddressFromEntry(LIST_ENTRY* List) {
    if (!List) return nullptr;
    MY_LDR_DATA_TABLE_ENTRY* pModule = CONTAINING_RECORD(
        List, MY_LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);
    return pModule->DllBase;
}

__declspec(noinline) inline BYTE* GetModuleBaseByHash(DWORD ModuleHash) {
    LdrAddress pGetLdr = GetLdrAddress;
    ModuleList pGetList = GetModuleList;
    ModuleAddressFn pGetAddr = GetModuleAddressFromEntry;

    PEB_LDR_DATA* ldr = pGetLdr();
    if (!ldr) return nullptr;

    LIST_ENTRY* entry = pGetList(ldr, ModuleHash);
    return (BYTE*)pGetAddr(entry);
}