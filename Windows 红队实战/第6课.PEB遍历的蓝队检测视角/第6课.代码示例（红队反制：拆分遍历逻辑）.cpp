#include <windows.h>
#include <iostream>
#include <string>
#include <winternl.h>

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

// 第一步：只负责读 PEB 和 Ldr
__declspec(noinline) PEB_LDR_DATA* Step1_GetLdr() {
    PEB* pPeb = (PEB*)__readgsqword(0x60);
    return (PEB_LDR_DATA*)pPeb->Ldr;
}

// 第二步：只负责遍历链表
__declspec(noinline) LIST_ENTRY* Step2_FindEntry(PEB_LDR_DATA* pLdr) {
    LIST_ENTRY* pHead = &pLdr->InMemoryOrderModuleList;
    LIST_ENTRY* pEntry = pHead->Flink;
    while (pEntry != pHead) {
        MY_LDR_DATA_TABLE_ENTRY* pModule = CONTAINING_RECORD(
            pEntry, MY_LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);

        std::wstring name(pModule->BaseDllName.Buffer,
                          pModule->BaseDllName.Length / 2);

        // 简单比对：找到 ntdll.dll
        if (name == L"ntdll.dll") {
            return pEntry;
        }
        pEntry = pEntry->Flink;
    }
    return nullptr;
}

// 第三步：只负责提取基址
__declspec(noinline) PVOID Step3_ExtractBase(LIST_ENTRY* pEntry) {
    if (!pEntry) return nullptr;
    MY_LDR_DATA_TABLE_ENTRY* pModule = CONTAINING_RECORD(
        pEntry, MY_LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);
    return pModule->DllBase;
}

int main() {
    PEB_LDR_DATA* pLdr = Step1_GetLdr();
    LIST_ENTRY* pEntry = Step2_FindEntry(pLdr);
    PVOID base = Step3_ExtractBase(pEntry);

    std::cout << "[+] ntdll.dll 基址: 0x" 
              << std::hex << (uintptr_t)base << std::dec << std::endl;

    system("pause");
    return 0;
}