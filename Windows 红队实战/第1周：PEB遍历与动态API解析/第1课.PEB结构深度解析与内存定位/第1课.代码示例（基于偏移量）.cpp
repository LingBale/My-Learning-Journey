#include <windows.h>
#include <iostream>
#include <cwchar>

int main() {
    uintptr_t pPeb = __readgsqword(0x60);
    uintptr_t pLdr = *(uintptr_t*)(pPeb + 0x18);
    uintptr_t pHead = pLdr + 0x20; // PEB_LDR_DATA.InMemoryOrderModuleList
    uintptr_t pEntry = *(uintptr_t*)pHead;

    while (pEntry != pHead) {
        uintptr_t pModule = pEntry - 0x10; // LDR_DATA_TABLE_ENTRY.InMemoryOrderLinks

        uintptr_t dllBase = *(uintptr_t*)(pModule + 0x30);
        if (dllBase == 0) {
            pEntry = *(uintptr_t*)pEntry;
            continue;
        }

        USHORT nameLen = *(USHORT*)(pModule + 0x58); // BaseDllName.Length
        wchar_t* namePtr = *(wchar_t**)(pModule + 0x60); // BaseDllName.Buffer

        if (namePtr && nameLen > 0) {
            std::wstring dllName(namePtr, nameLen / 2);

            if (_wcsicmp(dllName.c_str(), L"kernel32.dll") == 0) {
                std::wcout << L"[+] kernel32.dll: 0x" << std::hex << dllBase << std::dec << std::endl;
            } else if (_wcsicmp(dllName.c_str(), L"ntdll.dll") == 0) {
                std::wcout << L"[+] ntdll.dll: 0x" << std::hex << dllBase << std::dec << std::endl;
            }
        }

        pEntry = *(uintptr_t*)pEntry;
    }

    return 0;
}