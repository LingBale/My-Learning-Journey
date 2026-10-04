#include <windows.h>
#include <iostream>
#include <winternl.h>

// ... 结构体定义同上 ...

// 定义函数指针类型
typedef LIST_ENTRY* (*pFindEntry)(PEB_LDR_DATA*);

LIST_ENTRY* RealFindEntry(PEB_LDR_DATA* pLdr) {
    LIST_ENTRY* pHead = &pLdr->InMemoryOrderModuleList;
    LIST_ENTRY* pEntry = pHead->Flink;
    while (pEntry != pHead) {
        pEntry = pEntry->Flink;
    }
    return pEntry;
}

int main() {
    // 用函数指针调用，而不是直接调用
    pFindEntry pFunc = RealFindEntry;

    PEB* pPeb = (PEB*)__readgsqword(0x60);
    PEB_LDR_DATA* pLdr = (PEB_LDR_DATA*)pPeb->Ldr;

    // 间接调用
    LIST_ENTRY* pEntry = pFunc(pLdr);

    std::cout << "[+] 间接调用完成" << std::endl;

    system("pause");
    return 0;
}