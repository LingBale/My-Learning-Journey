#include <windows.h>
#include <iostream>

// 用 SEH 包裹 PEB 访问
void* StealthGetPeb() {
    void* pPeb = nullptr;

    __try {
        pPeb = (void*)__readgsqword(0x60);
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        std::cerr << "[-] PEB 访问被拦截，异常已捕获" << std::endl;
        return nullptr;
    }

    return pPeb;
}

int main() {
    void* pPeb = StealthGetPeb();
    if (pPeb) {
        std::cout << "[+] PEB 地址: 0x" 
                  << std::hex << (uintptr_t)pPeb << std::dec << std::endl;
    }
    system("pause");
    return 0;
}