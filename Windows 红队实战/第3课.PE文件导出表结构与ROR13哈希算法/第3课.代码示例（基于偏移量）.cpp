#include <windows.h>
#include <iostream>
#include <iomanip>
#include <string>

// ROR13 哈希函数
DWORD Ror13Hash(const char* str) {
    DWORD hash = 0;
    while (*str) {
        // 循环右移 13 位
        hash = (hash >> 13) | (hash << (32 - 13));
        // 加上当前字符
        hash += (unsigned char)*str;
        str++;
    }
    return hash;
}

void* FindFuncByHash(HMODULE hModule, DWORD targetHash) {
    BYTE* base = (BYTE*)hModule;

    // 第一步：读 e_lfanew，跳到 NT 头
    DWORD e_lfanew = *(DWORD*)(base + 0x3C);
    BYTE* ntHeaders = base + e_lfanew;

    // 第二步：从 DataDirectory[0] 拿到导出表 RVA
    DWORD exportRVA = *(DWORD*)(ntHeaders + 0x88);

    // 第三步：跳到导出表
    BYTE* exportDir = base + exportRVA;

    // 第四步：从导出表里读出四个关键字段
    DWORD numberOfNames = *(DWORD*)(exportDir + 0x18);              // 名字总数
    DWORD addressOfFunctions = *(DWORD*)(exportDir + 0x1C);         // 地址数组
    DWORD addressOfNames = *(DWORD*)(exportDir + 0x20);             // 名字数组
    DWORD addressOfNameOrdinals = *(DWORD*)(exportDir + 0x24);      // 序号数组

    // 第五步：把偏移量转成真正的指针
    DWORD* nameArray = (DWORD*)(base + addressOfNames);
    WORD* ordinalArray = (WORD*)(base + addressOfNameOrdinals);
    DWORD* funcArray = (DWORD*)(base + addressOfFunctions);

    // 第六步：遍历名字数组，算哈希，比对
    for (DWORD i = 0; i < numberOfNames; i++) {
        char* funcName = (char*)(base + nameArray[i]);
        if (Ror13Hash(funcName) == targetHash) {
            WORD ordinal = ordinalArray[i];
            DWORD funcRVA = funcArray[ordinal];
            return base + funcRVA;
        }
    }
    return nullptr;
}
int main() {
    // 预计算 CreateRemoteThread 的哈希值
    DWORD targetHash = Ror13Hash("CreateRemoteThread");
    std::cout << "[*] 目标哈希值: 0x" << std::hex << std::setw(8)
              << std::setfill('0') << targetHash << std::dec << std::endl;

    // 拿 kernel32.dll 基址
    HMODULE hKernel32 = GetModuleHandleA("kernel32.dll");
    std::cout << "[*] kernel32.dll 基址: 0x" << std::hex
              << (uintptr_t)hKernel32 << std::dec << std::endl;

    // 用哈希查找函数
    void* addr = FindFuncByHash(hKernel32, targetHash);
    if (addr) {
        std::cout << "[+] 找到 CreateRemoteThread 地址: 0x"
                  << std::hex << (uintptr_t)addr << std::dec << std::endl;

        // 用 GetProcAddress 对比验证
        FARPROC check = GetProcAddress(hKernel32, "CreateRemoteThread");
        std::cout << "[*] GetProcAddress 拿到的地址: 0x"
                  << std::hex << (uintptr_t)check << std::dec << std::endl;

        if (addr == (void*)check) {
            std::cout << "[+] 两个地址一致，验证成功！" << std::endl;
        }
    } else {
        std::cout << "[-] 未找到函数" << std::endl;
    }

    system("pause");
}
