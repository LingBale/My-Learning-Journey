#include <windows.h>
#include <iostream>
#include <iomanip>
#include <string>

#ifdef _WIN64

// 导出表
struct MY_IMAGE_DATA_DIRECTORY {
    DWORD VirtualAddress;   // 数据目录的 RVA
    DWORD Size;             // 数据目录的大小
};
struct MY_IMAGE_EXPORT_DIRECTORY {
    DWORD   Characteristics;        // 未使用，恒为0
    DWORD   TimeDateStamp;          // 时间戳
    WORD    MajorVersion;           // 主版本号
    WORD    MinorVersion;           // 次版本号
    DWORD   Name;                   // 模块名称的RVA
    DWORD   Base;                   // 起始序号
    DWORD   NumberOfFunctions;      // 导出函数的总数
    DWORD   NumberOfNames;          // 按名称导出的函数数量
    DWORD   AddressOfFunctions;     // 导出函数地址表的RVA
    DWORD   AddressOfNames;         // 导出函数名称表的RVA
    DWORD   AddressOfNameOrdinals;  // 导出函数序号表的RVA
};
struct MY_IMAGE_NT_HEADERS64 {
    DWORD Signature;                            // PE 签名：0x00004550，即 "PE\0\0"
    IMAGE_FILE_HEADER FileHeader;               // PE 文件头
    IMAGE_OPTIONAL_HEADER64 OptionalHeader;     // 64 位可选头
};

// ROR13 哈希计算函数
DWORD Ror13Hash(const char* str){
    DWORD hash{0};
    while(*str){
        hash = (hash >> 13) | (hash << (32-13));
        hash += (unsigned char)*str;
        str++;
    }
    return hash;
}

void* FindFuncByHash(HMODULE hModule, DWORD targetHash){
    BYTE* base = (BYTE*)hModule;

    DWORD e_lfanew = *(DWORD*)(base + 0x3c);
    BYTE* ntHeaders = base + e_lfanew;

    MY_IMAGE_DATA_DIRECTORY* pDataDirectory_0 =(MY_IMAGE_DATA_DIRECTORY*)&((MY_IMAGE_NT_HEADERS64*)ntHeaders)->OptionalHeader.DataDirectory[0];
    MY_IMAGE_EXPORT_DIRECTORY* ExportTable = (MY_IMAGE_EXPORT_DIRECTORY*)(base + pDataDirectory_0->VirtualAddress);

    DWORD numberOfName = ExportTable->NumberOfNames;
    DWORD* funcArray = (DWORD*)(base + ExportTable->AddressOfFunctions);        // 地址
    DWORD* nameArray = (DWORD*)(base + ExportTable->AddressOfNames);            // 名字
    WORD* ordinalArray = (WORD*)(base + ExportTable->AddressOfNameOrdinals);    // 序号

    for(DWORD i{0}; i < numberOfName; i++){
        char* funcName = (char*)(base + nameArray[i]);
        if(Ror13Hash(funcName) == targetHash){
            WORD ordinal = ordinalArray[i];
            DWORD funcRVA = funcArray[ordinal];
            return base + funcRVA;
        }
    }
    return nullptr;
}
int main(){
    DWORD targetHash = Ror13Hash("CreateRemoteThread");
    std::cout << "[*] 目标哈希值: 0x" << std::hex << std::setw(8)
              << targetHash << std::dec << std::endl;

    HMODULE hKernel32 = GetModuleHandleA("kernel32.dll");
    std::cout << "[*] kernel32.dll 基址: 0x" << std::hex
              << (uintptr_t)hKernel32 << std::dec << std::endl;

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
}

#endif
#ifndef _WIN64
    int main() {
        std::cout << "此程序仅支持 64 位系统" << std::endl;
        return 0;
    }
#endif