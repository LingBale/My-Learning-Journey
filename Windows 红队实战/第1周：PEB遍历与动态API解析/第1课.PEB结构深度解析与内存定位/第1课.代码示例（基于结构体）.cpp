#include <windows.h>
#include <iostream>
#include <iomanip>
#include <string>

// 重定义UNICODE_STRING：是Windows内核中表示Unicode字符串的结构体
struct MY_UNICODE_STRING{
    USHORT Length;          // 字符串长度（字节数）
    USHORT MaximumLength;   // 缓冲区大小
    PWSTR  Buffer;          // 宽字符串指针
};
// 重定义LDR_DATA_TABLE_ENTRY：是PEB中Ldr模块链表的节点结构体
struct MY_LDR_DATA_TABLE_ENTRY{
    LIST_ENTRY InLoadOrderLinks;          // 0x00
    LIST_ENTRY InMemoryOrderLinks;        // 0x10  ← 遍历的链表节点
    LIST_ENTRY InInitializationOrderLinks;// 0x20
    PVOID DllBase;                        // 0x30  模块基址
    PVOID EntryPoint;                     // 0x38
    ULONG SizeOfImage;                    // 0x40
    MY_UNICODE_STRING FullDllName;           // 0x48  完整路径
    MY_UNICODE_STRING BaseDllName;           // 0x58  文件名（不含路径）
    // 后续字段省略...
};
int main(){
    // 获取PEB地址
    uintptr_t pPeb = __readgsqword(0x60);
    // 获取Ldr结构指针
    uintptr_t pLdr = *(uintptr_t*)(pPeb + 0x18);
    // 获取InMemoryOrderModuleList链表头
    LIST_ENTRY* pListHead = (LIST_ENTRY*)(pLdr + 0x20);
    LIST_ENTRY* pEntry = pListHead->Flink;  // 首个节点
    
    while(pEntry != pListHead){
        // 使用 CONTAINING_RECORD 反推结构体首地址
        MY_LDR_DATA_TABLE_ENTRY* pModule = CONTAINING_RECORD(pEntry, MY_LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);
        // 读取模块基址
        uintptr_t dllBase = (uintptr_t)pModule->DllBase;
        if(dllBase == 0){
            pEntry = pEntry->Flink;
            continue;
        }

        // 读取模块文件名
        MY_UNICODE_STRING* pName = &pModule->BaseDllName;
        if(pName->Buffer && pName->Length > 0){
            // 将宽字符串转换为std::wstring
            std::wstring dllName(pName->Buffer, pName->Length / 2);
            if(_wcsicmp(dllName.c_str(), L"kernel32.dll") == 0){
                std::cout << "[+] kernel32.dll 基址: 0x"
                          << std::hex << dllBase << std::dec << std::endl;}
            else if(_wcsicmp(dllName.c_str(), L"ntdll.dll") == 0){
                std::cout << "[+] ntdll.dll 基址: 0x"
                          << std::hex << dllBase << std::dec << std::endl;
            }
        pEntry = pEntry->Flink;
        }
    }
}
