#include <windows.h>
#include <iostream>
#include <iomanip>

// ============================================================
// 从 Nt* 函数地址提取 SSN
// ============================================================
DWORD ExtractSSN(BYTE* funcAddr) {
    if (!funcAddr) return 0;

    // 检查开头是不是 4C 8B D1 B8（mov r10, rcx; mov eax, imm32）
    if (funcAddr[0] != 0x4C || funcAddr[1] != 0x8B ||
        funcAddr[2] != 0xD1 || funcAddr[3] != 0xB8) {
        std::cerr << "[-] 函数开头不是标准 Nt* 存根" << std::endl;
        return 0;
    }

    // B8 后面的 4 字节就是 SSN（小端序）
    DWORD ssn = *(DWORD*)(funcAddr + 4);
    return ssn;
}

int main() {
    // ① 拿到 ntdll.dll 基址和 NtWriteVirtualMemory 地址
    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    if (!hNtdll) {
        std::cerr << "[-] 找不到 ntdll.dll" << std::endl;
        return 1;
    }

    BYTE* pNtWrite = (BYTE*)GetProcAddress(hNtdll, "NtWriteVirtualMemory");
    if (!pNtWrite) {
        std::cerr << "[-] 找不到 NtWriteVirtualMemory" << std::endl;
        return 1;
    }

    std::cout << "[*] NtWriteVirtualMemory 地址: 0x"
              << std::hex << (uintptr_t)pNtWrite << std::dec << std::endl;

    // ② 打印前 8 字节，肉眼确认
    std::cout << "[*] 前 8 字节: ";
    for (int i = 0; i < 8; i++) {
        std::cout << std::hex << std::setw(2) << std::setfill('0')
                  << (int)pNtWrite[i] << " ";
    }
    std::cout << std::dec << std::endl;

    // ③ 提取 SSN
    DWORD ssn = ExtractSSN(pNtWrite);
    if (ssn == 0) {
        std::cerr << "[-] SSN 提取失败" << std::endl;
        return 1;
    }

    std::cout << "[+] NtWriteVirtualMemory SSN: 0x"
              << std::hex << ssn << std::dec << " (" << ssn << ")" << std::endl;

    system("pause");
    return 0;
}