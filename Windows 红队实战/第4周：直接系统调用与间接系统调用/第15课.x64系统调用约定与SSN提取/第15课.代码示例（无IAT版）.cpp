#include <windows.h>
#include <iostream>
#include <iomanip>
#include "EnableDebugPrivilege.h"
#include "Hash.h"
#include "GetProcAddress.h"

// ============================================================
// 从 Nt* 函数地址提取 SSN
// ============================================================
__declspec(noinline) DWORD ExtractSSN(BYTE* funcAddr) {
    if (!funcAddr) return 0;
    if (funcAddr[0] != 0x4C || funcAddr[1] != 0x8B ||
        funcAddr[2] != 0xD1 || funcAddr[3] != 0xB8) {
        return 0;
    }
    return *(DWORD*)(funcAddr + 4);
}

// ============================================================
// syscall 存根（GCC 内联汇编版）
// 注意：如果你用 MSVC，x64 不支持 __asm，需要单独的 .asm 文件
// ============================================================
__declspec(noinline)
NTSTATUS DoSyscall(DWORD ssn, ULONG_PTR a1, ULONG_PTR a2,
                   ULONG_PTR a3, ULONG_PTR a4) {
    NTSTATUS status;
    __asm__ __volatile__ (
        "mov %[ssn], %%eax\n"     // EAX = SSN
        "mov %[a1],  %%rcx\n"     // RCX = 参数1
        "mov %[a2],  %%rdx\n"     // RDX = 参数2
        "mov %[a3],  %%r8\n"      // R8  = 参数3
        "mov %[a4],  %%r9\n"      // R9  = 参数4
        "mov %%rcx,  %%r10\n"     // R10 = RCX（内核约定）
        "syscall\n"                // 进入内核
        "mov %%eax,  %[out]\n"    // 返回值存到 status
        : [out] "=r" (status)
        : [ssn] "r" (ssn),
          [a1]  "r" (a1),
          [a2]  "r" (a2),
          [a3]  "r" (a3),
          [a4]  "r" (a4)
        : "rax", "rcx", "rdx", "r8", "r9", "r10", "r11", "memory"
    );
    return status;
}

int main() {
    EnableDebugPrivilege();

    // ① 通过哈希解析 ntdll.dll 和 NtWriteVirtualMemory
    DWORD hNtdll = NHash32::hash("ntdll.dll");
    BYTE* pNtWrite = (BYTE*)GetProcAddressEx(hNtdll, NHash32::hash("NtWriteVirtualMemory"));
    if (!pNtWrite) {
        std::cerr << "[-] 找不到 NtWriteVirtualMemory" << std::endl;
        return 1;
    }

    std::cout << "[*] NtWriteVirtualMemory: 0x"
              << std::hex << (uintptr_t)pNtWrite << std::dec << std::endl;

    // ② 提取 SSN
    DWORD ssn = ExtractSSN(pNtWrite);
    if (ssn == 0) {
        std::cerr << "[-] SSN 提取失败（可能被 Hook）" << std::endl;
        return 1;
    }
    std::cout << "[+] SSN: 0x" << std::hex << ssn << std::dec << std::endl;

    // ③ 用 syscall 调用一次 NtWriteVirtualMemory
    // 参数： HANDLE ProcessHandle, PVOID BaseAddress,
    //        PVOID Buffer, SIZE_T NumberOfBytesToWrite,
    //        PSIZE_T NumberOfBytesWritten
    HANDLE hSelf = GetCurrentProcess();
    int localBuf = 0x12345678;
    int targetBuf = 0;
    SIZE_T written = 0;

    NTSTATUS status = DoSyscall(
        ssn,
        (ULONG_PTR)hSelf,           // 参数1：进程句柄
        (ULONG_PTR)&targetBuf,      // 参数2：目标地址
        (ULONG_PTR)&localBuf,       // 参数3：源数据
        sizeof(int)                 // 参数4：写入字节数
    );

    std::cout << "[*] syscall 返回值: 0x" << std::hex << status << std::dec << std::endl;
    std::cout << "[*] targetBuf = 0x" << std::hex << targetBuf << std::dec << std::endl;

    if (status == 0 && targetBuf == 0x12345678) {
        std::cout << "[+] syscall 调用成功，数据写入正确！" << std::endl;
    } else {
        std::cout << "[-] syscall 调用失败" << std::endl;
    }

    system("pause");
    return 0;
}