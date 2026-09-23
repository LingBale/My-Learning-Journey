#include <windows.h>
#include <winternl.h>
#include <tlhelp32.h>
#include <iostream>
#include <string>

// 定义函数指针类型（为后续通过 GetProcAddress 动态获取做准备）
typedef NTSTATUS (NTAPI * NtQueryInformationProces)(
    HANDLE,
    PROCESSINFOCLASS,
    PVOID,
    ULONG,
    PULONG
);

// ============================================================
// 判断目标进程架构
// ============================================================
bool IsProcess64Bit(HANDLE Process){
    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    if(!hNtdll){
        std::cerr << "[-] 无法获取 ntdll.dll 句柄！" << std::endl;
        return false;
    }

    NtQueryInformationProces NtQuery = (NtQueryInformationProces)GetProcAddress(hNtdll, "NtQueryInformationProcess");
    if(!NtQuery){
        std::cerr << "[-] 获取 NtQueryInformationProces 失败！" << std::endl;
        return false;
    }

    ULONG_PTR Wow64Infor{};
    NTSTATUS status = NtQuery(Process, ProcessWow64Information, &Wow64Infor, sizeof(ULONG_PTR), NULL);

    if(status != 0){
        std::cerr << "[-] ProcessWow64Information 调用失败！" << std::endl;
        return false;
    }

    if(Wow64Infor == 0){
        std::cout << "[*] 目标为64位进程！" << std::endl;
        return true;
    }else{
        std::cout << "[*] 目标为32位进程，64位PEB地址为：" 
                  << std::hex << Wow64Infor << std::dec << std::endl;
        return false;
    }
}

// ============================================================
// 通过进程名获取 PID
// ============================================================
DWORD GetProcessPidByName(const std::string& ProcessName){
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if(hSnap == INVALID_HANDLE_VALUE){
        std::cerr << "[-] 进程快照拍摄失败！" << std::endl;
        return false;
    }

    PROCESSENTRY32 pe;
    pe.dwSize = sizeof(PROCESSENTRY32);

    if(Process32First(hSnap, &pe)){
        do{
            if(ProcessName == pe.szExeFile){
                CloseHandle(hSnap);
                return pe.th32ProcessID;
            }
        }while(Process32Next(hSnap, &pe));
    }

    CloseHandle(hSnap);
    std::cout << "[-] 未找到目标进程" << std::endl;
    return 0;
}

// ============================================================
// 主函数
// ============================================================
int main(){
    std::string ProcessName;
    std::cout << "请输入目标进程名：";
    getline(std::cin, ProcessName);

    DWORD ProcessPID = GetProcessPidByName(ProcessName);
    if(ProcessPID == 0){
        std::cerr << "[-] 获取目标PID失败！" << std::endl;
        system("pause");
        return 0;
    }

    HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, ProcessPID);
    if(!hProcess){
        std::cout << "[-] 进程打开失败！" << std::endl;
        system("pause");
        return 0;
    }

    IsProcess64Bit(hProcess);

    CloseHandle(hProcess);
    system("pause");
}
