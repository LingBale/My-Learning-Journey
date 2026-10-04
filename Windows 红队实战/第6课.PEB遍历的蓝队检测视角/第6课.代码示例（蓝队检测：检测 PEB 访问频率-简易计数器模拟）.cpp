#include <windows.h>
#include <iostream>
#include <atomic>

std::atomic<int> g_pebAccessCount{0};

// 被监控的“可疑函数”
void* SuspiciousGetModuleAddress() {
    // 每次访问 PEB，计数器 +1
    g_pebAccessCount++;

    PEB* pPeb = (PEB*)__readgsqword(0x60);
    if (!pPeb) return nullptr;
    return (void*)pPeb->Ldr;
}

// 模拟“蓝队监控逻辑”
void BlueTeamMonitor() {
    // 假设每 100 毫秒采样一次
    for (int i = 0; i < 5; i++) {
        Sleep(100);
        int count = g_pebAccessCount.load();
        if (count > 3) {
            std::cout << "[!] 告警：PEB 访问频率异常，共 " 
                      << count << " 次" << std::endl;
            return;
        }
    }
    std::cout << "[+] 未发现异常。" << std::endl;
}

int main() {
    std::cout << "[*] 开始监控 PEB 访问频率..." << std::endl;

    // 模拟“恶意程序”快速遍历 PEB 多次
    for (int i = 0; i < 5; i++) {
        SuspiciousGetModuleAddress();
        Sleep(10);
    }

    // 蓝队监控
    BlueTeamMonitor();

    system("pause");
    return 0;
}