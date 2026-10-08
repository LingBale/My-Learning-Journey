#pragma once

#include <winternl.h>
#include <cstring>
#include <string>
#include "GetModuleAddress.h"
#include "Hash.h"

static constexpr int kMaxForwardDepth = 8;

// 前向声明
__declspec(noinline) inline uintptr_t GetProcAddressExImpl(BYTE* Base,
                                                            DWORD ProcHash,
                                                            int depth);

// 处理转发导出
__declspec(noinline)
inline uintptr_t ResolveExportRVA(BYTE* Base, DWORD FuncRVA,
                                  DWORD expRva, DWORD expSize, int depth) {
    if (FuncRVA < expRva || FuncRVA >= expRva + expSize) {
        return reinterpret_cast<uintptr_t>(Base + FuncRVA);
    }

    if (depth >= kMaxForwardDepth) return 0;

    const char* forwarder = reinterpret_cast<const char*>(Base + FuncRVA);
    const char* dot = std::strchr(forwarder, '.');
    if (!dot) return 0;

    std::string dllName(forwarder, dot - forwarder);
    std::string funcName(dot + 1);
    if (dllName.empty() || funcName.empty()) return 0;

    if (dllName.find('.') == std::string::npos) {
        dllName += ".dll";
    }
    dllName = ToLowerAscii(dllName);

    BYTE* targetBase = GetModuleBaseByHash(NHash32::hash(dllName.c_str()));
    if (!targetBase) return 0;

    return GetProcAddressExImpl(targetBase,
                                NHash32::hash(funcName.c_str()),
                                depth + 1);
}

// 遍历导出表
__declspec(noinline)
inline uintptr_t GetProcAddressRImpl(BYTE* Base,
                                     IMAGE_EXPORT_DIRECTORY* pExport,
                                     DWORD expRva, DWORD expSize,
                                     DWORD ProcHash, int depth) {
    if (!Base || !pExport) return 0;

    DWORD* pNames     = (DWORD*)(Base + pExport->AddressOfNames);
    WORD*  pOrdinals  = (WORD*)(Base + pExport->AddressOfNameOrdinals);
    DWORD* pFunctions = (DWORD*)(Base + pExport->AddressOfFunctions);

    for (DWORD i = 0; i < pExport->NumberOfNames; i++) {
        char* pFuncName = (char*)(Base + pNames[i]);
        if (NHash32::hash(pFuncName) == ProcHash) {
            WORD  Ordinal = pOrdinals[i];
            DWORD FuncRVA = pFunctions[Ordinal];
            return ResolveExportRVA(Base, FuncRVA, expRva, expSize, depth);
        }
    }
    return 0;
}

// 核心解析
__declspec(noinline)
inline uintptr_t GetProcAddressExImpl(BYTE* Base, DWORD ProcHash, int depth) {
    if (!Base) return 0;

    IMAGE_DOS_HEADER* pDos = (IMAGE_DOS_HEADER*)Base;
    if (pDos->e_magic != IMAGE_DOS_SIGNATURE) return 0;

    IMAGE_NT_HEADERS* pNt = (IMAGE_NT_HEADERS*)(Base + pDos->e_lfanew);
    if (pNt->Signature != IMAGE_NT_SIGNATURE) return 0;

    IMAGE_OPTIONAL_HEADER* pOptional = &pNt->OptionalHeader;
    DWORD expRva  = pOptional->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
    DWORD expSize = pOptional->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;
    if (expRva == 0) return 0;

    IMAGE_EXPORT_DIRECTORY* pExport =
        (IMAGE_EXPORT_DIRECTORY*)(Base + expRva);
    if (!pExport) return 0;

    return GetProcAddressRImpl(Base, pExport, expRva, expSize, ProcHash, depth);
}

// 对外入口
__declspec(noinline) inline PVOID GetProcAddressEx(DWORD ModuleHash,
                                                    DWORD ProcHash) {
    BYTE* base = GetModuleBaseByHash(ModuleHash);
    if (!base) return nullptr;
    return reinterpret_cast<PVOID>(GetProcAddressExImpl(base, ProcHash, 0));
}