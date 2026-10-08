#pragma once

#include <winternl.h>
#include <cstring>
#include <string>
#include "GetModuleAddress.h"
#include "Hash.h"

static constexpr int kMaxForwardDepth = 8;

typedef BYTE* (*pGetModule)(PVOID ModuleAddress);
typedef IMAGE_DOS_HEADER* (*pGetDos)(BYTE* Base);
typedef IMAGE_NT_HEADERS* (*pGetNt)(IMAGE_DOS_HEADER* pDos, BYTE* Base);
typedef IMAGE_OPTIONAL_HEADER* (*pGetOptional)(IMAGE_NT_HEADERS* pNt, BYTE* Base);
typedef IMAGE_EXPORT_DIRECTORY* (*pGetExport)(IMAGE_OPTIONAL_HEADER* pOptional, BYTE* Base);
typedef uintptr_t (*pGetProcAddressR)(BYTE* Base, IMAGE_EXPORT_DIRECTORY* pExport,
                                      DWORD expRva, DWORD expSize,
                                      DWORD ProcHash, int depth);

__declspec(noinline) inline BYTE* GetModuleBase(PVOID pBase){
    return (BYTE*)pBase;
}
__declspec(noinline) inline IMAGE_DOS_HEADER* GetDos(BYTE* Base){
    return (IMAGE_DOS_HEADER*)Base;
}
__declspec(noinline) inline IMAGE_NT_HEADERS* GetNt(IMAGE_DOS_HEADER* pDos, BYTE* Base){
    return (IMAGE_NT_HEADERS*)(Base + pDos->e_lfanew);
}
__declspec(noinline) inline IMAGE_OPTIONAL_HEADER* GetOptional(IMAGE_NT_HEADERS* pNt, BYTE* Base){
    (void)Base;
    return (IMAGE_OPTIONAL_HEADER*)(&pNt->OptionalHeader);
}
__declspec(noinline) inline IMAGE_EXPORT_DIRECTORY* GetExport(IMAGE_OPTIONAL_HEADER* pOptional, BYTE* Base){
    DWORD expRva = pOptional->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
    if(expRva == 0) return nullptr;
    return (IMAGE_EXPORT_DIRECTORY*)(Base + expRva);
}

// 前向声明
__declspec(noinline) inline uintptr_t GetProcAddressExImpl(BYTE* Base, DWORD ProcHash, int depth);

// 处理单个函数 RVA：普通导出直接返回，转发导出递归解析
__declspec(noinline)
inline uintptr_t ResolveExportRVA(BYTE* Base, DWORD FuncRVA,
                                  DWORD expRva, DWORD expSize, int depth) {
    // 普通导出：RVA 不在导出目录范围内
    if (FuncRVA < expRva || FuncRVA >= expRva + expSize) {
        return reinterpret_cast<uintptr_t>(Base + FuncRVA);
    }

    // 转发导出，防递归过深
    if (depth >= kMaxForwardDepth) return 0;

    const char* forwarder = reinterpret_cast<const char*>(Base + FuncRVA);
    const char* dot = std::strchr(forwarder, '.');
    if (!dot) return 0;

    std::string dllName(forwarder, dot - forwarder);
    std::string funcName(dot + 1);
    if (dllName.empty() || funcName.empty()) return 0;

    // 转发字符串里的 DLL 名通常不带 .dll，补上
    if (dllName.find('.') == std::string::npos) {
        dllName += ".dll";
    }
    dllName = ToLowerAscii(dllName);

    BYTE* targetBase = GetModuleBaseByHash(NHash32::hash(dllName.c_str()));
    if (!targetBase) return 0;

    // 在目标模块继续查（可能又转发）
    return GetProcAddressExImpl(targetBase, NHash32::hash(funcName.c_str()), depth + 1);
}

// 在给定模块导出表里按函数名哈希匹配
__declspec(noinline)
inline uintptr_t GetProcAddressRImpl(BYTE* Base, IMAGE_EXPORT_DIRECTORY* pExport,
                                     DWORD expRva, DWORD expSize,
                                     DWORD ProcHash, int depth) {
    if (!Base || !pExport) return 0;

    DWORD* pNames    = (DWORD*)(Base + pExport->AddressOfNames);
    WORD*  pOrdinals = (WORD*)(Base + pExport->AddressOfNameOrdinals);
    DWORD* pFunctions= (DWORD*)(Base + pExport->AddressOfFunctions);

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

// 给定模块基址，解析导出表，返回函数地址（可能经过转发）
__declspec(noinline)
inline uintptr_t GetProcAddressExImpl(BYTE* Base, DWORD ProcHash, int depth) {
    pGetModule       pModule        = GetModuleBase;
    pGetDos          pDos           = GetDos;
    pGetNt           pNt            = GetNt;
    pGetOptional     pOptional      = GetOptional;
    pGetExport       pExport        = GetExport;
    pGetProcAddressR pProcAddressR  = GetProcAddressRImpl;

    BYTE* pBASE = pModule(Base);
    if (!pBASE) return 0;

    IMAGE_DOS_HEADER* pDOS = pDos(pBASE);
    if (!pDOS || pDOS->e_magic != IMAGE_DOS_SIGNATURE) return 0;

    IMAGE_NT_HEADERS* pNT = pNt(pDOS, pBASE);
    if (!pNT || pNT->Signature != IMAGE_NT_SIGNATURE) return 0;

    IMAGE_OPTIONAL_HEADER* pOPTIONAL = pOptional(pNT, pBASE);
    DWORD expRva  = pOPTIONAL->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
    DWORD expSize = pOPTIONAL->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;
    if (expRva == 0) return 0;

    IMAGE_EXPORT_DIRECTORY* pEXPORT = pExport(pOPTIONAL, pBASE);
    if (!pEXPORT) return 0;

    return pProcAddressR(pBASE, pEXPORT, expRva, expSize, ProcHash, depth);
}

// 对外入口：模块名哈希 + 函数名哈希
__declspec(noinline) inline PVOID GetProcAddressEx(DWORD ModuleHash, DWORD ProcHash) {
    BYTE* base = GetModuleBaseByHash(ModuleHash);
    if (!base) return nullptr;
    return reinterpret_cast<PVOID>(GetProcAddressExImpl(base, ProcHash, 0));
}