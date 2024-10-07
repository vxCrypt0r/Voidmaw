#pragma once
#include <Windows.h>
#include <iostream>
#include <unordered_map>
#include <stdio.h>
#include <inttypes.h>
#include <Zydis/Zydis.h>

constexpr DWORD ASM_INT3 = 0xcc;


constexpr DWORD ASM_MAX_INSTRUCTION_LEN_X64 = 16;

constexpr DWORD PAGE_GUARD_READ_EXCEPTION = 0;
constexpr DWORD PAGE_GUARD_WRITE_EXCEPTION = 1;
constexpr DWORD PAGE_GUARD_EXECUTE_EXCEPTION = 8;



LONG VehPageGuard(EXCEPTION_POINTERS* ExceptionInfo);
std::string GenerateXorKeyForAsm(DWORD asmLen);
#if defined(_WIN64)
DWORD64 FindRipOffsetFromPayloadBase(DWORD64 rip);
#elif defined(_WIN32)
DWORD FindRipOffsetFromPayloadBase(DWORD rip);
#endif
