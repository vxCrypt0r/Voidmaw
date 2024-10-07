#pragma once
#include <Windows.h>
#include <iostream>
#include <unordered_map>

constexpr DWORD ASM_INT3 = 0xcc;


constexpr DWORD ASM_MAX_INSTRUCTION_LEN_X64 = 16;

constexpr DWORD PAGE_GUARD_READ_EXCEPTION = 0;
constexpr DWORD PAGE_GUARD_WRITE_EXCEPTION = 1;
constexpr DWORD PAGE_GUARD_EXECUTE_EXCEPTION = 8;



LONG VehPayload(EXCEPTION_POINTERS* ExceptionInfo);
std::string GenerateXorKeyForAsm(DWORD asmLen);
DWORD64 FindRipOffsetFromPayloadBase(DWORD64 rip);
BOOL ExceptionHappenedInOurPayload(PVOID exceptionAddress);