#include "veh.h"
#include "utils.h"
#include "dismantle.h"

extern ZydisFormatter formatter;
extern ZydisDecoder decoder;

LONG VehPageGuard(EXCEPTION_POINTERS* ExceptionInfo)
{
    //Handle PAGE GUARD EXCEPTIONS ONLY:
    if (ExceptionInfo->ExceptionRecord->ExceptionCode == STATUS_GUARD_PAGE_VIOLATION)
    {
        //If the exception is triggered by an execute instruction:
        if (ExceptionInfo->ExceptionRecord->ExceptionInformation[0] == PAGE_GUARD_EXECUTE_EXCEPTION)
        {
#if defined(_WIN64)
            DWORD64 asmOffsetFromBase = FindRipOffsetFromPayloadBase(ExceptionInfo->ContextRecord->Rip);
#elif defined(_WIN32)
            DWORD asmOffsetFromBase = FindRipOffsetFromPayloadBase(ExceptionInfo->ContextRecord->Eip);
#endif
            
            if (asmOffsetFromBase == 8)
            {
                int a = 0;
            }

            //If element not found:
            if (payloadExecutedAsm.find(asmOffsetFromBase) == payloadExecutedAsm.end())
            {
                ZyanU64 runtime_address = 0;
                ZyanUSize offset = 0;
                const ZyanUSize length = 15;
                ZydisDecodedInstruction instruction;
                ZydisDecodedOperand operands[ZYDIS_MAX_OPERAND_COUNT];

#if defined(_WIN64)
                ZydisDecoderDecodeFull(&decoder, (PVOID)ExceptionInfo->ContextRecord->Rip, length - offset, &instruction, operands);
#elif defined(_WIN32)
                ZydisDecoderDecodeFull(&decoder, (PVOID)ExceptionInfo->ContextRecord->Eip, length - offset, &instruction, operands);
#endif
                size_t instructionLength = instruction.length;


                BYTE* executedAsm = new BYTE[instructionLength];

#if defined(_WIN64)
                memcpy(executedAsm, (PBYTE)ExceptionInfo->ContextRecord->Rip, instructionLength);
#elif defined(_WIN32)
                memcpy(executedAsm, (PBYTE)ExceptionInfo->ContextRecord->Eip, instructionLength);
#endif

                std::vector<unsigned char> aux;
                for (INT i = 0; i < instructionLength; i++)
                {
                    aux.push_back(executedAsm[i]);
                }
                payloadExecutedAsm[asmOffsetFromBase] = aux;
                delete[] executedAsm;
            }
        }
        //Set trap flag to restore page guard at next exception
        ExceptionInfo->ContextRecord->EFlags |= 0x100ui32;

        return EXCEPTION_CONTINUE_EXECUTION;
    }

    else if (ExceptionInfo->ExceptionRecord->ExceptionCode == EXCEPTION_SINGLE_STEP)
    {
        //Restore page guard on the payload memory region:
        DWORD oldProtect = 0;
        if (!VirtualProtect(payloadBase, payloadSize, PAGE_EXECUTE_READWRITE | PAGE_GUARD, &oldProtect))
        {
            LogWinapiFail("VirtualProtect");
            LogProgramFail("Failed to restore page guard protections in VEH... Program will now terminate...");
            TerminateProcess(GetCurrentProcess(), EXIT_FAILURE);
        }
        //Set trap flag to restore page guard at next exception
        //ExceptionInfo->ContextRecord->EFlags |= 0x100ui32;
        return EXCEPTION_CONTINUE_EXECUTION;
    }

    else
    {
        return EXCEPTION_CONTINUE_SEARCH;
    }
}

#if defined(_WIN64)
DWORD64 FindRipOffsetFromPayloadBase(DWORD64 rip)
{
    return  rip - (DWORD64)payloadBase;
}
#elif defined(_WIN32)
DWORD FindRipOffsetFromPayloadBase(DWORD rip)
{
    return  rip - (DWORD)payloadBase;
}
#endif


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