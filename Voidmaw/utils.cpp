#include <Windows.h>
#include <sstream>
#include "utils.h"


void LogWinapiFail(std::string failedWinFuncName)
{
    std::cout << "[X] ERROR - WINAPI " << failedWinFuncName << " failed with error code: 0x" << std::hex << GetLastError() << std::endl;
}
void LogProgramFail(std::string failureMessage)
{
    std::cout << "[X] FAIL - " << failureMessage << std::endl;
}
void LogProgramSuccess(std::string successMessage)
{
    std::cout << "[+] SUCCESS - " << successMessage << std::endl;
}
void LogProgramMessage(std::string logMessage)
{
    std::cout << "[~] LOG - " << logMessage << std::endl;
}

std::string IntToString(DWORD input)
{
    std::stringstream ss;
    ss << input;
    std::string str = ss.str();
    return str;
}
std::string DwordToHexString(DWORD in)
{
    std::stringstream sstream;
    sstream << std::hex << in;
    std::string result = sstream.str();
    return result;
}