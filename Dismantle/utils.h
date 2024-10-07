#pragma once
#include<iostream>

void LogWinapiFail(std::string failedWinFuncName);
void LogProgramFail(std::string failureMessage);
void LogProgramSuccess(std::string successMessage);
void LogProgramMessage(std::string logMessage);

std::string IntToString(DWORD input);
std::string DwordToHexString(DWORD in);
std::wstring StringToWString(std::string inputString);