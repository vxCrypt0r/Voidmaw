#pragma once
#include<iostream>
#include <minwindef.h>

void LogWinapiFail(std::string failedWinFuncName);
void LogProgramFail(std::string failureMessage);
void LogProgramSuccess(std::string successMessage);
void LogProgramMessage(std::string logMessage);

std::string IntToString(DWORD input);
std::string DwordToHexString(DWORD in);