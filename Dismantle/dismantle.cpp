#include "dismantle.h"
#include "utils.h"
#include "veh.h"

UNICODE_STRING newCliArg = { 0 };

PPEB GetPeb(VOID)
{
#if defined(_WIN64)
    return (PPEB)__readgsqword(0x60);
#elif defined(_WIN32)
    return (PPEB)__readfsdword(0x30);
#endif
}

BOOL CheckProgramArgs(std::string inputFilePath)
{
    inputFileHandle = CreateFileA(inputFilePath.c_str(), GENERIC_READ, NULL, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (inputFileHandle == INVALID_HANDLE_VALUE)
    {
        LogWinapiFail("CreateFileA");
        if (GetLastError() == ERROR_FILE_NOT_FOUND)
        {
            LogProgramFail("Invalid argument (ERROR_FILE_NOT_FOUND)");
        }
        return FALSE;
    }

    return TRUE;
}

//NOTE:
//If the program is compiled for x64, payload must be also x64
//If the program is compiled for x86, payload must be also x86
//The program is compatible with reflective loaders and PEs converted to shellcode with tools such as pe2shc
PVOID ReadInputFile(CHAR* filePath)
{
    LARGE_INTEGER fileSize = { 0 };
    if (!GetFileSizeEx(inputFileHandle, &fileSize))
    {
        CloseHandle(inputFileHandle);
        LogWinapiFail("GetFileSizeEx");
        return NULL;
    }

    payloadSize = fileSize.QuadPart;
    PVOID asmFromFile = VirtualAlloc(NULL, fileSize.QuadPart, MEM_COMMIT, PAGE_READWRITE);
    if (!asmFromFile)
    {
        CloseHandle(inputFileHandle);
        LogWinapiFail("VirtualAlloc");
        return NULL;
    }

    if (!ReadFile(inputFileHandle, asmFromFile, fileSize.QuadPart, NULL, NULL))
    {
        CloseHandle(inputFileHandle);
        LogWinapiFail("ReadFile");
        VirtualFree(asmFromFile, 0, MEM_RELEASE);
        return NULL;
    }

    CloseHandle(inputFileHandle);
    return asmFromFile;
}


PVOID CreateInputDataCopy()
{
    PVOID memoryCopy = VirtualAlloc(NULL, payloadSize, MEM_COMMIT, PAGE_READWRITE);
    if (!memoryCopy)
    {
        LogWinapiFail("VirtualAlloc");
        return NULL;
    }

    memcpy(memoryCopy, payloadBase, payloadSize);
    return memoryCopy;
}


//AWFUL HACKY CODE
//This function is responsible with changing the current process command line
//This may be required 
BOOL ChangeCurrentProcessCliArgs(std::string newArgs,CHAR** argv)
{

    PPEB peb = GetPeb();
    
    std::wstring argv0 = StringToWString(argv[0]);
    std::wstring argv1 = StringToWString(newArgs);

    if (!newArgs.size())
    {
        PWCHAR awfulHack = GetCommandLine();
        awfulHack += argv0.size();
        WCHAR nullbyte = 0;
        *awfulHack = 0;
        return TRUE;
    }

    argv0 = L"\"" + argv0 + L"\"";

    std::wstring newArgsFullString = argv0 + L" " + argv1;

    std::wstring originalCmdLine = GetCommandLine(); //AWFUL HACK

    

    //This should never be true IN THEORY
    if (newArgsFullString.size() > originalCmdLine.size())
    {
        LogProgramFail("Insufficient space for new command line.");
        return FALSE;
    }



    DWORD newProcArgsSize = newArgsFullString.size() + 1;
    newProcArgs = (PWSTR)malloc(newProcArgsSize * sizeof(WCHAR));
    if (!newProcArgs)
    {
        return FALSE;
    }

    ZeroMemory(newProcArgs, newProcArgsSize*sizeof(WCHAR));
    PWCHAR aux = newProcArgs;
    for (INT i = 0; i < newProcArgsSize-1; i++)
    {
        *aux = newArgsFullString[i];
        aux++;
    }

    newCliArg.Buffer = newProcArgs;
    newCliArg.Length = (newProcArgsSize - 1) * sizeof(WCHAR);
    newCliArg.MaximumLength = (newProcArgsSize - 1) * sizeof(WCHAR);

    LPWSTR awfulHack = GetCommandLine();
    memcpy(awfulHack, newProcArgs, newProcArgsSize * sizeof(WCHAR));

    peb->ProcessParameters->CommandLine = newCliArg;

    
    return TRUE;
}

void KillAllChildProcsOfCurrentProc()
{
    LogProgramMessage("Searching for any child processess that may have been spawned by the payload...");
    DWORD currentProcPid = GetCurrentProcessId();

    HANDLE hProcessSnap = 0;
    HANDLE hProcess = 0;
    PROCESSENTRY32 pe32 = { 0 };


    hProcessSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hProcessSnap == INVALID_HANDLE_VALUE)
    {
        LogProgramFail("Process enumeration failed... Program will skip child process cleanup...");
        return;
    }

    pe32.dwSize = sizeof(PROCESSENTRY32);
    if (!Process32First(hProcessSnap, &pe32))
    {
        CloseHandle(hProcessSnap);
        LogProgramFail("Process enumeration failed... Program will skip child process cleanup...");
        return;
    }
    do
    {
        if (pe32.th32ParentProcessID == currentProcPid)
        {
            LogProgramMessage("Found child of our current process...");
            std::cout << "    ---- CHILD PID = " << pe32.th32ProcessID << std::endl;
            HANDLE handleToFoundProc = OpenProcess(PROCESS_TERMINATE, FALSE, pe32.th32ProcessID);
            if(!handleToFoundProc)
            {
                LogWinapiFail("OpenProcess");
                LogProgramFail("Failed to open a handle to the found child process... Continuing process enumeration...");
                continue;
            }
            if (!TerminateProcess(handleToFoundProc, EXIT_SUCCESS))
            {
                LogWinapiFail("TerminateProcess");
                LogProgramFail("Failed to terminate the found child process... Continuing process enumeration...");

            }
            CloseHandle(handleToFoundProc);
        }

    } while (Process32Next(hProcessSnap, &pe32));

    LogProgramSuccess("Finished process enumeration! All child processess of our current process were handled.");
    LogProgramSuccess("Child process cleanup successful!");
    CloseHandle(hProcessSnap);
    return;
}

void EncryptPayloadExecutedAsm(PVOID payloadData, DWORD64 payloadDataSize)
{
    for (auto it = payloadExecutedAsm.begin(); it != payloadExecutedAsm.end(); it++)
    {
        DWORD asmOffset = it->first;
        std::vector<unsigned char> asmXorKey = it->second;
        PBYTE asmAddr = (PBYTE)payloadData + asmOffset;
        for (INT i = 0; i < asmXorKey.size(); i++)
        {
            *asmAddr = *asmAddr ^ asmXorKey[i];
            asmAddr++;
        }
    }
}

void ReplaceExecutedAsmWithInt3(PBYTE payloadData, DWORD payloadDataSize)
{
    for (auto it = payloadExecutedAsm.begin(); it != payloadExecutedAsm.end(); it++)
    {
        DWORD asmOffset = it->first;
        DWORD asmSize = it->second.size();
        memset(payloadData + asmOffset, ASM_INT3, asmSize);
    }
}
std::string CreateIncludesString()
{
    std::string aux;
    aux += "#pragma once\n";
    aux += "#include <unordered_map>\n";
    aux += "#include <iostream>\n";
    return aux;
}
std::string CreatePayloadAsmBuffer(PBYTE payloadData, DWORD payloadDataSize)
{
    ReplaceExecutedAsmWithInt3(payloadData, payloadDataSize);


    std::string aux;
    aux += "unsigned char payload[] = {";

    //Write the raw encrypted payload bytes:
    for (INT i = 0; i < payloadDataSize; i++)
    {

        PBYTE payloadByte = payloadData + i;
        DWORD byte = *payloadByte;
        std::string byteStr = DwordToHexString(byte);
        if (byteStr.size() == 1)
        {
            byteStr = "0" + DwordToHexString(byte);
        }
        aux += "0x" + byteStr;
        if (i == payloadDataSize - 1)
        {
            aux += "};\n";
        }
        else
        {
            aux += ",";
        }
    }
    return aux;
}
std::string CreatePayloadAsmBufferSize()
{
    std::string aux = "int payloadSize = sizeof(payload);\n";
    return aux;
}
std::string CreateUnorderedMapDeclaration()
{
    std::string aux = "std::unordered_map<DWORD, std::vector<unsigned char>> payloadExecutedAsm;\n";
    return aux;
}
std::string CreateEncryptionKeyStringDeclaration()
{
    std::string aux;
    aux += "std::vector<unsigned char> encryptionKey;\n";
    return aux;
}
std::string CreateUnorderedMapInitFunction()
{
    std::string aux;
    aux += "void InitMap()\n{\n";

    //generate vector with payload key
    for (INT i = 0; i < encryptionKey.size(); i++)
    {
        BYTE byte = encryptionKey[i];
        DWORD dwByte = byte;
        aux += "    encryptionKey.push_back(\'\\x" + DwordToHexString(dwByte) + "\');\n";
    }
    aux += "    std::vector<unsigned char> aux;\n";

    //generate map data
    for (auto it = payloadExecutedAsm.begin(); it != payloadExecutedAsm.end(); it++)
    {
        aux += "    aux.clear();\n";
        for (INT i = 0; i < it->second.size(); i++)
        {
            BYTE byte = it->second[i];
            DWORD dwByte = byte;
            aux += "    aux.push_back(\'\\x" + DwordToHexString(dwByte) + "\');\n";
        }

        aux += "    payloadExecutedAsm[";
        aux += IntToString(it->first);
        aux += "] = aux;\n";
    }
    aux += "}\n";
    return aux;
}


std::string GenerateOutFileData(PVOID payload, DWORD64 payloadSize)
{
    std::string result;
    result += CreateIncludesString();
    result += CreatePayloadAsmBuffer((PBYTE)payload, payloadSize);
    result += CreatePayloadAsmBufferSize();
    result += CreateUnorderedMapDeclaration();
    result += CreateEncryptionKeyStringDeclaration();
    result += CreateUnorderedMapInitFunction();
    return result;
}

void EncryptMapData()
{
    for (auto it = payloadExecutedAsm.begin(); it != payloadExecutedAsm.end(); it++)
    {
        std::vector<unsigned char> aux;
        for (INT i = 0; i < it->second.size(); i++)
        {
            aux.push_back(it->second[i] ^ encryptionKey[i]);
        }
        it->second = aux;
    }
}

BOOL WriteOutputFile(PVOID input, DWORD64 inputSize,std::string outFilePath)
{
    HANDLE outFile = CreateFileA(outFilePath.c_str(), GENERIC_READ | GENERIC_WRITE, 0, NULL, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, NULL);
    if (outFile == INVALID_HANDLE_VALUE)
    {
        LogWinapiFail("CreateFileA");
        return FALSE;
    }

    //EncryptPayloadExecutedAsm(input, inputSize);
    EncryptMapData();

    std::string outFileData = GenerateOutFileData(input, inputSize);

    if (!WriteFile(outFile, outFileData.c_str(), outFileData.size(), NULL, NULL))
    {
        LogWinapiFail("WriteFile");
        return FALSE;
    }
    CloseHandle(outFile);
    return TRUE;
}

BOOL GenerateEncryptionKey()
{
    BYTE randomData[ASM_MAX_INSTRUCTION_LEN_X64] = { 0 };

    HCRYPTPROV hProv = { 0 };
    if (!CryptAcquireContextA(&hProv, NULL, NULL, PROV_RSA_AES, NULL))
    {
        LogWinapiFail("CryptAcquireContextA");
        return FALSE;
    }

    if (!CryptGenRandom(hProv, ASM_MAX_INSTRUCTION_LEN_X64, randomData))
    {
        LogWinapiFail("CryptGenRandom");
        CryptReleaseContext(hProv, NULL);
        return FALSE;
    }

    for (INT i = 0; i < ASM_MAX_INSTRUCTION_LEN_X64; i++)
    {
        encryptionKey.push_back(randomData[i]);
    }

    CryptReleaseContext(hProv, NULL);
    return TRUE;
}