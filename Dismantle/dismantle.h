#pragma once
#include <Windows.h>
#include <iostream>
#include <vector>
#include <tuple>
#include <tlhelp32.h>
#include <tchar.h>
#include <unordered_map>



extern std::vector<unsigned char> encryptionKey;
extern std::unordered_map<DWORD, std::vector<unsigned char>> payloadExecutedAsm;
extern HANDLE inputFileHandle;
extern HANDLE outputFileHandle;
extern PVOID payloadBase;
extern DWORD payloadSize;
extern PWSTR newProcArgs;

typedef struct _UNICODE_STRING {
	USHORT Length;
	USHORT MaximumLength;
	PWSTR  Buffer;
} UNICODE_STRING, * PUNICODE_STRING;

typedef struct _RTL_USER_PROCESS_PARAMETERS {
	BYTE           Reserved1[16];
	PVOID          Reserved2[10];
	UNICODE_STRING ImagePathName;
	UNICODE_STRING CommandLine;
} RTL_USER_PROCESS_PARAMETERS, * PRTL_USER_PROCESS_PARAMETERS;

typedef struct _PEB {
	BYTE                          Reserved1[2];
	BYTE                          BeingDebugged;
	BYTE                          Reserved2[1];
	PVOID                         Reserved3[2];
	PVOID		                  Ldr;
	PRTL_USER_PROCESS_PARAMETERS  ProcessParameters;
	PVOID                         Reserved4[3];
	PVOID                         AtlThunkSListPtr;
	PVOID                         Reserved5;
	ULONG                         Reserved6;
	PVOID                         Reserved7;
	ULONG                         Reserved8;
	ULONG                         AtlThunkSListPtr32;
	PVOID                         Reserved9[45];
	BYTE                          Reserved10[96];
	PVOID						  PostProcessInitRoutine;
	BYTE                          Reserved11[128];
	PVOID                         Reserved12[1];
	ULONG                         SessionId;
} PEB, * PPEB;

BOOL CheckProgramArgs(std::string inputFilePath);
PVOID ReadInputFile(CHAR* filePath);

PPEB GetPeb(VOID);
BOOL ChangeCurrentProcessCliArgs(std::string newArgs,CHAR** argv);

PVOID CreateInputDataCopy();

void KillAllChildProcsOfCurrentProc();

void EncryptPayloadExecutedAsm(PVOID payloadData, DWORD64 payloadDataSize);

void ReplaceExecutedAsmWithInt3(PBYTE payloadData, DWORD payloadDataSize);
std::string CreateIncludesString();
std::string CreatePayloadAsmBuffer(PBYTE payloadData, DWORD payloadDataSize);
std::string CreatePayloadAsmBufferSize();
std::string CreateUnorderedMapDeclaration();
std::string CreateEncryptionKeyStringDeclaration();
std::string CreateUnorderedMapInitFunction();


std::string GenerateOutFileData(PVOID payload, DWORD64 payloadSize);

void EncryptMapData();

BOOL WriteOutputFile(PVOID input, DWORD64 inputSize, std::string outFilePath);

BOOL GenerateEncryptionKey();