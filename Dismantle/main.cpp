#include "dismantle.h"
#include "utils.h"
#include "veh.h"
#include "cmdparser.hpp"

std::vector<unsigned char> encryptionKey;   // holds the bytes of the key used to encrypt the executed instructions
std::unordered_map<DWORD, std::vector<unsigned char>> payloadExecutedAsm; //records all uniquely executed ASM instructions along with the offset from the base of the payload

HANDLE inputFileHandle = INVALID_HANDLE_VALUE;
HANDLE outputFileHandle = INVALID_HANDLE_VALUE;

PVOID payloadBase = NULL;
DWORD payloadSize = 0;
PWSTR newProcArgs = 0;

ZydisFormatter formatter;
ZydisDecoder decoder;

INT main(INT argc, CHAR** argv)
{
    DWORD status = 0;
    PVOID payloadCopy = 0;
    PVOID pageGuardVeh = NULL;
    DWORD oldProtect = 0;
    HANDLE runPayload = 0;

    //CHECK IF PROGRAM GOT THE REQUIRED ARGS
    cli::Parser parser(argc, argv); 
    configure_parser(parser);       //init parser args
    parser.run_and_exit_if_error(); //check if program got required args

    std::string inputFilePath = parser.get<std::string>("p");   //GET PATH TO THE INITIAL PAYLOAD FILE
    std::string outputFilePath = parser.get<std::string>("o");  //GET PATH WHERE THE OUTPUT FILE WILL BE SAVED
    std::string payloadArgs = parser.get<std::string>("a");     //GET ARGS REQUIRED FOR THE PAYLOAD (IF REQUIRED)
    

    //CHECK IF THE INPUT FILE IS A VALID PATH WITH AN EXISTING FILE
    LogProgramMessage("Validating program arguments...");
    if (!CheckProgramArgs(inputFilePath))
    {
        LogProgramFail("Argument validation failed... Program will now terminate...");
        status = EXIT_FAILURE;
        goto cleanup_exit;
    }

    
    //GENERATES A XOR KEY USED FOR ENCRYPTION OF THE RECORDED EXECUTED ASM 
    LogProgramMessage("Generating the encryption key...");
    if (!GenerateEncryptionKey())
    {
        LogProgramFail("Failed to generate encryption key... Program will now terminate...");
        status = EXIT_FAILURE;
        goto cleanup_close_handle;
    }

    //READ THE DATA INSIDE THE INPUT FILE (SHOULD HAVE A PIC OR SHELLCODE INSIDE)
    LogProgramMessage("Reading the raw data from the input file...");
    payloadBase = ReadInputFile(argv[1]);
    if (!payloadBase)
    {
        LogProgramFail("Failed to read the raw data from the input file... Program will now terminate...");
        status = EXIT_FAILURE;
        goto cleanup_close_handle;
    }

    //WRITE THE DATA FROM THE INPUT FILE IN OUR OWN ADDRESS SPACE FOR LATER MODIFICATION
    LogProgramMessage("Creating a backup of the input file data...");
    payloadCopy = CreateInputDataCopy();
    if (!payloadCopy)
    {
        LogProgramFail("Failed to create copy of the input data... Program will now terminate...");
        status = EXIT_FAILURE;
        goto cleanup_free_memory_1;
    }

    //INSTALLS VEH RESPONSIBLE WITH RECORDING OF THE EXECUTION OF THE PAYLOAD
    LogProgramMessage("Installing page guard VEH...");
    pageGuardVeh = AddVectoredExceptionHandler(1, (PVECTORED_EXCEPTION_HANDLER)&VehPageGuard);
    if (!pageGuardVeh)
    {
        LogWinapiFail("AddVectoredExceptionHandler");
        status = EXIT_FAILURE;
        goto cleanup_free_memory_2;
    }

    //SETTING UP PAGE_GUARD PROTECTION TO TRIGGER EXCEPTIONS WHEN A THREAD TRIES TO EXECUTE OUR PAYLOAD SO THAT WE CAN CATCH AND RECORD THE EXECUTION
    LogProgramMessage("Setting up page guard protection on payload memory...");
    if (!VirtualProtect(payloadBase, payloadSize, PAGE_EXECUTE_READWRITE | PAGE_GUARD, &oldProtect))
    {
        LogWinapiFail("VirtualProtect");
        status = EXIT_FAILURE;
        goto cleanup_free_memory_2;
    }

    //CLEAR OR SET OUR OWN PROCESS ARGS - IN CASE THE PAYLOAD REQUIRES SOME CLI ARGS TO BE PASSED TO IT
    if (!ChangeCurrentProcessCliArgs(payloadArgs, argv))
    {
        LogProgramFail("Failed to modify the current process CLI args... Exiting...");
        goto cleanup_free_memory_2;
    }
    
    //Init Zydis decoder for disassembling:
#if defined(_WIN64)
    ZydisDecoderInit(&decoder, ZYDIS_MACHINE_MODE_LONG_64, ZYDIS_STACK_WIDTH_64);
#elif defined(_WIN32)
    ZydisDecoderInit(&decoder, ZYDIS_MACHINE_MODE_LONG_COMPAT_32, ZYDIS_STACK_WIDTH_32);
#endif
    ZydisFormatterInit(&formatter, ZYDIS_FORMATTER_STYLE_INTEL);

    //CREATE A THREAD ON OUR PAYLOAD PROTECTED BY PAGE_GUARD, STARTING THE RECORDING OF THE EXECUTION
    LogProgramMessage("Creating new thread on the payload...");
    runPayload = CreateThread(NULL, NULL, (LPTHREAD_START_ROUTINE)payloadBase, NULL, NULL, NULL);
    if (!runPayload)
    {
        LogWinapiFail("CreateThread");
        status = EXIT_FAILURE;
        goto cleanup_free_memory_3;
    }

    //We wait for manual input for the payload to finish execution (since payloads have different exit method, or they don't return at all)
    LogProgramMessage("...WAITING-FOR-STOP-SIGNAL...");
    
    MessageBoxA(NULL, "Press \"OK\" button to stop the recording of the payload execution and start generating the final output file.", "WAITING USER INPUT...", 0);

    //KILL THE PAYLOAD THREAD WHEN WE FINISHED RECORDING
    TerminateThread(runPayload, EXIT_SUCCESS);

    //KILL ANY CHILD PROCESSESS THAT MAY HAVE BEEN CREATED BY OUR PAYLOAD (best effort cleanup attempt)
    KillAllChildProcsOfCurrentProc();

    //GENERATE THE HEADER FILE CONTAINING THE NEW PAYLOAD
    LogProgramMessage("Writing the generated header file to the output path of " + outputFilePath);
    if (!WriteOutputFile(payloadCopy, payloadSize,outputFilePath))
    {
        LogProgramFail("Failed to write the output file... Program will now terminate...");
        status = EXIT_FAILURE;
        goto cleanup_free_memory_3;
    }
    LogProgramSuccess("Header file successfully written on disk!");
    LogProgramSuccess("Program executed successfully!");
    status = EXIT_SUCCESS;

cleanup_free_memory_3:
    if (newProcArgs)
    {
        free(newProcArgs);
    }
cleanup_free_memory_2:
    VirtualFree(payloadCopy, 0, MEM_RELEASE);
cleanup_free_memory_1:
    VirtualFree(payloadBase, 0, MEM_RELEASE);
cleanup_close_handle:
    CloseHandle(inputFileHandle);
cleanup_exit:
    return status;
}
