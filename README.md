# VOIDMAW
### Description:
This is a new bypass technique for memory scanners. It is useful in hiding problematic code that will be flagged by the antivirus vendors. 

This is basically an improved version of [Voidgate](https://github.com/vxCrypt0r/Voidgate), but without all of the previous limitations.

This technique is compatible with all C2 beacons, it handles multithreaded payloads and it can handle executables generated by tools such as [pe_to_shellcode](https://github.com/hasherezade/pe_to_shellcode), thus allowing it to run virtually any non .NET executables.

How it looks under the debugger:
![debugger](https://github.com/vxCrypt0r/Voidmaw/blob/master/gifs/debugger.gif)
____
### How it works:

This technique is made out of two programs:
* Dismantle - responsible with new payload creation
* Voidmaw - responsible with execution of the newly created payload

#### 1.) Dismantle:
This program records all the uniquely executed instructions and their offset. It will use this data to create a header file that needs to be included in the second program (`Voidmaw`) responsible with payload execution.  

This program takes an input file that contains the desired payload (could be a Cobaltstrike beacon or an executable such as mimikatz that was converted to shellcode and reads it into a buffer. 

The prgogram will then set `PAGE_GUARD` protection to that page and install a  vectored exception handler (`VEH`). This VEH is responsible with two things:
* handling any `STATUS_GUARD_PAGE_VIOLATION` that the program will raise once we create a new thread at the payload inside the memory and save the offset and the executed assembly code at the instruction pointer in an `unordered_map` structure, then setting the `TRAP_FLAG` to trigger an `EXCEPTION_SINGLE_STEP` This is necessary to restore the `PAGE_GUARD` protection on that memory page, since triggering it will remove it.
* handling any `EXCEPTION_SINGLE_STEP` triggered by the `TRAP_FLAG` that was configured by our handler and restores the `PAGE_GUARD` protection so that we can gen an exception the next time the CPU tries to execute something on that memory page. This is required for us to record all the executed instructions.

Once the program has finished recording all the executed instructions, it will encrypt them in the unordered_map.

After that, the program will create a copy of the previously executed payload and mask all the recorded executed assembly with INT3 instructions.

 Once all of the above mentioned steps, are done, the program will generate an output file. This file is a header file that you must include in the `Voidmaw` program.


##### IMPORTANT:
* The program records only branches of the code that were executed. If a certain branch was not executed, that code will not be recorded by our application. If you want to record a C2 beacon, during the recording itself you must make sure that the code responsible with networking is successfully executed, since if it fails during the recording, the branch responsible with handling the failure will be the one that is registered in our unordered_map.
* The recording must be manually stopped by pressing the `OK` button in the message box that pops up once the recording has started.
* It is recommended that the environment where you use Dismantle is similar with the environment where the red team engagement will take place (ex: host must have networking) to ensure that the execution will be the same as on your target.
* It is important to use the same level of permissions when recording (Example: if you want to record mimkatz, you will need to record it while running as admin so that you can get the correct code branch responsible with adjusting the privileges to execute and capture and not fall).
* If the executable you want to run requires CLI arguments , you can provide them using the `-a` option. The host program will change its own arguments before creating the new thread in the payload.



#### 2.) Voidmaw:
This program is responsible with the execution of the newly generated payload. 

The above mentioned generated header file has 4 important elements:
 * The original payload masked with INT3 over any executed instructions
 * The XOR encryption key used for decrypting data from the unordered_map
 * The unordered map as a global variable
 * An "InitMap" function responsible with initializing the unordered_map that contains the encrypted assembly instructions paired with the offset where they occurred

This program will first call the InitMap function and then create a memory region where it writes the payload, then it installs a `VEH`. 

This VEH is responsible with handling `EXCEPTION_BREAKPOINT`. 

When we create a new thread on the copied payload, whenever we hit an INT3 (an instruction that was executed during our recording and was masked), we will trigger this VEH. The VEH will then check at what offset this occurred. Once the offset was found, it will look up for that offset in the unordered_map and copy the encrypted assembly to a buffer and decrypt it and write it at the instruction pointer where the exception occurred.

After this, the offset and size of the instruction is placed in a queue, where it will be masked back with INT3 at the next exception, thus basically hiding its previous steps. Only one assembly instruction is visible per thread.

The assembly instructions have only 2 possible states:
1.) masked by INT3
2.) replaced by the original assembly

If the payload creates a new thread somewhere in it's code section, if the instruction is masked, we will get a new exception and handle it also. This makes this technique capable of handling multithreaded payloads without setting hooks on NtCreateThread or other possible ways to create a new thread.

##### IMPORTANT:
* If you want to debug the VEH in Visual Studio, you need to change the INT3 masking with the opcode 0x6 on x64 to trigger EXCEPTION_ILLEGAL_INSTRUCTION, since Visual Studio does not allow you to handle EXCEPTION_BREAKPOINT in it's debuger.
* If the first two bytes of the payload are 'MZ', the program will not mask them back after executing them. This is important since many reflective loaders need to find it in order to be able to load themselves.

____
### Usage:
1.) Dismantle.exe:

```
.\Dismantle.exe -p "C:\mimikatz.bin" -o "./out.h" -a "privilege::debug"
```
Where:
 * -p is the path to the initial payload
 * -o is the path to where the header file containing the final payload will be saved to
 * -a is the argument required to be passed to the process. This is optional. If this argument is not configured, the program will clear its arguments to avoid giving junk arguments to the payload.

2.) Voidmaw.exe:
 Compile with the above generated header file and run. This program takes no arguments and can be delivered as a standalone executable on the target machine where.

____
### Compilation Dependencies:
* [Zycore](https://github.com/zyantific/zycore-c)
* [Zydis](https://github.com/zyantific/zydis)

NOTE: The compiled libraries are included in the project, however it is recommended that you compile them yourself.
____
### Demo:

#### Cobaltstrike beacon:

NOTE: This is a bypass for memory scanners and YARA rules and is not a bulletproof technique. Bad OPSEC (such as default cobaltstrike profile) will get your beacon flagged!

1.) Payload generation:
![cobalt-rec](https://github.com/vxCrypt0r/Voidmaw/blob/master/gifs/cobalt-rec.gif)
2.) Payload execution:
![cobalt-exec](https://github.com/vxCrypt0r/Voidmaw/blob/master/gifs/cobalt-exec.gif)

#### Mimikatz:
1.) Payload generation:
![mimi-rec](https://github.com/vxCrypt0r/Voidmaw/blob/master/gifs/mimi-rec.gif)
2.) Payload execution:
![mimi-exec](https://github.com/vxCrypt0r/Voidmaw/blob/master/gifs/mimi-exec.gif)

____
### Disclaimer:
This repository is for academic purposes, the use of this software is your responsibility.
____
### NOTE:
 * If you are a Red Teamer and want to have earlier access to my future research, you can support me on [Patreon](https://patreon.com/vxCrypt0r) to get earlier access to future tools and techniques before I release them publicly.

### Author - Paul Socatiu
 * Linkedin - [Paul Socatiu](https://ro.linkedin.com/in/paul-%C8%99oca%C8%9Biu-68b566210?trk=people-guest_people_search-card)
 * Twitter  - [vxCrypt0r](https://x.com/vxCrypt0r)
 * Patreon - [vxCrypt0r](https://patreon.com/vxCrypt0r)
 * Ko-Fi - [vxCrypt0r](https://ko-fi.com/vxcrypt0r)

