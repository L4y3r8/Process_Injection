#define WIN32_LEAN_AND_MEAN

#define _WIN32_WINNT 0x0501

// indirect WinAPI CALL version with LoadLibrary
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

    typedef struct tagMODULEENTRY32 {
        DWORD   dwSize;
        DWORD   th32ModuleID;
        DWORD   th32ProcessID;
        DWORD   GlblcntUsage;
        DWORD   ProccntUsage;
        BYTE    *modBaseAddr;
        DWORD   modBaseSize;
        HMODULE hModule;
        char    szModule[MAX_MODULE_NAME32 + 1];
        char    szExePath[MAX_PATH];
    } MODULEENTRY32;
*/
#include <windows.h>
#include <stdlib.h>
#include <stdio.h>
#include <tlhelp32.h>

//for later usage
#pragma comment (lib, "Ws2_32.lib")
#pragma comment (lib, "Mswsock.lib")
#pragma comment (lib, "AdvApi32.lib")

int main(int argc, char **argv)
{
    HANDLE hSnapshot_processes;
    HANDLE hSnapshot_modules;
    DWORD dwFlags_SNAPPROCESS = 0x00000002; //  TH32CS_SNAPPROCESS: Includes all processes in the system
    DWORD dfFlags_SNAPMODULE = 0x00000008; // TH32CS_SNAPMODULE: Includes all 32-bit modules of the process specified in th32ProcessID
    DWORD th32ProcessID;
    PROCESSENTRY32 ProcessInformation;
    MODULEENTRY32 ModuleInformation;

    HMODULE LoadedLibraryAddress;
    //FARPROC LoadedFunctionAddress;
    // use string obfuscation / encryption to evade av detection
    // these strings are used to find the corresponding WinAPI function pointer with GetProcAddress
    char *Library="Kernel32.dll";
    char *Function="CreateToolhelp32Snapshot";
    char *func[6];
    // build custom function array to store custom WinAPI function pointer into it
    // it´s a bit more inconspicuous... again to reduce the av detection risk
    for (int i=0; i< sizeof(func)/ sizeof(char*); i++){
        ZeroMemory(&func[i], sizeof(char*));
        printf("memory address function [0]: 0x%p\n",&func[i]);
    };

    LoadedLibraryAddress = LoadLibrary(Library);
    //hSnapshot_processes = CreateToolhelp32Snapshot(dwFlags_SNAPPROCESS,th32ProcessID);
    // --> same semantic, different syntax
    func[0] = (char *)GetProcAddress(LoadedLibraryAddress,Function);
    printf("[+] Library %s is at: 0x%p\n",Library,LoadedLibraryAddress);
    printf("[+] Function %s is at: 0x%p\n",Function,func[0]);

    hSnapshot_processes = (HANDLE)(*(FARPROC)(func[0]))(dwFlags_SNAPPROCESS,th32ProcessID);
    getchar();
    // Continue as before
    if (hSnapshot_processes == INVALID_HANDLE_VALUE) {
        printf("[-] SnapTool32() failed...");
        return -1;
    }

    ZeroMemory(&ProcessInformation,sizeof(PROCESSENTRY32));
    ZeroMemory(&ModuleInformation,sizeof(MODULEENTRY32));
    ProcessInformation.dwSize=sizeof(PROCESSENTRY32);
    ModuleInformation.dwSize=sizeof(MODULEENTRY32);

    //Skip system process with id 0
    Process32First(hSnapshot_processes,&ProcessInformation);

    while(Process32Next(hSnapshot_processes,&ProcessInformation)) {
        printf("\n------------ current process information ---------------\n");
        printf("Name     : %s\n",ProcessInformation.szExeFile );
        printf("ID       : %08d\n",ProcessInformation.th32ProcessID);
        printf("Parent ID: %08d\n",ProcessInformation.th32ParentProcessID);
        printf("Number of threads: %08d\n",ProcessInformation.cntThreads);

        // decision whether the ProcessID is 32-bit or 64-bit
        // -->  important for shellcode architecture
        hSnapshot_modules = CreateToolhelp32Snapshot(dfFlags_SNAPMODULE, ProcessInformation.th32ProcessID);
        // if the calling process is 32 bit, then Module32First() gets the first 32-bit module
        // --> if no 32-bit module available (RETURN FALSE), then the ProcessID is a 64-bit module
        if(Module32First(hSnapshot_modules,&ModuleInformation)) {
            printf("\n                  list of 32-bit modules:\n");
            getchar();
            do {
            //    printf("                  szModule     : %s\n",ModuleInformation.szModule );
                printf("                  szExePath    : %s\n",ModuleInformation.szExePath);
            //    printf("                  modBaseAddr  : %p\n",ProcessInformation.modBaseAddr);
            } while (Module32Next(hSnapshot_modules,&ModuleInformation));
        }
        else {
            printf("\n                  ---> no 32-bit modules: assuming ProcessID is a 64-bit process");
        };
        //getchar();
    };

    return 0;
}
