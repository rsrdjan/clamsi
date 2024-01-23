/*
    clamsi - Command Line for Anti-Malware Scan Interface
    by Srdjan Rajcevic @ SECTREME 2024
*/

#pragma comment(lib, "amsi.lib")

#include <windows.h>
#include <amsi.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

// Console color macros
#define FOREGROUND_GRAY 7
#define cResetColor() {SetConsoleTextAttribute(hConsole, FOREGROUND_GRAY);}
#define cColorRed() {SetConsoleTextAttribute(hConsole, FOREGROUND_RED);}
#define cColorBlue() {SetConsoleTextAttribute(hConsole, FOREGROUND_BLUE);}
#define cColorGreen() {SetConsoleTextAttribute(hConsole, FOREGROUND_GREEN);}

// Content name macros
#define clamsiProcess L"clamsiProcess"
#define clamsiFile L"clamsiFile"
#define clamsiString L"clamsiString"

LPCWSTR clamsi = L"clamsi";

enum Flag {
    flPROCESS,
    flFILE,
    flSTRING,
    flERR
};


enum Flag getFlag(PWCHAR flag)
{
    if (wcscmp(flag, L"-p") == 0)
        return flPROCESS;
    if (wcscmp(flag, L"-f") == 0)
        return flFILE;
    if (wcscmp(flag, L"-s") == 0)
        return flSTRING;
    return flERR;
}

void printUsage(PCWCHAR exec_name)
{
    printf("Usage: %ws -[p/f/s] TARGET [ADDR_RANGE]\n", exec_name);
    printf("\t-p: process to scan\n");
    printf("\t-f: path to file\n");
    printf("\t-s: string to search\n");
    printf("\tTARGET: PID | file | string\n");
    printf("\tADDR_RANGE: -p [offset length]\n");
    printf("\tEXAMPLE: \t%ws -f C:\\Windows\\System32\\calc.exe\n", exec_name);
    printf("\t\t\t%ws -s \"Hello World\"\n", exec_name);
    printf("\t\t\t%ws -p 1234 0x7ff6990b0000 0x7ff699151000\n", exec_name);
}

void printError(PCWCHAR ErrMsg)
{
    HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
    cColorRed();
    printf("ERROR: %ws\n", ErrMsg);
    cResetColor();
}

int wmain(int argc, PWCHAR argv[])
{
    // Check arguments
    if (argc < 2 || argc > 5)
    {
        printUsage(argv[0]);
        return -1;
    }

    enum Flag flag = getFlag(argv[1]); 

    if (flag == flERR)
    {
        printUsage(argv[0]);
        return -1;
    }

    HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE);

    // Prepare and initialize AMSI
    HAMSICONTEXT ctx = NULL;
    HRESULT res;
    HAMSISESSION session = NULL;
    AMSI_RESULT result;
    LONGLONG    offset = 0,
                length = 0;

    if (AmsiInitialize(clamsi, &ctx) != S_OK)
    {
        printError(L"AmsiInitialize failed.");
        return -1;
    }

    if (AmsiOpenSession(ctx, &session) != S_OK)
    {
        printError(L"AmsiOpenSession failed.");
        return -1;
    }

    // Scan according to the flag
    // flSTRING
    if (flag == flSTRING)
    {
        PVOID strToScan = argv[2];

        if (AmsiScanString(ctx, strToScan, clamsiString, session, &result) != S_OK)
        {
            printError(L"AmsiScanString failed.");
            return -1;
        }
    }

    // flFILE
    if (flag == flFILE)
    {
        if (argv[2] == NULL)
        {
            printError(L"No file specified.");
            printUsage(argv[0]);
            return -1;
        }

        if (wcslen(argv[2]) > MAX_PATH)
        {
            printError(L"File path too long.");
            printUsage(argv[0]);
            return -1;
        }

        
        LPCWSTR fileToScan = argv[2];
        HANDLE hFile, hFileObject;
        LPCWSTR foName = L"clamsiFileObject";
        LPVOID stMapView = NULL;
        
        hFile = CreateFileW(fileToScan, GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
        if (hFile == INVALID_HANDLE_VALUE)
        {
            printError(L"Could not open file or file does not exist.");
            return -1;
        }

        DWORD fileSize = GetFileSize(hFile, NULL);
        if (fileSize == 0)
        {
            printError(L"File is empty.");
            return -1;
        }

        hFileObject = CreateFileMappingW(hFile, NULL, PAGE_READONLY, 0, 0, foName);
        if (hFileObject == NULL)
        {
            printError(L"Could not create file mapping.");
            return -1;
        }

            stMapView = MapViewOfFile(hFileObject, FILE_MAP_READ, 0, 0, 0);

        if (stMapView == NULL)
        {
            printError(L"Could not map file.");
            return -1;
        }

        printf("%ws\t\t", fileToScan);

        if (AmsiScanBuffer(ctx, stMapView, fileSize, clamsiFile, session, &result) != S_OK)
        {
            printError(L"AmsiScanBuffer failed.");
            return -1;
        }

        CloseHandle(hFileObject);
        CloseHandle(hFile);
    }

    // flPROCESS
    if (flag == flPROCESS)
    {
        DWORD pid = 0;

        if (argv[2] == NULL)
        {
            printError(L"No process ID specified.");
            printUsage(argv[0]);
            return -1;
        }

        pid = (DWORD)wcstol(argv[2], NULL, 10);

        if (pid == 0)
        {
            printError(L"Invalid process ID.");
            printUsage(argv[0]);
            return -1;
        }

        if (argv[3] == NULL || argv[4] == NULL)
        {
            printError(L"Missing range of bytes to scan.");
            printUsage(argv[0]);
            return -1;
        }

        offset = wcstoull(argv[3], NULL, 16);
        length = wcstoull(argv[4], NULL, 16);
        

        if (offset == 0 || length == 0)
        {
            printError(L"Invalid offset or length.");
            printUsage(argv[0]);
            return -1;
        }

        HANDLE hProcess = OpenProcess(PROCESS_VM_READ, FALSE, pid);
        if (hProcess == NULL)
        {
            printError(L"Could not open process.");
            return -1;
        }

        ULONG buffSize = length - offset;
        LPVOID buff = malloc(buffSize);

        if (buff == NULL)
        {
            printError(L"Could not allocate memory.");
            return -1;
        }
        size_t numRead;
        if (ReadProcessMemory(hProcess, (LPVOID)(LONG_PTR)offset, buff, buffSize, &numRead) == FALSE)
        {
            printError(L"Could not read process memory.");
            printf("ERRCODE: %d\n", GetLastError());
            return -1;
        }
        printf("Scanning %zd bytes...\t\t", numRead);

        // TODO: Verbose output
        // PVOID p = buff;
        // for(int i=0; i < buffSize; i++)
        // {
        //     printf("%02x ", ((BYTE*)p)[i]);
        // }

        if (AmsiScanBuffer(ctx, buff, buffSize, clamsiProcess, session, &result) != S_OK)
        {
            printError(L"AmsiScanBuffer failed.");
            return -1;
        }

        CloseHandle(hProcess);
        free(buff);
    }
    
    // Process the results
    switch(result)
    {
        case AMSI_RESULT_CLEAN:
            cColorGreen();
            printf("CLEAN\n");
            cResetColor();
            break;
        case AMSI_RESULT_NOT_DETECTED:
            cColorGreen();
            printf("NOT DETECTED\n");
            cResetColor();
            break;
        case AMSI_RESULT_BLOCKED_BY_ADMIN_START:
            cColorBlue();
            printf("BLOCKED BY ADMIN START\n");
            cResetColor();
            break;
        case AMSI_RESULT_BLOCKED_BY_ADMIN_END:
            cColorBlue();
            printf("BLOCKED BY ADMIN END\n");
            cResetColor();
            break;
        case AMSI_RESULT_DETECTED:
            cColorRed();
            printf("DETECTED\n");
            cResetColor();
            break;           
    }

    AmsiResultIsMalware(result);
    
    AmsiCloseSession(ctx, session);

    AmsiUninitialize(ctx);

    CloseHandle(hConsole);

    return 0;
}