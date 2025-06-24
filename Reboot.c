/*
 * Simple Reboot Tool (C) — Multi-Method Reboot with SeShutdownPrivilege
 *
 * Features:
 * - Enables SeShutdownPrivilege
 * - Tries three reboot methods in order:
 *   1. InitiateSystemShutdownEx
 *   2. ExitWindowsEx
 *   3. system("shutdown /r /t 0")
 * - Reports detailed errors if any method fails
 *
 * OS Compatibility:
 * - Windows 7, 8, 10, 11
 * - Windows Server 2008 – 2022
 * - Requires SeShutdownPrivilege to be present in the current token
 *
 * Compilation (Cross or Native):
 * 
 * For 64-bit (x86_64):
 *   x86_64-w64-mingw32-gcc reboot.c -o reboot.exe -ladvapi32 -luser32
 *
 * For 32-bit (x86):
 *   i686-w64-mingw32-gcc reboot.c -o reboot32.exe -ladvapi32 -luser32
 *
 * Test your binary with:
 *   file reboot.exe
 *
 * Required Libraries:
 * - advapi32: For AdjustTokenPrivileges
 * - user32: For ExitWindowsEx
 *
 * Notes:
 * - Does not require process migration if you're running in a proper local context.
 * - If called remotely (e.g., via WinRM or Evil-WinRM), make sure the token still has the proper privileges locally.
 * - If SeShutdownPrivilege is not granted even though it's enabled, you'll need to duplicate a token from another process that has it (like winlogon.exe, services.exe, or use Meterpreter’s migration logic).
 */


#include <windows.h>
#include <stdio.h>

BOOL EnableShutdownPrivilege() {
    HANDLE hToken;
    TOKEN_PRIVILEGES tkp;

    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken)) {
        printf("[-] OpenProcessToken failed: %lu\n", GetLastError());
        return FALSE;
    }

    if (!LookupPrivilegeValue(NULL, SE_SHUTDOWN_NAME, &tkp.Privileges[0].Luid)) {
        printf("[-] LookupPrivilegeValue failed: %lu\n", GetLastError());
        CloseHandle(hToken);
        return FALSE;
    }

    tkp.PrivilegeCount = 1;
    tkp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

    if (!AdjustTokenPrivileges(hToken, FALSE, &tkp, 0, NULL, 0)) {
        printf("[-] AdjustTokenPrivileges failed: %lu\n", GetLastError());
        CloseHandle(hToken);
        return FALSE;
    }

    if (GetLastError() == ERROR_NOT_ALL_ASSIGNED) {
        printf("[-] The token does not have the specified privilege.\n");
        CloseHandle(hToken);
        return FALSE;
    }

    CloseHandle(hToken);
    return TRUE;
}

int main() {
    if (!EnableShutdownPrivilege()) {
        printf("[-] Failed to enable shutdown privilege.\n");
        return 1;
    } else {
        printf("[+] SeShutdownPrivilege enabled.\n");
    }

    // 1. InitiateSystemShutdownEx (reboot)
    printf("[*] Trying InitiateSystemShutdownEx...\n");
    if (InitiateSystemShutdownEx(NULL, NULL, 0, TRUE, TRUE, SHTDN_REASON_MAJOR_OTHER)) {
        printf("[+] Reboot issued via InitiateSystemShutdownEx.\n");
        return 0;
    } else {
        printf("[-] InitiateSystemShutdownEx failed: %lu\n", GetLastError());
    }

    // 2. ExitWindowsEx
    printf("[*] Trying ExitWindowsEx...\n");
    if (ExitWindowsEx(EWX_REBOOT | EWX_FORCE, SHTDN_REASON_MAJOR_OTHER)) {
        printf("[+] Reboot issued via ExitWindowsEx.\n");
        return 0;
    } else {
        printf("[-] ExitWindowsEx failed: %lu\n", GetLastError());
    }

    // 3. Fallback: system() call to shutdown command
    printf("[*] Trying system(\"shutdown /r /t 0\")...\n");
    int result = system("shutdown /r /t 0");
    if (result == 0) {
        printf("[+] Reboot command issued via system().\n");
        return 0;
    } else {
        printf("[-] system(\"shutdown\") failed: return code %d\n", result);
    }

    printf("[-] All reboot attempts failed.\n");
    return 1;
}
