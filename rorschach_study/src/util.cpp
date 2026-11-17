// util.cpp
#include <windows.h>
#include <cstdint>

// Returns milliseconds since system boot — used for timing jitter
DWORD get_uptime_ms() {
    return GetTickCount();
}

// Secure buffer wipe — compiler won't optimize this out
void secure_wipe(void* buf, size_t len) {
    volatile uint8_t* p = reinterpret_cast<volatile uint8_t*>(buf);
    while (len--) *p++ = 0;
}

// Wide string to narrow — simple ASCII range, no CRT dependency
void wcs_to_narrow(const wchar_t* src, char* dst, size_t dst_len) {
    size_t i = 0;
    while (src[i] && i < dst_len - 1) {
        dst[i] = static_cast<char>(src[i] & 0xFF);
        i++;
    }
    dst[i] = '\0';
}

// Checks if current process is running elevated
bool is_elevated() {
    HANDLE hToken = NULL;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken))
        return false;

    TOKEN_ELEVATION elev = {};
    DWORD size = sizeof(elev);
    BOOL elevated = FALSE;
    if (GetTokenInformation(hToken, TokenElevation, &elev, sizeof(elev), &size))
        elevated = elev.TokenIsElevated;

    CloseHandle(hToken);
    return elevated == TRUE;
}

// Returns full path of current module (DLL or EXE)
bool get_self_path(wchar_t* out, DWORD out_len) {
    return GetModuleFileNameW(NULL, out, out_len) != 0;
}
