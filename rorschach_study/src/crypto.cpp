#include "crypto.h"
#include "curve25519.h"
#include "chacha20.h"
#include <windows.h>
#include <bcrypt.h>
#pragma comment(lib, "bcrypt.lib")

uint8_t ATTACKER_PUBLIC[32] = {
    0xC3,0x11,0x95,0x28,0xB3,0xD9,0x6C,0x71,0x61,0x1C,0xF7,0x7A,0x73,0xCC,0xAB,0x56,
    0x73,0x12,0xED,0xF5,0x58,0xA4,0x0F,0x12,0x28,0x50,0x92,0xBA,0x47,0xE0,0x04,0x31
};

static const uint8_t BASEPOINT[32] = {9};

void crypto_init() {}

void generate_keypair(uint8_t* pub_out, uint8_t* priv_out) {
    BCryptGenRandom(NULL, priv_out, 32, BCRYPT_USE_SYSTEM_PREFERRED_RNG);
    priv_out[0]  &= 248;
    priv_out[31] &= 127;
    priv_out[31] |= 64;
    curve25519_donna(pub_out, priv_out, BASEPOINT);
}

void derive_session_key(
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

void chacha20_encrypt_buffer(
    uint8_t* buf, size_t len,
    const uint8_t* key, const uint8_t* nonce)
{
    chacha20_xor(buf, buf, len, key, nonce, 0);
}
