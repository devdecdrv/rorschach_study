#include "crypto.h"
#include "curve25519.h"
#include "chacha20.h"
#include <windows.h>
#include <bcrypt.h>
#pragma comment(lib, "bcrypt.lib")

static uint8_t ATTACKER_PUBLIC[32] = {
    // hardcoded attacker public key — replace with real key
    0xAB,0xCD,0xEF,0x01,0x23,0x45,0x67,0x89,
    0x10,0x11,0x12,0x13,0x14,0x15,0x16,0x17,
    0x18,0x19,0x1A,0x1B,0x1C,0x1D,0x1E,0x1F,
    0x20,0x21,0x22,0x23,0x24,0x25,0x26,0x27
};

static const uint8_t BASEPOINT[32] = {9};

void crypto_init() { /* nothing needed for Curve25519 */ }

void generate_keypair(uint8_t* pub_out, uint8_t* priv_out) {
    BCryptGenRandom(NULL, priv_out, 32, BCRYPT_USE_SYSTEM_PREFERRED_RNG);
    // clamp per RFC 7748
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

    // HKDF-SHA256 expand — simple version
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
