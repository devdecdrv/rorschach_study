#pragma once
#include <cstdint>

void crypto_init();
void generate_keypair(uint8_t* pub_out, uint8_t* priv_out);
void derive_session_key(
    const uint8_t* our_priv,
    const uint8_t* their_pub,
    uint8_t* key_out       // 32 bytes ChaCha20 key
);
void chacha20_encrypt_buffer(
    uint8_t* buf,
    size_t len,
    const uint8_t* key,
    const uint8_t* nonce   // 12 bytes
);
