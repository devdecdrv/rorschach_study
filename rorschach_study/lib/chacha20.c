/* lib/chacha20.c
 * ChaCha20 — IETF variant (RFC 8439): 32-byte key, 12-byte nonce, 32-bit counter.
 * Public domain.
 */

#include "chacha20.h"
#include <string.h>

#define ROTL32(v, n) (((v) << (n)) | ((v) >> (32 - (n))))

#define QR(a, b, c, d)      \
    a += b; d ^= a; d = ROTL32(d, 16); \
    c += d; b ^= c; b = ROTL32(b, 12); \
    a += b; d ^= a; d = ROTL32(d,  8); \
    c += d; b ^= c; b = ROTL32(b,  7)

static void chacha20_block(
    uint32_t out[16],
    const uint32_t in[16])
{
    uint32_t x[16];
    memcpy(x, in, 64);

    for (int i = 0; i < 10; i++) {
        /* column rounds */
        QR(x[0], x[4], x[ 8], x[12]);
        QR(x[1], x[5], x[ 9], x[13]);
        QR(x[2], x[6], x[10], x[14]);
        QR(x[3], x[7], x[11], x[15]);
        /* diagonal rounds */
        QR(x[0], x[5], x[10], x[15]);
        QR(x[1], x[6], x[11], x[12]);
        QR(x[2], x[7], x[ 8], x[13]);
        QR(x[3], x[4], x[ 9], x[14]);
    }

    for (int i = 0; i < 16; i++)
        out[i] = x[i] + in[i];
}

static inline uint32_t load_le32(const uint8_t* p) {
    return (uint32_t)p[0]       |
           (uint32_t)p[1] <<  8 |
           (uint32_t)p[2] << 16 |
           (uint32_t)p[3] << 24;
}

static inline void store_le32(uint8_t* p, uint32_t v) {
    p[0] = (uint8_t)(v);
    p[1] = (uint8_t)(v >>  8);
    p[2] = (uint8_t)(v >> 16);
    p[3] = (uint8_t)(v >> 24);
}

void chacha20_xor(
    uint8_t*       out,
    const uint8_t* in,
    size_t         len,
    const uint8_t* key,
    const uint8_t* nonce,
    uint32_t       counter)
{
    /* initial state: "expa" "nd 3" "2-by" "te k" + key + counter + nonce */
    uint32_t state[16] = {
        0x61707865, 0x3320646e, 0x79622d32, 0x6b206574,
        load_le32(key +  0), load_le32(key +  4),
        load_le32(key +  8), load_le32(key + 12),
        load_le32(key + 16), load_le32(key + 20),
        load_le32(key + 24), load_le32(key + 28),
        counter,
        load_le32(nonce + 0),
        load_le32(nonce + 4),
        load_le32(nonce + 8)
    };

    uint32_t block[16];
    uint8_t  keystream[64];

    while (len > 0) {
        chacha20_block(block, state);
        state[12]++;    /* increment block counter */

        for (int i = 0; i < 16; i++)
            store_le32(keystream + i*4, block[i]);

        size_t take = len < 64 ? len : 64;
        for (size_t i = 0; i < take; i++)
            out[i] = in[i] ^ keystream[i];

        in  += take;
        out += take;
        len -= take;
    }
}
