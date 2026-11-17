/* lib/chacha20.h */
#ifndef CHACHA20_H
#define CHACHA20_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * chacha20_xor:
 *   out    — output buffer (may alias in)
 *   in     — input buffer
 *   len    — byte length
 *   key    — 32-byte key
 *   nonce  — 12-byte nonce (RFC 8439 / IETF variant)
 *   counter— initial block counter (0 for first call)
 */
void chacha20_xor(
    uint8_t*       out,
    const uint8_t* in,
    size_t         len,
    const uint8_t* key,
    const uint8_t* nonce,
    uint32_t       counter
);

#ifdef __cplusplus
}
#endif

#endif /* CHACHA20_H */
