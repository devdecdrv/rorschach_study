/* lib/curve25519.h */
#ifndef CURVE25519_H
#define CURVE25519_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * curve25519_donna:
 *   mypublic   — output: 32-byte public key
 *   secret     — input:  32-byte clamped private key
 *   basepoint  — input:  32-byte base point (use {9} for key gen)
 */
int curve25519_donna(
    uint8_t*       mypublic,
    const uint8_t* secret,
    const uint8_t* basepoint
);

#ifdef __cplusplus
}
#endif

#endif /* CURVE25519_H */
