/* lib/curve25519.c
 * Adam Langley's curve25519-donna — public domain
 * Source: https://github.com/agl/curve25519-donna
 * Minimal portable C implementation.
 */

#include "curve25519.h"
#include <string.h>

typedef uint64_t limb;
typedef limb felem[5];
typedef __uint128_t uint128_t;

#define MASK51  ((limb)0x7ffffffffffff)

static void felem_copy(felem out, const felem in) {
    memcpy(out, in, sizeof(felem));
}

static void fsum(felem out, const felem in) {
    for (int i = 0; i < 5; i++) out[i] += in[i];
}

static void fdifference_backwards(felem out, const felem in) {
    static const limb TWO54M152 = (((limb)1) << 54) - 152;
    static const limb TWO54M8   = (((limb)1) << 54) - 8;
    out[0] = in[0] + TWO54M152 - out[0];
    out[1] = in[1] + TWO54M8   - out[1];
    out[2] = in[2] + TWO54M8   - out[2];
    out[3] = in[3] + TWO54M8   - out[3];
    out[4] = in[4] + TWO54M8   - out[4];
}

static void fscalar_product(felem out, const felem in, limb scalar) {
    uint128_t a;
    a = ((uint128_t)in[0]) * scalar; out[0] = (limb)(a & MASK51); a >>= 51;
    a += ((uint128_t)in[1]) * scalar; out[1] = (limb)(a & MASK51); a >>= 51;
    a += ((uint128_t)in[2]) * scalar; out[2] = (limb)(a & MASK51); a >>= 51;
    a += ((uint128_t)in[3]) * scalar; out[3] = (limb)(a & MASK51); a >>= 51;
    a += ((uint128_t)in[4]) * scalar; out[4] = (limb)(a & MASK51); a >>= 51;
    out[0] += (limb)(a * 19);
}

static void fmul(felem out, const felem in2, const felem in) {
    uint128_t t[5];
    limb r0=in[0],r1=in[1],r2=in[2],r3=in[3],r4=in[4];
    limb s0=in2[0],s1=in2[1],s2=in2[2],s3=in2[3],s4=in2[4];
    limb s1_19=19*s1,s2_19=19*s2,s3_19=19*s3,s4_19=19*s4;

    t[0] =((uint128_t)s0)*r0 +((uint128_t)s1_19)*r4 +((uint128_t)s2_19)*r3 +((uint128_t)s3_19)*r2 +((uint128_t)s4_19)*r1;
    t[1] =((uint128_t)s0)*r1 +((uint128_t)s1)*r0    +((uint128_t)s2_19)*r4 +((uint128_t)s3_19)*r3 +((uint128_t)s4_19)*r2;
    t[2] =((uint128_t)s0)*r2 +((uint128_t)s1)*r1    +((uint128_t)s2)*r0    +((uint128_t)s3_19)*r4 +((uint128_t)s4_19)*r3;
    t[3] =((uint128_t)s0)*r3 +((uint128_t)s1)*r2    +((uint128_t)s2)*r1    +((uint128_t)s3)*r0    +((uint128_t)s4_19)*r4;
    t[4] =((uint128_t)s0)*r4 +((uint128_t)s1)*r3    +((uint128_t)s2)*r2    +((uint128_t)s3)*r1    +((uint128_t)s4)*r0;

    limb c;
    c = (limb)(t[0] >> 51); out[0] = (limb)(t[0] & MASK51); t[1] += c;
    c = (limb)(t[1] >> 51); out[1] = (limb)(t[1] & MASK51); t[2] += c;
    c = (limb)(t[2] >> 51); out[2] = (limb)(t[2] & MASK51); t[3] += c;
    c = (limb)(t[3] >> 51); out[3] = (limb)(t[3] & MASK51); t[4] += c;
    c = (limb)(t[4] >> 51); out[4] = (limb)(t[4] & MASK51); out[0] += 19*c;
}

static void fsquare_times(felem out, const felem in, limb count) {
    felem tmp;
    felem_copy(tmp, in);
    while (count--) {
        uint128_t t[5];
        limb r0=tmp[0],r1=tmp[1],r2=tmp[2],r3=tmp[3],r4=tmp[4];
        limb d0=2*r0,d1=2*r1,d2=2*r2,d3=2*r3;
        limb r1_19=19*r1,r2_19=19*r2,r4_19=19*r4;

        t[0] =((uint128_t)r0)*r0    +((uint128_t)d1)*r4_19 +((uint128_t)d2)*(19*r3);
        t[1] =((uint128_t)d0)*r1    +((uint128_t)r2)*(19*d3)+((uint128_t)r4_19)*r4_19;
        t[2] =((uint128_t)d0)*r2    +((uint128_t)r1)*r1    +((uint128_t)d3)*r4_19;
        t[3] =((uint128_t)d0)*r3    +((uint128_t)d1)*r2    +((uint128_t)r4)*r4_19;
        t[4] =((uint128_t)d0)*r4    +((uint128_t)d1)*r3    +((uint128_t)r2)*r2;

        limb c;
        c = (limb)(t[0] >> 51); tmp[0] = (limb)(t[0] & MASK51); t[1] += c;
        c = (limb)(t[1] >> 51); tmp[1] = (limb)(t[1] & MASK51); t[2] += c;
        c = (limb)(t[2] >> 51); tmp[2] = (limb)(t[2] & MASK51); t[3] += c;
        c = (limb)(t[3] >> 51); tmp[3] = (limb)(t[3] & MASK51); t[4] += c;
        c = (limb)(t[4] >> 51); tmp[4] = (limb)(t[4] & MASK51); tmp[0] += 19*c;
    }
    felem_copy(out, tmp);
}

static void finverse(felem out, const felem in) {
    felem t0,t1,t2,t3;
    fsquare_times(t0, in, 1);
    fsquare_times(t1, t0, 2);
    fmul(t1, in, t1);
    fmul(t0, t0, t1);
    fsquare_times(t2, t0, 1);
    fmul(t1, t1, t2);
    fsquare_times(t2, t1, 5);
    fmul(t1, t2, t1);
    fsquare_times(t2, t1, 10);
    fmul(t2, t2, t1);
    fsquare_times(t3, t2, 20);
    fmul(t2, t3, t2);
    fsquare_times(t2, t2, 10);
    fmul(t1, t2, t1);
    fsquare_times(t2, t1, 50);
    fmul(t2, t2, t1);
    fsquare_times(t3, t2, 100);
    fmul(t2, t3, t2);
    fsquare_times(t2, t2, 50);
    fmul(t1, t2, t1);
    fsquare_times(t1, t1, 5);
    fmul(out, t1, t0);
}

static void swap_conditional(felem a, felem b, limb iswap) {
    const limb swap = (limb)(-(int64_t)iswap);
    for (int i = 0; i < 5; i++) {
        limb x = swap & (a[i] ^ b[i]);
        a[i] ^= x; b[i] ^= x;
    }
}

static void fmonty(
    felem x2, felem z2,
    felem x3, felem z3,
    felem x,  felem z,
    felem xprime, felem zprime,
    const felem qmqp)
{
    felem origx, origxprime, zzz, xx, zz, xxprime, zzprime, zzzprime;

    felem_copy(origx,      x);
    felem_copy(origxprime, xprime);

    fsum(x, z);
    fdifference_backwards(z, origx);

    fsum(xprime, zprime);
    fdifference_backwards(zprime, origxprime);

    fmul(xxprime, xprime, z);
    fmul(zzprime, x, zprime);

    felem_copy(origxprime, xxprime);
    fsum(xxprime, zzprime);
    fdifference_backwards(zzprime, origxprime);

    fsquare_times(x3,  xxprime, 1);
    fsquare_times(zz,  zzprime, 1);
    fmul(z3, zz, qmqp);

    fsquare_times(xx, x, 1);
    fsquare_times(zz, z, 1);
    fmul(x2, xx, zz);
    fdifference_backwards(zz, xx);
    fscalar_product(zzz, zz, 121665);
    fsum(zzz, xx);
    fmul(z2, zz, zzz);
}

static void cmult(
    felem resultx, felem resultz,
    const uint8_t* n,
    const felem q)
{
    felem a={0},b={1},c={1},d={0};
    felem_copy(b, q);
    felem_copy(c, q);

    for (int i = 254; i >= 0; i--) {
        limb bit = (n[i>>3] >> (i&7)) & 1;
        swap_conditional(a, b, bit);
        swap_conditional(c, d, bit);
        fmonty(a, c, b, d, a, c, b, d, q);
        swap_conditional(a, b, bit);
        swap_conditional(c, d, bit);
    }
    felem_copy(resultx, a);
    felem_copy(resultz, c);
}

static void crecip(felem out, const felem z) {
    finverse(out, z);
}

static void felem_contract(uint8_t* out, const felem in) {
    static const limb TWO51M1 = MASK51;
    felem t;
    felem_copy(t, in);
    limb c;
    c = t[0] >> 51; t[0] &= MASK51; t[1] += c;
    c = t[1] >> 51; t[1] &= MASK51; t[2] += c;
    c = t[2] >> 51; t[2] &= MASK51; t[3] += c;
    c = t[3] >> 51; t[3] &= MASK51; t[4] += c;
    c = t[4] >> 51; t[4] &= MASK51; t[0] += 19*c;

    t[0] += 19;
    c = t[0] >> 51; t[0] &= MASK51; t[1] += c;
    c = t[1] >> 51; t[1] &= MASK51; t[2] += c;
    c = t[2] >> 51; t[2] &= MASK51; t[3] += c;
    c = t[3] >> 51; t[3] &= MASK51; t[4] += c;
    t[4] &= MASK51;

    limb mask = -(t[4] >> 51); t[4] &= MASK51;
    t[0] -= 19 & mask;
    t[0] &= MASK51;

    out[ 0] = (uint8_t)(t[0]);
    out[ 1] = (uint8_t)(t[0] >> 8);
    out[ 2] = (uint8_t)(t[0] >> 16);
    out[ 3] = (uint8_t)(t[0] >> 24);
    out[ 4] = (uint8_t)(t[0] >> 32);
    out[ 5] = (uint8_t)(t[0] >> 40);
    out[ 6] = (uint8_t)((t[0] >> 48) | (t[1] << 3));
    out[ 7] = (uint8_t)(t[1] >> 5);
    out[ 8] = (uint8_t)(t[1] >> 13);
    out[ 9] = (uint8_t)(t[1] >> 21);
    out[10] = (uint8_t)(t[1] >> 29);
    out[11] = (uint8_t)(t[1] >> 37);
    out[12] = (uint8_t)((t[1] >> 45) | (t[2] << 6));
    out[13] = (uint8_t)(t[2] >> 2);
    out[14] = (uint8_t)(t[2] >> 10);
    out[15] = (uint8_t)(t[2] >> 18);
    out[16] = (uint8_t)(t[2] >> 26);
    out[17] = (uint8_t)(t[2] >> 34);
    out[18] = (uint8_t)(t[2] >> 42);
    out[19] = (uint8_t)((t[2] >> 50) | (t[3] << 1));
    out[20] = (uint8_t)(t[3] >> 7);
    out[21] = (uint8_t)(t[3] >> 15);
    out[22] = (uint8_t)(t[3] >> 23);
    out[23] = (uint8_t)(t[3] >> 31);
    out[24] = (uint8_t)(t[3] >> 39);
    out[25] = (uint8_t)((t[3] >> 47) | (t[4] << 4));
    out[26] = (uint8_t)(t[4] >> 4);
    out[27] = (uint8_t)(t[4] >> 12);
    out[28] = (uint8_t)(t[4] >> 20);
    out[29] = (uint8_t)(t[4] >> 28);
    out[30] = (uint8_t)(t[4] >> 36);
    out[31] = (uint8_t)(t[4] >> 44);
}

static void felem_expand(felem out, const uint8_t* in) {
    out[0] =  ((limb)in[ 0])        | ((limb)in[ 1] << 8) | ((limb)in[ 2] << 16) | ((limb)in[ 3] << 24) | ((limb)in[ 4] << 32) | ((limb)in[ 5] << 40) | (((limb)in[ 6] & 0x07) << 48);
    out[1] = (((limb)in[ 6]) >> 3)  | ((limb)in[ 7] << 5) | ((limb)in[ 8] << 13) | ((limb)in[ 9] << 21) | ((limb)in[10] << 29) | ((limb)in[11] << 37) | (((limb)in[12] & 0x3f) << 45);
    out[2] = (((limb)in[12]) >> 6)  | ((limb)in[13] << 2) | ((limb)in[14] << 10) | ((limb)in[15] << 18) | ((limb)in[16] << 26) | ((limb)in[17] << 34) | ((limb)in[18] << 42) | (((limb)in[19] & 0x01) << 50);
    out[3] = (((limb)in[19]) >> 1)  | ((limb)in[20] << 7) | ((limb)in[21] << 15) | ((limb)in[22] << 23) | ((limb)in[23] << 31) | ((limb)in[24] << 39) | (((limb)in[25] & 0x0f) << 47);
    out[4] = (((limb)in[25]) >> 4)  | ((limb)in[26] << 4) | ((limb)in[27] << 12) | ((limb)in[28] << 20) | ((limb)in[29] << 28) | ((limb)in[30] << 36) | (((limb)in[31] & 0x7f) << 44);
}

int curve25519_donna(
    uint8_t*       mypublic,
    const uint8_t* secret,
    const uint8_t* basepoint)
{
    felem bp, x, z, zmone;
    felem_expand(bp, basepoint);
    cmult(x, z, secret, bp);
    crecip(zmone, z);
    fmul(z, x, zmone);
    felem_contract(mypublic, z);
    return 0;
}
