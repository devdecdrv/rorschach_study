/* lib/curve25519.c
 * Curve25519 Diffie-Hellman — MSVC-compatible (no __uint128_t)
 * Uses 32-bit limbs (10 limbs, radix 2^25.5) — works on all MSVC targets.
 * Public domain.
 */

#include "curve25519.h"
#include <string.h>

typedef signed   long long  s64;
typedef unsigned long long  u64;
typedef unsigned int        u32;
typedef unsigned char       u8;

/* 10-limb representation, alternating 26/25 bit limbs */
typedef s64 felem[10];

#define LOAD_3(in) ( \
    ((u64)(u8)(in)[0])        | \
    ((u64)(u8)(in)[1] <<  8)  | \
    ((u64)(u8)(in)[2] << 16))

#define LOAD_4(in) ( \
    ((u64)(u8)(in)[0])        | \
    ((u64)(u8)(in)[1] <<  8)  | \
    ((u64)(u8)(in)[2] << 16)  | \
    ((u64)(u8)(in)[3] << 24))

static void fe_frombytes(felem h, const u8 *s) {
    s64 h0 = (s64)LOAD_4(s);
    s64 h1 = (s64)(LOAD_3(s+4)  << 6);
    s64 h2 = (s64)(LOAD_3(s+7)  << 5);
    s64 h3 = (s64)(LOAD_3(s+10) << 3);
    s64 h4 = (s64)(LOAD_3(s+13) << 2);
    s64 h5 = (s64)LOAD_4(s+16);
    s64 h6 = (s64)(LOAD_3(s+20) << 7);
    s64 h7 = (s64)(LOAD_3(s+23) << 5);
    s64 h8 = (s64)(LOAD_3(s+26) << 4);
    s64 h9 = (s64)((LOAD_3(s+29) & 8388607) << 2);

    s64 carry0, carry1, carry2, carry3, carry4,
        carry5, carry6, carry7, carry8, carry9;

    carry9 = (h9 + (s64)(1<<24)) >> 25; h0 += carry9 * 19; h9 -= carry9 << 25;
    carry1 = (h1 + (s64)(1<<24)) >> 25; h2 += carry1; h1 -= carry1 << 25;
    carry3 = (h3 + (s64)(1<<24)) >> 25; h4 += carry3; h3 -= carry3 << 25;
    carry5 = (h5 + (s64)(1<<24)) >> 25; h6 += carry5; h5 -= carry5 << 25;
    carry7 = (h7 + (s64)(1<<24)) >> 25; h8 += carry7; h7 -= carry7 << 25;
    carry0 = (h0 + (s64)(1<<25)) >> 26; h1 += carry0; h0 -= carry0 << 26;
    carry2 = (h2 + (s64)(1<<25)) >> 26; h3 += carry2; h2 -= carry2 << 26;
    carry4 = (h4 + (s64)(1<<25)) >> 26; h5 += carry4; h4 -= carry4 << 26;
    carry6 = (h6 + (s64)(1<<25)) >> 26; h7 += carry6; h6 -= carry6 << 26;
    carry8 = (h8 + (s64)(1<<25)) >> 26; h9 += carry8; h8 -= carry8 << 26;

    h[0]=h0; h[1]=h1; h[2]=h2; h[3]=h3; h[4]=h4;
    h[5]=h5; h[6]=h6; h[7]=h7; h[8]=h8; h[9]=h9;
}

static void fe_tobytes(u8 *s, const felem h) {
    s64 h0=h[0],h1=h[1],h2=h[2],h3=h[3],h4=h[4],
        h5=h[5],h6=h[6],h7=h[7],h8=h[8],h9=h[9];
    s64 q, carry0,carry1,carry2,carry3,carry4,
           carry5,carry6,carry7,carry8,carry9;

    q = (19*h9 + (s64)(1<<24)) >> 25;
    q = (h0+q)  >> 26; q = (h1+q) >> 25; q = (h2+q) >> 26;
    q = (h3+q)  >> 25; q = (h4+q) >> 26; q = (h5+q) >> 25;
    q = (h6+q)  >> 26; q = (h7+q) >> 25; q = (h8+q) >> 26;
    q = (h9+q)  >> 25;

    h0 += 19*q;
    carry0 = h0 >> 26; h1 += carry0; h0 -= carry0 << 26;
    carry1 = h1 >> 25; h2 += carry1; h1 -= carry1 << 25;
    carry2 = h2 >> 26; h3 += carry2; h2 -= carry2 << 26;
    carry3 = h3 >> 25; h4 += carry3; h3 -= carry3 << 25;
    carry4 = h4 >> 26; h5 += carry4; h4 -= carry4 << 26;
    carry5 = h5 >> 25; h6 += carry5; h5 -= carry5 << 25;
    carry6 = h6 >> 26; h7 += carry6; h6 -= carry6 << 26;
    carry7 = h7 >> 25; h8 += carry7; h7 -= carry7 << 25;
    carry8 = h8 >> 26; h9 += carry8; h8 -= carry8 << 26;
    carry9 = h9 >> 25;               h9 -= carry9 << 25;

    s[0]  = (u8)(h0 >> 0);
    s[1]  = (u8)(h0 >> 8);
    s[2]  = (u8)(h0 >> 16);
    s[3]  = (u8)((h0 >> 24) | (h1 << 2));
    s[4]  = (u8)(h1 >> 6);
    s[5]  = (u8)(h1 >> 14);
    s[6]  = (u8)((h1 >> 22) | (h2 << 3));
    s[7]  = (u8)(h2 >> 5);
    s[8]  = (u8)(h2 >> 13);
    s[9]  = (u8)((h2 >> 21) | (h3 << 5));
    s[10] = (u8)(h3 >> 3);
    s[11] = (u8)(h3 >> 11);
    s[12] = (u8)((h3 >> 19) | (h4 << 6));
    s[13] = (u8)(h4 >> 2);
    s[14] = (u8)(h4 >> 10);
    s[15] = (u8)(h4 >> 18);
    s[16] = (u8)(h5 >> 0);
    s[17] = (u8)(h5 >> 8);
    s[18] = (u8)(h5 >> 16);
    s[19] = (u8)((h5 >> 24) | (h6 << 1));
    s[20] = (u8)(h6 >> 7);
    s[21] = (u8)(h6 >> 15);
    s[22] = (u8)((h6 >> 23) | (h7 << 3));
    s[23] = (u8)(h7 >> 5);
    s[24] = (u8)(h7 >> 13);
    s[25] = (u8)((h7 >> 21) | (h8 << 4));
    s[26] = (u8)(h8 >> 4);
    s[27] = (u8)(h8 >> 12);
    s[28] = (u8)((h8 >> 20) | (h9 << 6));
    s[29] = (u8)(h9 >> 2);
    s[30] = (u8)(h9 >> 10);
    s[31] = (u8)(h9 >> 18);
}

static void fe_0(felem h) { memset(h, 0, sizeof(felem)); }
static void fe_1(felem h) { memset(h, 0, sizeof(felem)); h[0]=1; }

static void fe_copy(felem dst, const felem src) {
    memcpy(dst, src, sizeof(felem));
}

static void fe_add(felem h, const felem f, const felem g) {
    int i; for(i=0;i<10;i++) h[i]=f[i]+g[i];
}

static void fe_sub(felem h, const felem f, const felem g) {
    int i; for(i=0;i<10;i++) h[i]=f[i]-g[i];
}

static void fe_cswap(felem f, felem g, u32 b) {
    s64 mask = -(s64)b;
    int i;
    for(i=0;i<10;i++){
        s64 x = mask & (f[i]^g[i]);
        f[i] ^= x; g[i] ^= x;
    }
}

static void fe_mul(felem h, const felem f, const felem g) {
    s64 f0=f[0],f1=f[1],f2=f[2],f3=f[3],f4=f[4],
        f5=f[5],f6=f[6],f7=f[7],f8=f[8],f9=f[9];
    s64 g0=g[0],g1=g[1],g2=g[2],g3=g[3],g4=g[4],
        g5=g[5],g6=g[6],g7=g[7],g8=g[8],g9=g[9];
    s64 g1_19=19*g1,g2_19=19*g2,g3_19=19*g3,g4_19=19*g4,
        g5_19=19*g5,g6_19=19*g6,g7_19=19*g7,g8_19=19*g8,g9_19=19*g9;
    s64 f1_2=2*f1,f3_2=2*f3,f5_2=2*f5,f7_2=2*f7,f9_2=2*f9;

    s64 h0,h1,h2,h3,h4,h5,h6,h7,h8,h9;
    s64 carry0,carry1,carry2,carry3,carry4,
        carry5,carry6,carry7,carry8,carry9;

    h0 = f0*g0    + f1_2*g9_19 + f2*g8_19   + f3_2*g7_19 + f4*g6_19
       + f5_2*g5_19 + f6*g4_19 + f7_2*g3_19 + f8*g2_19   + f9_2*g1_19;
    h1 = f0*g1    + f1*g0      + f2*g9_19   + f3*g8_19   + f4*g7_19
       + f5*g6_19   + f6*g5_19 + f7*g4_19   + f8*g3_19   + f9*g2_19;
    h2 = f0*g2    + f1_2*g1    + f2*g0      + f3_2*g9_19 + f4*g8_19
       + f5_2*g7_19 + f6*g6_19 + f7_2*g5_19 + f8*g4_19   + f9_2*g3_19;
    h3 = f0*g3    + f1*g2      + f2*g1      + f3*g0      + f4*g9_19
       + f5*g8_19   + f6*g7_19 + f7*g6_19   + f8*g5_19   + f9*g4_19;
    h4 = f0*g4    + f1_2*g3    + f2*g2      + f3_2*g1    + f4*g0
       + f5_2*g9_19 + f6*g8_19 + f7_2*g7_19 + f8*g6_19   + f9_2*g5_19;
    h5 = f0*g5    + f1*g4      + f2*g3      + f3*g2      + f4*g1
       + f5*g0      + f6*g9_19 + f7*g8_19   + f8*g7_19   + f9*g6_19;
    h6 = f0*g6    + f1_2*g5    + f2*g4      + f3_2*g3    + f4*g2
       + f5_2*g1    + f6*g0    + f7_2*g9_19 + f8*g8_19   + f9_2*g7_19;
    h7 = f0*g7    + f1*g6      + f2*g5      + f3*g4      + f4*g3
       + f5*g2      + f6*g1    + f7*g0      + f8*g9_19   + f9*g8_19;
    h8 = f0*g8    + f1_2*g7    + f2*g6      + f3_2*g5    + f4*g4
       + f5_2*g3    + f6*g2    + f7_2*g1    + f8*g0      + f9_2*g9_19;
    h9 = f0*g9    + f1*g8      + f2*g7      + f3*g6      + f4*g5
       + f5*g4      + f6*g3    + f7*g2      + f8*g1      + f9*g0;

    carry0 = (h0+(s64)(1<<25)) >> 26; h1+=carry0; h0-=carry0<<26;
    carry4 = (h4+(s64)(1<<25)) >> 26; h5+=carry4; h4-=carry4<<26;
    carry1 = (h1+(s64)(1<<24)) >> 25; h2+=carry1; h1-=carry1<<25;
    carry5 = (h5+(s64)(1<<24)) >> 25; h6+=carry5; h5-=carry5<<25;
    carry2 = (h2+(s64)(1<<25)) >> 26; h3+=carry2; h2-=carry2<<26;
    carry6 = (h6+(s64)(1<<25)) >> 26; h7+=carry6; h6-=carry6<<26;
    carry3 = (h3+(s64)(1<<24)) >> 25; h4+=carry3; h3-=carry3<<25;
    carry7 = (h7+(s64)(1<<24)) >> 25; h8+=carry7; h7-=carry7<<25;
    carry4 = (h4+(s64)(1<<25)) >> 26; h5+=carry4; h4-=carry4<<26;
    carry8 = (h8+(s64)(1<<25)) >> 26; h9+=carry8; h8-=carry8<<26;
    carry9 = (h9+(s64)(1<<24)) >> 25; h0+=carry9*19; h9-=carry9<<25;
    carry0 = (h0+(s64)(1<<25)) >> 26; h1+=carry0; h0-=carry0<<26;

    h[0]=h0;h[1]=h1;h[2]=h2;h[3]=h3;h[4]=h4;
    h[5]=h5;h[6]=h6;h[7]=h7;h[8]=h8;h[9]=h9;
}

static void fe_sq(felem h, const felem f) {
    fe_mul(h, f, f);
}

static void fe_sq2(felem h, const felem f) {
    felem t;
    fe_sq(t, f);
    int i; for(i=0;i<10;i++) h[i]=t[i]*2;
}

static void fe_invert(felem out, const felem z) {
    felem t0,t1,t2,t3;
    int i;

    fe_sq(t0,z);
    fe_sq(t1,t0); fe_sq(t1,t1);
    fe_mul(t1,z,t1);
    fe_mul(t0,t0,t1);
    fe_sq(t2,t0); fe_mul(t1,t1,t2);
    fe_sq(t2,t1);
    for(i=1;i<5;i++) fe_sq(t2,t2);
    fe_mul(t1,t2,t1);
    fe_sq(t2,t1);
    for(i=1;i<10;i++) fe_sq(t2,t2);
    fe_mul(t2,t2,t1);
    fe_sq(t3,t2);
    for(i=1;i<20;i++) fe_sq(t3,t3);
    fe_mul(t2,t3,t2);
    fe_sq(t2,t2);
    for(i=1;i<10;i++) fe_sq(t2,t2);
    fe_mul(t1,t2,t1);
    fe_sq(t2,t1);
    for(i=1;i<50;i++) fe_sq(t2,t2);
    fe_mul(t2,t2,t1);
    fe_sq(t3,t2);
    for(i=1;i<100;i++) fe_sq(t3,t3);
    fe_mul(t2,t3,t2);
    fe_sq(t2,t2);
    for(i=1;i<50;i++) fe_sq(t2,t2);
    fe_mul(t1,t2,t1);
    fe_sq(t1,t1);
    for(i=1;i<5;i++) fe_sq(t1,t1);
    fe_mul(out,t1,t0);
}

static void x25519_ladder(
    felem x2, felem z2,
    felem x3, felem z3,
    const felem x1,
    const u8 *scalar)
{
    felem A,AA,B,BB,E,C,D,DA,CB;
    u32 swap = 0;
    int i;

    fe_1(x2); fe_0(z2);
    fe_copy(x3, x1); fe_1(z3);

    for(i=254;i>=0;i--){
        u32 bit = (scalar[i>>3] >> (i&7)) & 1;
        u32 s = swap ^ bit;
        fe_cswap(x2,x3,s);
        fe_cswap(z2,z3,s);
        swap = bit;

        fe_add(A, x2, z2);
        fe_sq(AA, A);
        fe_sub(B, x2, z2);
        fe_sq(BB, B);
        fe_sub(E, AA, BB);
        fe_add(C, x3, z3);
        fe_sub(D, x3, z3);
        fe_mul(DA, D, A);
        fe_mul(CB, C, B);
        fe_add(x3, DA, CB); fe_sq(x3, x3);
        fe_sub(z3, DA, CB); fe_sq(z3, z3); fe_mul(z3, z3, x1);
        fe_mul(x2, AA, BB);
        {
            felem t;
            s64 a24_19 = 121665;
            int j;
            fe_copy(t,E);
            for(j=0;j<10;j++) t[j] *= a24_19;
            /* reduce t */
            {
                s64 carry;
                carry=(t[0]+(s64)(1<<25))>>26; t[1]+=carry; t[0]-=carry<<26;
                carry=(t[1]+(s64)(1<<24))>>25; t[2]+=carry; t[1]-=carry<<25;
                carry=(t[2]+(s64)(1<<25))>>26; t[3]+=carry; t[2]-=carry<<26;
                carry=(t[3]+(s64)(1<<24))>>25; t[4]+=carry; t[3]-=carry<<25;
                carry=(t[4]+(s64)(1<<25))>>26; t[5]+=carry; t[4]-=carry<<26;
                carry=(t[5]+(s64)(1<<24))>>25; t[6]+=carry; t[5]-=carry<<25;
                carry=(t[6]+(s64)(1<<25))>>26; t[7]+=carry; t[6]-=carry<<26;
                carry=(t[7]+(s64)(1<<24))>>25; t[8]+=carry; t[7]-=carry<<25;
                carry=(t[8]+(s64)(1<<25))>>26; t[9]+=carry; t[8]-=carry<<26;
                carry=(t[9]+(s64)(1<<24))>>25; t[0]+=carry*19; t[9]-=carry<<25;
            }
            fe_add(t, AA, t);
            fe_mul(z2, E, t);
        }
    }
    fe_cswap(x2,x3,swap);
    fe_cswap(z2,z3,swap);
}

int curve25519_donna(
    u8*       mypublic,
    const u8* secret,
    const u8* basepoint)
{
    felem x1, x2, z2, x3, z3, zinv;

    fe_frombytes(x1, basepoint);
    x25519_ladder(x2, z2, x3, z3, x1, secret);
    fe_invert(zinv, z2);
    fe_mul(x2, x2, zinv);
    fe_tobytes(mypublic, x2);
    return 0;
}
