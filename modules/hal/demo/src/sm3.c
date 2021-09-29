/*
 * Copyright (C) 2016-2019 Alibaba Group Holding Limited
 */

/*
 * SM3 Implementation
 * Standard: GM/T 0004-2012(http://www.gmbz.org.cn/main/bzlb.html)
 */

#include "sm3.h"

/* Implementation that should never be optimized out by the compiler */
static void zeroize(void *v, size_t n)
{
    volatile uint8_t *p = (uint8_t *)v;
    while (n--)
        *p++ = 0;
}

/*
 * 32-bit integer manipulation macros (big endian)
 */
#ifndef GET_UINT32_BE
#define GET_UINT32_BE(n, b, i)                                              \
    {                                                                       \
        (n) = ((uint32_t)(b)[(i)] << 24) | ((uint32_t)(b)[(i) + 1] << 16) | \
              ((uint32_t)(b)[(i) + 2] << 8) | ((uint32_t)(b)[(i) + 3]);     \
    }
#endif

#ifndef PUT_UINT32_BE
#define PUT_UINT32_BE(n, b, i)                     \
    {                                              \
        (b)[(i)]     = (uint8_t)((n) >> 24); \
        (b)[(i) + 1] = (uint8_t)((n) >> 16); \
        (b)[(i) + 2] = (uint8_t)((n) >> 8);  \
        (b)[(i) + 3] = (uint8_t)((n));       \
    }
#endif

void impl_sm3_init(impl_sm3_context *ctx)
{
    memset(ctx, 0, sizeof(impl_sm3_context));
}

void impl_sm3_free(impl_sm3_context *ctx)
{
    if (ctx == NULL)
        return;

    zeroize(ctx, sizeof(impl_sm3_context));
}

/*
 * SM3 context setup
 */
void impl_sm3_starts(impl_sm3_context *ctx)
{
    ctx->total[0] = 0;
    ctx->total[1] = 0;

    ctx->state[0] = 0x7380166f;
    ctx->state[1] = 0x4914b2b9;
    ctx->state[2] = 0x172442d7;
    ctx->state[3] = 0xda8a0600;
    ctx->state[4] = 0xa96f30bc;
    ctx->state[5] = 0x163138aa;
    ctx->state[6] = 0xe38dee4d;
    ctx->state[7] = 0xb0fb0e4e;
}

static const uint32_t T[] =
{
    0x79cc4519, 0x79cc4519, 0x79cc4519, 0x79cc4519,
    0x79cc4519, 0x79cc4519, 0x79cc4519, 0x79cc4519,
    0x79cc4519, 0x79cc4519, 0x79cc4519, 0x79cc4519,
    0x79cc4519, 0x79cc4519, 0x79cc4519, 0x79cc4519,
    0x7a879d8a, 0x7a879d8a, 0x7a879d8a, 0x7a879d8a,
    0x7a879d8a, 0x7a879d8a, 0x7a879d8a, 0x7a879d8a,
    0x7a879d8a, 0x7a879d8a, 0x7a879d8a, 0x7a879d8a,
    0x7a879d8a, 0x7a879d8a, 0x7a879d8a, 0x7a879d8a,
    0x7a879d8a, 0x7a879d8a, 0x7a879d8a, 0x7a879d8a,
    0x7a879d8a, 0x7a879d8a, 0x7a879d8a, 0x7a879d8a,
    0x7a879d8a, 0x7a879d8a, 0x7a879d8a, 0x7a879d8a,
    0x7a879d8a, 0x7a879d8a, 0x7a879d8a, 0x7a879d8a,
    0x7a879d8a, 0x7a879d8a, 0x7a879d8a, 0x7a879d8a,
    0x7a879d8a, 0x7a879d8a, 0x7a879d8a, 0x7a879d8a,
    0x7a879d8a, 0x7a879d8a, 0x7a879d8a, 0x7a879d8a,
    0x7a879d8a, 0x7a879d8a, 0x7a879d8a, 0x7a879d8a
};

#define ROTL(x,n) (((x) << n) | ((x) >> (32 - n)))

#define FF0(x,y,z) ((x) ^ (y) ^ (z))
#define FF1(x,y,z) (((x) & (y)) | ((x) & (z)) | ((y) & (z)))

#define GG0(x,y,z) ((x) ^ (y) ^ (z))
#define GG1(x,y,z) (((x) & (y)) | ((~x) & (z)))

#define P0(x) ((x) ^ (ROTL(x,9)) ^ (ROTL(x,17)))
#define P1(x) ((x) ^ (ROTL(x,15)) ^ (ROTL(x,23)))

void impl_sm3_process(impl_sm3_context *ctx,
                      const uint8_t   data[64])
{
    uint32_t SS1, SS2, TT1, TT2, W[68], WW[64];
    uint32_t A[8];
    uint32_t i;

    for (i = 0; i < 8; i++)
        A[i] = ctx->state[i];

    /*  expansion   */
    for (i = 0; i < 68; i++) {
        if( i < 16 ) {
            GET_UINT32_BE( W[i], data, 4 * i );
        } else {
            W[i] = (P1(((W[i-16]) ^ (W[i-9]) ^ (ROTL(W[i-3],15)))) ^ (ROTL(W[i-13],7)) ^ (W[i-6]));
        }
    }
    for (i = 0; i < 64; i++) {
        WW[i] = (W[i]) ^ (W[i+4]);
        /* compression  */
        if (i == 0)
            SS1 = ROTL(((ROTL(A[0],12)) + A[4] + T[i]), 7);
        else
            SS1 = ROTL(((ROTL(A[0],12)) + A[4] + ROTL(T[i], (i & 0x1F))), 7);
        SS2 = SS1 ^ (ROTL(A[0],12));
        if (i < 16) {
            TT1 = FF0(A[0], A[1], A[2]) + A[3] + SS2 + WW[i];
            TT2 = GG0(A[4], A[5], A[6]) + A[7] + SS1 + W[i];
        } else {
            TT1 = FF1(A[0], A[1], A[2]) + A[3] + SS2 + WW[i];
            TT2 = GG1(A[4], A[5], A[6]) + A[7] + SS1 + W[i];
        }
        A[3] = A[2];
        A[2] = ROTL(A[1],9);
        A[1] = A[0];
        A[0] = TT1;
        A[7] = A[6];
        A[6] = ROTL(A[5],19);
        A[5] = A[4];
        A[4] = P0(TT2);
    }

    for ( i = 0; i < 8; i++ ) {
        ctx->state[i] ^= A[i];
    }
}

/*
 * SM3 process buffer
 */
void impl_sm3_update(impl_sm3_context *ctx, const uint8_t *input,
                     size_t ilen)
{
    size_t fill;
    uint32_t left;

    if (ilen == 0)
        return;

    left = ctx->total[0] & 0x3F;
    fill = 64 - left;

    ctx->total[0] += (uint32_t)ilen;
    ctx->total[0] &= 0xFFFFFFFF;

    if (ctx->total[0] < (uint32_t)ilen)
        ctx->total[1]++;

    if (left && ilen >= fill) {
        memcpy((void *)(ctx->buffer + left), input, fill);
        impl_sm3_process(ctx, ctx->buffer);
        input += fill;
        ilen -= fill;
        left = 0;
    }

    while (ilen >= 64) {
        impl_sm3_process(ctx, input);
        input += 64;
        ilen -= 64;
    }

    if (ilen > 0)
        memcpy((void *)(ctx->buffer + left), input, ilen);
}

static const uint8_t sm3_padding[64] = {
    0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0,    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0,    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
};

/*
 * SM3 final digest
 */
void impl_sm3_finish(impl_sm3_context *ctx, uint8_t output[32])
{
    uint32_t last, padn;
    uint32_t high, low;
    uint8_t msglen[8];

    high = (ctx->total[0] >> 29) | (ctx->total[1] << 3);
    low  = (ctx->total[0] << 3);

    PUT_UINT32_BE(high, msglen, 0);
    PUT_UINT32_BE(low, msglen, 4);

    last = ctx->total[0] & 0x3F;
    padn = (last < 56) ? (56 - last) : (120 - last);
    impl_sm3_update(ctx, sm3_padding, padn);
    impl_sm3_update(ctx, msglen, 8);

    PUT_UINT32_BE( ctx->state[0], output,  0 );
    PUT_UINT32_BE( ctx->state[1], output,  4 );
    PUT_UINT32_BE( ctx->state[2], output,  8 );
    PUT_UINT32_BE( ctx->state[3], output, 12 );
    PUT_UINT32_BE( ctx->state[4], output, 16 );
    PUT_UINT32_BE( ctx->state[5], output, 20 );
    PUT_UINT32_BE( ctx->state[6], output, 24 );
    PUT_UINT32_BE( ctx->state[7], output, 28 );
}

