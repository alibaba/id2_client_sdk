/*
 * Copyright (C) 2017-2019 Alibaba Group Holding Limited.
 */

/*
 * SM2 Implementation
 * Standard: GM/T 0003.1-2012(http://www.gmbz.org.cn/main/bzlb.html)
 */

#include "config.h"
#include "sm2.h"
#include "ecp.h"
#include "sm3.h"

/*
 * 32-bit integer manipulation macros (big endian)
 */
#ifndef GET_UINT32_BE
#define GET_UINT32_BE(n,b,i)                            \
do {                                                    \
    (n) = ( (uint32_t) (b)[(i)    ] << 24 )             \
        | ( (uint32_t) (b)[(i) + 1] << 16 )             \
        | ( (uint32_t) (b)[(i) + 2] <<  8 )             \
        | ( (uint32_t) (b)[(i) + 3]       );            \
} while( 0 )
#endif

#ifndef PUT_UINT32_BE
#define PUT_UINT32_BE(n,b,i)                            \
do {                                                    \
    (b)[(i)    ] = (unsigned char) ( (n) >> 24 );       \
    (b)[(i) + 1] = (unsigned char) ( (n) >> 16 );       \
    (b)[(i) + 2] = (unsigned char) ( (n) >>  8 );       \
    (b)[(i) + 3] = (unsigned char) ( (n)       );       \
} while( 0 )
#endif

/*
 * Key derive function
 */
void KDF( unsigned char *K, size_t klen, const unsigned char *Z, size_t zlen )
{
    uint32_t ct = 1;
    uint8_t i, s;
    uint16_t v = 32;    //since SM3 is used, v is 32 bytes
    size_t m,n;
    impl_sm3_context ctx0,ctx1;
    unsigned char tmp[4], output[32];

    impl_sm3_init( &ctx0 );
    impl_sm3_init( &ctx1 );
    impl_sm3_starts( &ctx0 );
    impl_sm3_update( &ctx0, Z, zlen );
    m = klen % v;
    if (m == 0) {
        n = klen / v;
    } else {
        n = (klen-m) / v + 1;
    }

    for (i = 0; i < n-1; i++) {
        ctx1 = ctx0;
        PUT_UINT32_BE(ct, tmp, 0);
        impl_sm3_update(&(ctx1), tmp, 4);
        impl_sm3_finish(&(ctx1), output);
        for (s = 0; s < 32; s++) {
            K[i*32+s] = output[s];
        }
        ct++;
    }

    ctx1 = ctx0;
    PUT_UINT32_BE( ct, tmp, 0 );
    impl_sm3_update( &(ctx1), tmp, 4 );
    impl_sm3_finish( &(ctx1), output );

    if (m == 0) {
        for (s = 0; s < 32; s++) {
            K[(n-1)*32+s] = output[s];
        }
    } else {
        i = klen - v * (n-1);
        for (s = 0; s < i; s++) {
            K[(n-1)*32+s] = output[s];
        }
    }

    impl_sm3_free( &ctx0 );
    impl_sm3_free( &ctx1 );
}

/*
 * Derive a suitable integer for group grp from a buffer of length len
 * SEC1 4.1.3 step 5 aka SEC1 4.1.4 step 3
 */
static int derive_mpi( const impl_ecp_group *grp, impl_mpi *x,
                       const unsigned char *buf, size_t blen )
{
    int ret;
    size_t n_size = ( grp->nbits + 7 ) / 8;
    size_t use_size = blen > n_size ? n_size : blen;

    HAL_MPI_CHK( impl_mpi_read_binary( x, buf, use_size ) );
    if( use_size * 8 > grp->nbits )
        HAL_MPI_CHK( impl_mpi_shift_r( x, use_size * 8 - grp->nbits ) );

    /* While at it, reduce modulo N */
    if( impl_mpi_cmp_mpi( x, &grp->N ) >= 0 )
        HAL_MPI_CHK( impl_mpi_sub_mpi( x, x, &grp->N ) );

cleanup:
    return( ret );
}

/*
 * Compute SM2_SIGN signature of a hashed message
 */
int impl_sm2_sign( impl_ecp_keypair *context,
                   const unsigned char *src, size_t src_size,
                   uint8_t *sig, size_t *sig_size,
                   int (*f_rng)(void *, unsigned char *, size_t), void *p_rng )
{
    int ret, key_tries, sign_tries;
    impl_ecp_point kg; // kG
    impl_mpi k, e, r, s;
    impl_ecp_group *grp;
    impl_mpi *d;
    size_t rlen, slen;

    grp = &context->grp;
    d = &context->d;

    if( grp->N.p == NULL )
        return( IMPL_ERR_ECP_BAD_INPUT_DATA );

    impl_ecp_point_init( &kg );

    impl_mpi_init( &r );
    impl_mpi_init( &s );
    impl_mpi_init( &k );
    impl_mpi_init( &e );

    sign_tries = 0;
    do {

        /*
         * Step A1(ignored): src is M' = Za || M
         * Step A2: derive e from hashed message
         */
        HAL_MPI_CHK( derive_mpi( grp, &e, src, src_size ) );

        key_tries = 0;
        do {
            /*
             * Step A3: generate rand k
             * Step A4: (x1, y1) = kG
             */
            HAL_MPI_CHK( impl_ecp_gen_keypair( grp, &k, &kg, f_rng, p_rng ) );
            /*
             * Step A5: r = (e + x1) mod n
             */
            HAL_MPI_CHK( impl_mpi_add_mpi( &r, &e, &(kg.X)) );
            HAL_MPI_CHK( impl_mpi_mod_mpi( &r, &r, &grp->N ) );

            if( key_tries++ > 10 ) {
                ret = IMPL_ERR_ECP_RANDOM_FAILED;
                goto cleanup;
            }

            HAL_MPI_CHK( impl_mpi_add_mpi( &e, &r, &k ) );
        // r = 0 or r + k = n
        } while( impl_mpi_cmp_int( &r, 0 ) == 0 || impl_mpi_cmp_mpi( &e, &grp->N ) == 0 );

        /*
         * Step A6: compute s = (1 + d)^(-1) *(k - r * d)  mod n
         */
        HAL_MPI_CHK( impl_mpi_mul_mpi( &s, &r, d ) );
        HAL_MPI_CHK( impl_mpi_sub_mpi( &s, &k, &s ) );
        HAL_MPI_CHK( impl_mpi_add_int( &e, d, 1 ) );
        HAL_MPI_CHK( impl_mpi_inv_mod( &e, &e, &grp->N ) );
        HAL_MPI_CHK( impl_mpi_mul_mpi( &s, &s, &e ) );
        HAL_MPI_CHK( impl_mpi_mod_mpi( &s, &s, &grp->N ) );

        if( sign_tries++ > 10 ) {
            ret = IMPL_ERR_ECP_RANDOM_FAILED;
            goto cleanup;
        }
    } while( impl_mpi_cmp_int( &s, 0 ) == 0 );


    if( *sig_size < 2 * src_size ) {
        ret = IMPL_ERR_ECP_BUFFER_TOO_SMALL;
        *sig_size = 2 * src_size;
        goto cleanup;
    }
    *sig_size = 2 * src_size;
    memset(sig, 0, *sig_size);
    rlen = impl_mpi_size( &r );
    slen = impl_mpi_size( &s );

    HAL_MPI_CHK( impl_mpi_write_binary(&r, sig + *sig_size/2 - rlen, rlen) );
    HAL_MPI_CHK( impl_mpi_write_binary(&s, sig + *sig_size - slen, slen) );

cleanup:
    impl_mpi_free( &r );
    impl_mpi_free( &s );
    impl_mpi_free( &e );
    impl_mpi_free( &k );
    impl_ecp_point_free( &kg );

    return( ret );
}

/*
 * Verify SM2_SIGN signature of hashed message
 */
int impl_sm2_verify( impl_ecp_keypair *context,
                     const uint8_t *src, size_t src_size,
                     const uint8_t *sig, size_t sig_size )
{
    int ret = 0;
    impl_mpi e, t, R;
    impl_mpi r, s;
    impl_ecp_point *P, Q;
    impl_ecp_group *grp;

    P = &context->Q;
    grp = &context->grp;

    if( grp->N.p == NULL )
        return( IMPL_ERR_ECP_BAD_INPUT_DATA );

    impl_mpi_init( &r );
    impl_mpi_init( &s );
    impl_mpi_init( &e );
    impl_mpi_init( &R );
    impl_mpi_init( &t );
    impl_ecp_point_init( &Q );

    HAL_MPI_CHK( impl_mpi_read_binary( &r, sig, src_size) );
    HAL_MPI_CHK( impl_mpi_read_binary( &s, sig + src_size, src_size));

    /*
     * Step B1-B2: make sure r and s are in range [1,n-1]
     */
    if( impl_mpi_cmp_int( &r, 1 ) < 0 || impl_mpi_cmp_mpi( &r, &grp->N ) >= 0 ||
        impl_mpi_cmp_int( &s, 1 ) < 0 || impl_mpi_cmp_mpi( &s, &grp->N ) >= 0 ) {
        ret = IMPL_ERR_ECP_VERIFY_FAILED;
        goto cleanup;
    }

    /*
     * Additional precaution: make sure P is valid
     */
    HAL_MPI_CHK( impl_ecp_check_pubkey( grp, P ) );

    /*
     * Step B3-B4: ignored since src is already H(M)
     * derive MPI from hashed message
     */
    HAL_MPI_CHK( derive_mpi( grp, &e, src, src_size ) );

    /*
     * Step B5: t = (r + s) mod n
     */
    HAL_MPI_CHK( impl_mpi_add_mpi( &t, &r, &s ) );
    HAL_MPI_CHK( impl_mpi_mod_mpi( &t, &t, &grp->N ) );

    if( impl_mpi_cmp_int( &t, 0 ) == 0 ) {
        ret = IMPL_ERR_ECP_VERIFY_FAILED;
        goto cleanup;
    }

    /*
     * Step B6: Q = s*G + t*P
     */
    HAL_MPI_CHK( impl_ecp_muladd( grp, &Q, &s, &grp->G, &t, P ) );
    if( impl_ecp_is_zero( &Q ) ) {
        ret = IMPL_ERR_ECP_VERIFY_FAILED;
        goto cleanup;
    }

    /*
     * Step B7: R = ( e + x ) mod n and check if R is equal to r
     */
    HAL_MPI_CHK( impl_mpi_add_mpi( &R, &e, &Q.X ) );
    HAL_MPI_CHK( impl_mpi_mod_mpi( &R, &R, &grp->N ) );

    if( impl_mpi_cmp_mpi( &R, &r ) != 0 ) {
        ret = IMPL_ERR_ECP_VERIFY_FAILED;
        goto cleanup;
    }

cleanup:
    impl_mpi_free( &r );
    impl_mpi_free( &s );
    impl_mpi_free( &t );
    impl_mpi_free( &R );
    impl_ecp_point_free( &Q );
    impl_mpi_free( &e );
    return( ret );
}

/*
 * Derive pubkey from d
 */
int impl_sm2_derive_p( impl_ecp_keypair *context,
                       unsigned char *dst, size_t *dst_size)
{
    int ret = 0;
    impl_ecp_point kp;

    impl_ecp_point_init( &kp );
    HAL_MPI_CHK( impl_ecp_mul( &context->grp,
                               &kp, &context->d, &(context->grp.G), NULL, NULL ) );

    /* dst = xp || yp */
    HAL_MPI_CHK( impl_mpi_write_binary( &(kp.X), dst, IMPL_SM2_KEY_LEN ));
    HAL_MPI_CHK( impl_mpi_write_binary( &(kp.Y), dst + IMPL_SM2_KEY_LEN, IMPL_SM2_KEY_LEN ));

    impl_ecp_point_free( &kp );
cleanup:
    return ret;
}

/*
 * SM2 encryption
 */
int impl_sm2_encrypt( impl_ecp_keypair *context,
                      const unsigned char *src, size_t src_size,
                      unsigned char *dst, size_t *dst_size,
                      int (*f_rng)(void *, unsigned char *, size_t), void *p_rng )
{
    int ret = 0;
    size_t olen;
    impl_sm3_context ctx;
    // alg related
    uint8_t i;
    uint8_t flag = 0;
    impl_mpi k;
    // tmp = (x2 || y2) t = KDF(x2||y2, klen)
    uint8_t *tmp = NULL, *t = NULL;
    impl_ecp_group *grp;
    impl_ecp_point pb, kp, kg;
    uint8_t *c1, *c2, *c3;
    size_t  c1_size;

    grp = &context->grp;
    pb = context->Q;

    if( grp->N.p == NULL )
        return ( IMPL_ERR_ECP_BAD_INPUT_DATA );

    impl_ecp_point_init( &kp );
    impl_ecp_point_init( &kg );
    impl_mpi_init( &k );

    tmp = ls_osa_calloc(2*IMPL_SM2_KEY_LEN, sizeof(unsigned char));
    if (NULL == tmp) {
        ret = IMPL_ERR_ECP_ALLOC_FAILED;
        goto cleanup;
    }

    t = ls_osa_calloc(src_size, sizeof(unsigned char));
    if (NULL == t) {
        ret = IMPL_ERR_ECP_ALLOC_FAILED;
        goto cleanup;
    }

    // since the length of X,Y coordinates of SM2 points is 32 bytes
    do {
        /*
         * Step A1: generated random k
         * Step A2: c1 = [k]G = (x1, y1)
         */
        HAL_MPI_CHK( impl_ecp_gen_keypair( grp, &k, &kg, f_rng, p_rng ));

        /*
         * Step A3 (skipped): S = [h]Pb
         * skip S=[h]P, since h=1 for given parameters in the SM2 standard
         * ref: https://crypto.stackexchange.com/questions/66145/
         *      why-sm2-ecc-parameters-does-not-specify-cofactor-h
         */

        /*
         * Step A4: kp = [k]Pb = (x2, y2)
         */
        HAL_MPI_CHK( impl_ecp_mul( grp, &kp, &k, &pb, NULL, NULL ) );

        /* tmp = x2 || y2 */
        HAL_MPI_CHK( impl_mpi_write_binary( &(kp.X), tmp, IMPL_SM2_KEY_LEN ));
        HAL_MPI_CHK( impl_mpi_write_binary( &(kp.Y), tmp + IMPL_SM2_KEY_LEN, IMPL_SM2_KEY_LEN ));

        /*
         * Step A5: t = KDF(x2||y2, klen), which tmp = x2||y2
         * if t is full 0, go back to Step A1
         */
        KDF( t, src_size, tmp, IMPL_SM2_KEY_LEN * 2 );
        for (i = 0; i < src_size; i++) {
            if (t[i] != 0) {
                flag = 1;
                break;
            }
        }
    } while (!flag);

    /* short buffer check */
    olen = 2 * impl_mpi_size( &grp->P ) + 1;
    olen = olen + src_size + IMPL_SM2_KEY_LEN;
    if (*dst_size < olen) {
        ret = IMPL_ERR_ECP_BUFFER_TOO_SMALL;
        *dst_size = olen;
        goto cleanup;
    }

    /* write c1 */
    c1 = dst;
    c1_size = *dst_size;
    // NOTE: only support IMPL_ECP_PF_UNCOMPRESSED, DO NOT change method here
    HAL_MPI_CHK( impl_ecp_point_write_binary( grp, &kg, IMPL_ECP_PF_UNCOMPRESSED, &c1_size, c1, c1_size ));

    /*
     * Step A6: c2 = M ^ t
     * C = c1 || c2
     */
    c2 = c1 + c1_size + IMPL_SM3_HASH_LEN;
    for (i = 0; i < src_size; i++) {
        *(c2 + i) = (src[i]) ^ (t[i]);
    }

    c3 = c1 + c1_size;

    /* Step A7: c3 = Hash(x2||M||y2) */
    impl_sm3_init( &ctx );
    impl_sm3_starts( &ctx );
    impl_sm3_update( &ctx, tmp, IMPL_SM2_KEY_LEN );  // x2
    impl_sm3_update( &ctx, src, src_size ); // M
    impl_sm3_update( &ctx, tmp + IMPL_SM2_KEY_LEN, IMPL_SM2_KEY_LEN ); // y2
    impl_sm3_finish( &ctx, c3 );

    /*
     * Step A8: C = c1||c3||c2
     * c2 size: length of M
     * c3 size: sm3 hash length
     */
    *dst_size = c1_size + IMPL_SM3_HASH_LEN + src_size;
cleanup:
    impl_sm3_free( &ctx );
    if (t) ls_osa_free( t );
    if (tmp) ls_osa_free( tmp );
    impl_mpi_free( &k );
    impl_ecp_point_free( &kg );
    impl_ecp_point_free( &kp );
    return ( ret );
}

/* SM2 decryption */
int impl_sm2_decrypt( impl_ecp_keypair *context,
                      const unsigned char *src, size_t clen,
                      unsigned char *dst, size_t *dst_size)
{
    int ret = 0;
    impl_sm3_context ctx;
    // alg related
    uint8_t i;
    impl_ecp_group *grp;
    impl_mpi *d;
    const uint8_t *c1, *m;
    size_t c1_size, klen;
    impl_ecp_point pc1, pc2;
    uint8_t *tmp = NULL, *t = NULL;

    grp = &context->grp;
    d = &context->d;

    impl_ecp_point_init( &pc1 );
    impl_ecp_point_init( &pc2 );

    tmp = ls_osa_calloc(2*IMPL_SM2_KEY_LEN, sizeof(unsigned char));
    if (NULL == tmp) {
        ret = IMPL_ERR_ECP_ALLOC_FAILED;
        goto cleanup;
    }

    /*
     * Step B1: extract point c1
     */

    // only support uncompressed point,
    // so c1_size is fixed to this equation
    c1 = src;
    c1_size = 2*IMPL_SM2_KEY_LEN + 1;
    HAL_MPI_CHK(impl_ecp_point_read_binary(grp, &pc1, c1, c1_size));
    HAL_MPI_CHK( impl_ecp_check_pubkey( grp, &pc1 ) );

    /*
     * Step B2 (skipped): s = [h]c1
     * h=1 for given parameters in the SM2 standard
     * ref: https://crypto.stackexchange.com/questions/66145/
     *      why-sm2-ecc-parameters-does-not-specify-cofactor-h
     */

    /*
     * Step B3: compute (x2,y2) = [d]c1
     */
    HAL_MPI_CHK( impl_ecp_mul( grp, &pc2, d, &pc1, NULL, NULL ) );

    /*
     * Step B4: t = KDF(x2||y2, klen)
     */
    HAL_MPI_CHK( impl_mpi_write_binary( &(pc2.X), tmp, IMPL_SM2_KEY_LEN ));
    HAL_MPI_CHK( impl_mpi_write_binary( &(pc2.Y), tmp + IMPL_SM2_KEY_LEN, IMPL_SM2_KEY_LEN ));

    klen = clen - c1_size - IMPL_SM2_KEY_LEN;  // clen - len(c1) - len(c3)

    if (*dst_size < klen) {
        ret = IMPL_ERR_ECP_BUFFER_TOO_SMALL;
        *dst_size = klen;
        goto cleanup;
    }
    *dst_size = klen;

    t = ls_osa_calloc(klen, sizeof(unsigned char));
    if (NULL == t) {
        ret = IMPL_ERR_ECP_ALLOC_FAILED;
        goto cleanup;
    }
    KDF(t, klen, tmp, IMPL_SM2_KEY_LEN * 2);

    // verify t (should not be all zero)
    for (i = 0; i < klen; i++) {
        if (t[i] != 0) break;
    }

    if (i == klen) {
        ret = IMPL_ERR_ECP_DECRYPT_FAILED;
        goto cleanup;
    }

    /*
     * Step B5: m = c2 ^ t
     * m points to c2
     */
    m = src + c1_size + IMPL_SM3_HASH_LEN;
    for (i = 0; i < klen; i++) {
        dst[i] = (m[i]) ^ (t[i]);
    }

    /*
     * Step B6: u = Hash(x2||M||y2)
     * tmp contains u
     */
    impl_sm3_init( &ctx );
    impl_sm3_starts( &ctx );
    impl_sm3_update( &ctx, tmp, IMPL_SM2_KEY_LEN);  // x2
    impl_sm3_update( &ctx, dst, klen ); // m'
    impl_sm3_update( &ctx, tmp + IMPL_SM2_KEY_LEN, IMPL_SM2_KEY_LEN); // y2
    impl_sm3_finish( &ctx, tmp );

    /*
     * Step B7: check u == c3 ?
     * m points to c3
     */
    //m = m + klen;
    m = src + c1_size;
    // since the output of SM3 is 32 bytes
    for (i = 0; i < IMPL_SM2_KEY_LEN; i++) {
        if (tmp[i] != m[i]) break;
    }

    if (i != IMPL_SM2_KEY_LEN) {
        ret = IMPL_ERR_ECP_DECRYPT_FAILED;
        goto cleanup;
    }

cleanup:
    impl_sm3_free( &ctx );
    if (t) ls_osa_free( t );
    if (tmp) ls_osa_free( tmp );
    impl_ecp_point_free( &pc1 );
    impl_ecp_point_free( &pc2 );
    return ( ret );
}

/*
 * Compute shared secret
 */
int impl_sm2dh_compute_shared( impl_ecp_group *grp,
                               impl_mpi *K,
                               const size_t secret_size,
                               const impl_mpi *ZA,
                               const impl_mpi *ZB,
                               const impl_mpi *dA,
                               const impl_mpi *rA,
                               const impl_ecp_point *RA,
                               const impl_ecp_point *RB,
                               const impl_ecp_point *PB )
{
    int ret;
    uint8_t w, i;
    size_t tmp, len;
    impl_mpi bX, tA;
    impl_ecp_point U;
    unsigned char *buf = NULL, *K0 = NULL;

    impl_mpi_init( &bX );
    impl_mpi_init( &tA );
    impl_ecp_point_init( &U );
    /* compute w=ceil(N/2)-1  */
    tmp = impl_mpi_bitlen(&(grp->N));

    if ((tmp % 2) == 0)
    { w = tmp/2 - 1; }
    else
    { w = (tmp + 1)/2 - 1; }
    //  \bar{x_1}=2^w+(x1 & (2^w-1))
    HAL_MPI_CHK(impl_mpi_lset( &bX, 1));
    HAL_MPI_CHK(impl_mpi_shift_l( &bX, w));
    for(i=0; i< bX.n; i++){
            bX.p[i] = RA->X.p[i];
    }
    HAL_MPI_CHK(impl_mpi_set_bit( &bX, w, 1));

    //  t_A=(d_A+\bar{x_1}\cdot r_A) mod n
    HAL_MPI_CHK(impl_mpi_mul_mpi(&tA, &bX, rA));
    HAL_MPI_CHK(impl_mpi_add_mpi(&tA, &tA, dA));
    HAL_MPI_CHK(impl_mpi_mod_mpi(&tA, &tA, &(grp->N)));

    //  \bar{x_2}=2^w+(x2 & (2^w-1))
    HAL_MPI_CHK(impl_mpi_lset( &bX, 1));
    HAL_MPI_CHK(impl_mpi_shift_l( &bX, w));
    for(i=0; i< bX.n; i++){
            bX.p[i] = RB->X.p[i];
    }
    HAL_MPI_CHK(impl_mpi_set_bit( &bX, w, 1));

   // U=[h\cdot tA](PB+[\bar{x2}]RB)
   HAL_MPI_CHK(impl_mpi_mul_mpi(&bX, &tA, &bX));
   HAL_MPI_CHK(impl_mpi_mod_mpi(&bX, &bX, &(grp->N)));
   HAL_MPI_CHK(impl_ecp_muladd(grp, &U, &tA, PB, &bX, RB));
   if( impl_ecp_is_zero( &U ))
   {
       ret = IMPL_ERR_ECP_DH_FAILED;
       goto cleanup;
   }

   tmp = impl_mpi_size(&U.X);
   len = tmp + impl_mpi_size(&U.Y);
   len += impl_mpi_size(ZA) + impl_mpi_size(ZB);
   buf = ls_osa_calloc(len, sizeof(unsigned char));
   HAL_MPI_CHK(impl_mpi_write_binary( &U.X, buf, tmp ));
   len = tmp;
   tmp = impl_mpi_size(&U.Y);
   HAL_MPI_CHK(impl_mpi_write_binary( &U.Y, buf+len, tmp ));
   len += tmp;
   tmp = impl_mpi_size(ZA);
   HAL_MPI_CHK(impl_mpi_write_binary( ZA, buf+len, tmp ));
   len += tmp;
   tmp = impl_mpi_size(ZB);
   HAL_MPI_CHK(impl_mpi_write_binary( ZB, buf+len, tmp ));

   len += tmp;
   K0  = ls_osa_calloc(secret_size, sizeof(unsigned char));
   KDF(K0, secret_size, buf, len);
   HAL_MPI_CHK(impl_mpi_read_binary( K, K0, secret_size ));

cleanup:
   ls_osa_free( K0 );
   ls_osa_free( buf );
   impl_ecp_point_free( &U );
   impl_mpi_free( &tA );
   impl_mpi_free( &bX );
   return(ret);
}
