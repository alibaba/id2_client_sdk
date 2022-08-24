/**
* Copyright (C) 2017-2020 Alibaba Group Holding Limited.
**/

#include "rsa.h"
#include "config.h"

/*
 * Initialize an RSA context
 */
void impl_rsa_init( impl_rsa_context *ctx,
               int padding,
               int hash_id )
{
    memset( ctx, 0, sizeof( impl_rsa_context ) );

    impl_rsa_set_padding( ctx, padding, hash_id );

#if defined(CONFIG_MULTH_SUPPORT)
    ls_osa_mutex_init( &ctx->mutex );
#endif
}

/*
 * Set padding for an existing RSA context
 */
void impl_rsa_set_padding( impl_rsa_context *ctx, int padding, int hash_id )
{
    ctx->padding = padding;
    ctx->hash_id = hash_id;
}

/*
 * Generate an RSA keypair
 */
int impl_rsa_gen_key( impl_rsa_context *ctx,
                 int (*f_rng)(void *, unsigned char *, size_t),
                 void *p_rng,
                 unsigned int nbits, int exponent )
{
    int ret;
    impl_mpi P1, Q1, H, G;

    if( f_rng == NULL || nbits < 128 || exponent < 3 )
        return( HAL_ERR_RSA_BAD_INPUT_DATA );

    if( nbits % 2 )
        return( HAL_ERR_RSA_BAD_INPUT_DATA );

    impl_mpi_init( &P1 ); impl_mpi_init( &Q1 );
    impl_mpi_init( &H ); impl_mpi_init( &G );

    /*
     * find primes P and Q with Q < P so that:
     * GCD( E, (P-1)*(Q-1) ) == 1
     */
    HAL_MPI_CHK( impl_mpi_lset( &ctx->E, exponent ) );

    do
    {
        HAL_MPI_CHK( impl_mpi_gen_prime( &ctx->P, nbits >> 1, 0,
                                f_rng, p_rng ) );

        HAL_MPI_CHK( impl_mpi_gen_prime( &ctx->Q, nbits >> 1, 0,
                                f_rng, p_rng ) );

        if( impl_mpi_cmp_mpi( &ctx->P, &ctx->Q ) == 0 )
            continue;

        HAL_MPI_CHK( impl_mpi_mul_mpi( &ctx->N, &ctx->P, &ctx->Q ) );
        if( impl_mpi_bitlen( &ctx->N ) != nbits )
            continue;

        if( impl_mpi_cmp_mpi( &ctx->P, &ctx->Q ) < 0 )
                                impl_mpi_swap( &ctx->P, &ctx->Q );

        HAL_MPI_CHK( impl_mpi_sub_int( &P1, &ctx->P, 1 ) );
        HAL_MPI_CHK( impl_mpi_sub_int( &Q1, &ctx->Q, 1 ) );
        HAL_MPI_CHK( impl_mpi_mul_mpi( &H, &P1, &Q1 ) );
        HAL_MPI_CHK( impl_mpi_gcd( &G, &ctx->E, &H  ) );
    }
    while( impl_mpi_cmp_int( &G, 1 ) != 0 );

    /*
     * D  = E^-1 mod ((P-1)*(Q-1))
     * DP = D mod (P - 1)
     * DQ = D mod (Q - 1)
     * QP = Q^-1 mod P
     */
    HAL_MPI_CHK( impl_mpi_inv_mod( &ctx->D , &ctx->E, &H  ) );
    HAL_MPI_CHK( impl_mpi_mod_mpi( &ctx->DP, &ctx->D, &P1 ) );
    HAL_MPI_CHK( impl_mpi_mod_mpi( &ctx->DQ, &ctx->D, &Q1 ) );
    HAL_MPI_CHK( impl_mpi_inv_mod( &ctx->QP, &ctx->Q, &ctx->P ) );

    ctx->len = ( impl_mpi_bitlen( &ctx->N ) + 7 ) >> 3;

cleanup:

    impl_mpi_free( &P1 ); impl_mpi_free( &Q1 ); impl_mpi_free( &H ); impl_mpi_free( &G );

    if( ret != 0 )
    {
        //impl_rsa_free( ctx );
        return( HAL_ERR_RSA_KEY_GEN_FAILED + ret );
    }

    return( 0 );
}

/*
 * Do an RSA public key operation
 */
int impl_rsa_public( impl_rsa_context *ctx,
                const unsigned char *input,
                unsigned char *output )
{
    int ret;
    size_t olen;
    impl_mpi T;

    impl_mpi_init( &T );

#if defined(CONFIG_MULTH_SUPPORT)
    if( ( ret = ls_osa_mutex_lock( &ctx->mutex ) ) != 0 )
        return( ret );
#endif

    HAL_MPI_CHK( impl_mpi_read_binary( &T, input, ctx->len ) );

    if( impl_mpi_cmp_mpi( &T, &ctx->N ) >= 0 )
    {
        ret = HAL_ERR_MPI_BAD_INPUT_DATA;
        goto cleanup;
    }

    olen = ctx->len;
    HAL_MPI_CHK( impl_mpi_exp_mod( &T, &T, &ctx->E, &ctx->N, &ctx->RN ) );
    HAL_MPI_CHK( impl_mpi_write_binary( &T, output, olen ) );

cleanup:
#if defined(CONFIG_MULTH_SUPPORT)
    if( ls_osa_mutex_unlock( &ctx->mutex ) != 0 )
        return( HAL_ERR_THREADING_MUTEX_ERROR );
#endif

    impl_mpi_free( &T );

    if( ret != 0 )
        return( HAL_ERR_RSA_PUBLIC_FAILED + ret );

    return( 0 );
}

#ifdef CONFIG_ENABLE_BLINDING
/*
 * Generate or update blinding values, see section 10 of:
 *  KOCHER, Paul C. Timing attacks on implementations of Diffie-Hellman, RSA,
 *  DSS, and other systems. In : Advances in Cryptology-CRYPTO'96. Springer
 *  Berlin Heidelberg, 1996. p. 104-113.
 */
static int rsa_prepare_blinding( impl_rsa_context *ctx,
                 int (*f_rng)(void *, unsigned char *, size_t), void *p_rng )
{
    int ret, count = 0;

    if( ctx->Vf.p != NULL )
    {
        /* We already have blinding values, just update them by squaring */
        HAL_MPI_CHK( impl_mpi_mul_mpi( &ctx->Vi, &ctx->Vi, &ctx->Vi ) );
        HAL_MPI_CHK( impl_mpi_mod_mpi( &ctx->Vi, &ctx->Vi, &ctx->N ) );
        HAL_MPI_CHK( impl_mpi_mul_mpi( &ctx->Vf, &ctx->Vf, &ctx->Vf ) );
        HAL_MPI_CHK( impl_mpi_mod_mpi( &ctx->Vf, &ctx->Vf, &ctx->N ) );

        goto cleanup;
    }

    /* Unblinding value: Vf = random number, invertible mod N */
    do {
        if( count++ > 10 )
            return( HAL_ERR_RSA_RNG_FAILED );

        HAL_MPI_CHK( impl_mpi_fill_random( &ctx->Vf, ctx->len - 1, f_rng, p_rng ) );
        HAL_MPI_CHK( impl_mpi_gcd( &ctx->Vi, &ctx->Vf, &ctx->N ) );
    } while( impl_mpi_cmp_int( &ctx->Vi, 1 ) != 0 );

    /* Blinding value: Vi =  Vf^(-e) mod N */
    HAL_MPI_CHK( impl_mpi_inv_mod( &ctx->Vi, &ctx->Vf, &ctx->N ) );
    HAL_MPI_CHK( impl_mpi_exp_mod( &ctx->Vi, &ctx->Vi, &ctx->E, &ctx->N, &ctx->RN ) );


cleanup:
    return( ret );
}
#endif

/*
 * Do an RSA private key operation
 */

int impl_rsa_private( impl_rsa_context *ctx,
                 int (*f_rng)(void *, unsigned char *, size_t),
                 void *p_rng,
                 const unsigned char *input,
                 unsigned char *output )
{
    int ret;
    size_t olen;
    impl_mpi T, T1, T2;

    /* BUG FIX: p q can be NULL for private decryption */
    /* Make sure we have private key info, prevent possible misuse */
    /*
    if( ctx->P.p == NULL || ctx->Q.p == NULL || ctx->D.p == NULL ) {
        return( HAL_ERR_RSA_BAD_INPUT_DATA );
    }*/

    impl_mpi_init( &T ); impl_mpi_init( &T1 ); impl_mpi_init( &T2 );

#if defined(CONFIG_MULTH_SUPPORT)
    if( ( ret = ls_osa_mutex_lock( &ctx->mutex ) ) != 0 )
        return( ret );
#endif

    HAL_MPI_CHK( impl_mpi_read_binary( &T, input, ctx->len ) );
    if( impl_mpi_cmp_mpi( &T, &ctx->N ) >= 0 )
    {
        ret = HAL_ERR_MPI_BAD_INPUT_DATA;
        goto cleanup;
    }

#ifdef CONFIG_ENABLE_BLINDING
    if( f_rng != NULL )
    {
        /*
         * Blinding
         * T = T * Vi mod N
         */
        HAL_MPI_CHK( rsa_prepare_blinding( ctx, f_rng, p_rng ) );
        HAL_MPI_CHK( impl_mpi_mul_mpi( &T, &T, &ctx->Vi ) );
        HAL_MPI_CHK( impl_mpi_mod_mpi( &T, &T, &ctx->N ) );
    }
#endif

    if ((ctx->P.n) &&
        (ctx->Q.n) &&
        (ctx->DP.n) &&
        (ctx->DQ.n) &&
        (ctx->QP.n)) {

        /*
         * faster decryption using the CRT
         *
         * T1 = input ^ dP mod P
         * T2 = input ^ dQ mod Q
         */
        HAL_MPI_CHK( impl_mpi_exp_mod( &T1, &T, &ctx->DP, &ctx->P, &ctx->RP ) );
        HAL_MPI_CHK( impl_mpi_exp_mod( &T2, &T, &ctx->DQ, &ctx->Q, &ctx->RQ ) );
        /*
         * T = (T1 - T2) * (Q^-1 mod P) mod P
         */
        HAL_MPI_CHK( impl_mpi_sub_mpi( &T, &T1, &T2 ) );
        HAL_MPI_CHK( impl_mpi_mul_mpi( &T1, &T, &ctx->QP ) );
        HAL_MPI_CHK( impl_mpi_mod_mpi( &T, &T1, &ctx->P ) );

        /*
         * T = T2 + T * Q
         */
        HAL_MPI_CHK( impl_mpi_mul_mpi( &T1, &T, &ctx->Q ) );
        HAL_MPI_CHK( impl_mpi_add_mpi( &T, &T2, &T1 ) );

    } else {
        HAL_MPI_CHK( impl_mpi_exp_mod( &T, &T, &ctx->D, &ctx->N, &ctx->RN ) );
    }

#ifdef CONFIG_ENABLE_BLINDING
    if( f_rng != NULL )
    {
        /*
         * Unblind
         * T = T * Vf mod N
         */
        HAL_MPI_CHK( impl_mpi_mul_mpi( &T, &T, &ctx->Vf ) );
        HAL_MPI_CHK( impl_mpi_mod_mpi( &T, &T, &ctx->N ) );
    }
#endif

    olen = ctx->len;
    HAL_MPI_CHK( impl_mpi_write_binary( &T, output, olen ) );

cleanup:
#if defined(CONFIG_MULTH_SUPPORT)
    if( ls_osa_mutex_unlock( &ctx->mutex ) != 0 )
        return( HAL_ERR_THREADING_MUTEX_ERROR );
#endif

    impl_mpi_free( &T ); impl_mpi_free( &T1 ); impl_mpi_free( &T2 );

    if( ret != 0 )
        return( HAL_ERR_RSA_PRIVATE_FAILED + ret );

    return( 0 );
}

/*
 * Free the components of an RSA key
 */
void impl_rsa_free( impl_rsa_context *ctx )
{
    impl_mpi_free( &ctx->Vi ); impl_mpi_free( &ctx->Vf );
    impl_mpi_free( &ctx->RQ ); impl_mpi_free( &ctx->RP ); impl_mpi_free( &ctx->RN );
    impl_mpi_free( &ctx->QP ); impl_mpi_free( &ctx->DQ ); impl_mpi_free( &ctx->DP );
    impl_mpi_free( &ctx->Q  ); impl_mpi_free( &ctx->P  ); impl_mpi_free( &ctx->D );
    impl_mpi_free( &ctx->E  ); impl_mpi_free( &ctx->N  );

#if defined(CONFIG_MULTH_SUPPORT)
    impl_mutex_free( &ctx->mutex );
#endif
}

