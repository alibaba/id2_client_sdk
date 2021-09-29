/*
 * Copyright (C) 2016-2019 Alibaba Group Holding Limited
 */

#include "ls_hal.h"
#include "rsa.h"

int ls_hal_rsa_get_ctx_size(void)
{
    return sizeof(impl_rsa_context);
}

int ls_hal_rsa_init(const void *context)
{
    int result = 0;
    impl_rsa_context *ctx;
    if (context == NULL) {
        LS_HAL_LOG("ls_hal_rsa_init failed\n");
        return HAL_CRYPT_BAD_PARAMETERS;
    }
    ctx = (impl_rsa_context *) context;
    impl_rsa_init(ctx, 0, 0);
    return result;
}

void ls_hal_rsa_cleanup(const void *context)
{
    impl_rsa_free((impl_rsa_context *)context);
}

int ls_hal_rsa_init_pubkey(void *context, size_t keybits,
                           const uint8_t *n, size_t n_size,
                           const uint8_t *e, size_t e_size)
{
    impl_rsa_context *ctx;
    int ret = 0;

    if (context == NULL) {
        LS_HAL_LOG("invalid ctx\n");
        return HAL_CRYPT_INVALID_CONTEXT;
    }

    ctx = (impl_rsa_context *)context;
    ctx->len = keybits >> 3;

    // init n/e
    HAL_MPI_CHK(impl_mpi_read_binary(&(ctx->N), n, n_size));
    HAL_MPI_CHK(impl_mpi_read_binary(&(ctx->E), e, e_size));

cleanup:
    if (ret) {
        LS_HAL_LOG("failed(0x%08x)\n", ret);
        return HAL_CRYPT_ERROR;
    }
    return ret;
}

int ls_hal_rsa_init_keypair(void *context, size_t keybits,
                            const uint8_t *n, size_t n_size,
                            const uint8_t *e, size_t e_size,
                            const uint8_t *d, size_t d_size,
                            const uint8_t *p, size_t p_size,
                            const uint8_t *q, size_t q_size,
                            const uint8_t *dp, size_t dp_size,
                            const uint8_t *dq, size_t dq_size,
                            const uint8_t *qp, size_t qp_size)
{
    impl_rsa_context *ctx;
    int ret = 0;

    if (context == NULL) {
        LS_HAL_LOG("invalid ctx\n");
        return HAL_CRYPT_INVALID_CONTEXT;
    }

    ctx = (impl_rsa_context *)context;
    ctx->len = keybits >> 3;
    HAL_MPI_CHK(impl_mpi_read_binary(&(ctx->N),  n,  n_size));
    HAL_MPI_CHK(impl_mpi_read_binary(&(ctx->D),  d,  d_size));

    if (p_size && q_size && dp_size && dq_size && qp_size) {
        HAL_MPI_CHK(impl_mpi_read_binary(&(ctx->P),  p,  p_size));
        HAL_MPI_CHK(impl_mpi_read_binary(&(ctx->Q),  q,  q_size));
        HAL_MPI_CHK(impl_mpi_read_binary(&(ctx->DP), dp, dp_size));
        HAL_MPI_CHK(impl_mpi_read_binary(&(ctx->DQ), dq, dq_size));
        HAL_MPI_CHK(impl_mpi_read_binary(&(ctx->QP), qp, qp_size));
    }

cleanup:
    if (ret) {
        LS_HAL_LOG("failed(0x%08x)\n", ret);
        return HAL_CRYPT_ERROR;
    }
    return ret;
}

int ls_hal_rsa_public(const void *context,
                      const uint8_t *src, uint8_t *dst,
                      size_t size)
{
    int ret = 0;
    impl_rsa_context *ctx;
      
    if (context == NULL) {
        LS_HAL_LOG("invalid ctx\n");
        return HAL_CRYPT_INVALID_CONTEXT;
    }

    ctx = (impl_rsa_context *)context;

    ret = impl_rsa_public(ctx, src, dst);
    if (ret) {
        LS_HAL_LOG("failed(0x%08x)\n", ret);
        return HAL_CRYPT_ERROR;
    }

    return HAL_CRYPT_SUCCESS;
}

int ls_hal_rsa_private(const void *context,
           int (*f_rng)(void *, uint8_t *, size_t),
           const uint8_t *src, uint8_t *dst, size_t size)
{
    int ret = 0;
    impl_rsa_context *ctx;

    if (context == NULL) {
        LS_HAL_LOG("invalid context\n");
        return HAL_CRYPT_INVALID_CONTEXT;
    }

    ctx = (impl_rsa_context *) context;
    ret = impl_rsa_private(ctx, f_rng, NULL, src, dst);
    if (ret) {
        LS_HAL_LOG("failed(%d)\n", ret);
        return HAL_CRYPT_ERROR;
    }

    return HAL_CRYPT_SUCCESS;
}

int ls_hal_rsa_gen_keypair(const void *context,
        int (*f_rng)(void *, uint8_t *, size_t),
        void *p_rng,
        unsigned int nbits, int exponent,
        void *keypair)
{
    int ret = HAL_CRYPT_SUCCESS;
    impl_rsa_context *ctx;
    hal_rsa_keypair_t *kp;

    if (context == NULL) {
        LS_HAL_LOG("invalid context\n");
        return HAL_CRYPT_INVALID_CONTEXT;
    }

    if (keypair == NULL) {
        LS_HAL_LOG("invalid keypair\n");
        return HAL_CRYPT_INVALID_ARG;
    }
    kp = (hal_rsa_keypair_t *)keypair;

    ctx = (impl_rsa_context *) context;
    ret = impl_rsa_gen_key(ctx, f_rng, p_rng, nbits, exponent);
    if (ret) {
        LS_HAL_LOG("failed(0x%08x)\n", ret);
        return HAL_CRYPT_ERROR;
    }
    // update key_bytes
    kp->key_bytes = nbits >> 3;

    // alloc n/e/d/p/q/dp/dq/qp for keypair

    // convert ctx to keypair contents
    // TODO: add check
    kp->n_size = impl_mpi_size(&(ctx->N));
    kp->n = (uint8_t *)ls_osa_malloc(kp->n_size);
    HAL_MPI_CHK( impl_mpi_write_binary( &(ctx->N), kp->n, kp->n_size ) );

    kp->e_size = impl_mpi_size(&(ctx->E));
    kp->e = (uint8_t *)ls_osa_malloc(kp->e_size);
    HAL_MPI_CHK( impl_mpi_write_binary( &(ctx->E), kp->e, kp->e_size ) );

    kp->d_size = impl_mpi_size(&(ctx->D));
    kp->d = (uint8_t *)ls_osa_malloc(kp->d_size);
    HAL_MPI_CHK( impl_mpi_write_binary( &(ctx->D), kp->d, kp->d_size ) );

    kp->p_size = impl_mpi_size(&(ctx->P));
    kp->p = (uint8_t *)ls_osa_malloc(kp->p_size);
    HAL_MPI_CHK( impl_mpi_write_binary( &(ctx->P), kp->p, kp->p_size ) );

    kp->q_size = impl_mpi_size(&(ctx->Q));
    kp->q = (uint8_t *)ls_osa_malloc(kp->q_size);
    HAL_MPI_CHK( impl_mpi_write_binary( &(ctx->Q), kp->q, kp->q_size ) );

    kp->dp_size = impl_mpi_size(&(ctx->DP));
    kp->dp = (uint8_t *)ls_osa_malloc(kp->dp_size);
    HAL_MPI_CHK( impl_mpi_write_binary( &(ctx->DP), kp->dp, kp->dp_size ) );

    kp->dq_size = impl_mpi_size(&(ctx->DQ));
    kp->dq = (uint8_t *)ls_osa_malloc(kp->dq_size);
    HAL_MPI_CHK( impl_mpi_write_binary( &(ctx->DQ), kp->dq, kp->dq_size ) );

    kp->qp_size = impl_mpi_size(&(ctx->QP));
    kp->qp = (uint8_t *)ls_osa_malloc(kp->qp_size);
    HAL_MPI_CHK( impl_mpi_write_binary( &(ctx->QP), kp->qp, kp->qp_size ) );

cleanup:
    return ret;
}
