/*
 * Copyright (C) 2016-2020 Alibaba Group Holding Limited
 */

#include "ls_hal.h"
#include "ecp.h"

int ls_hal_ecc_get_ctx_size(void)
{
    return sizeof(impl_ecp_keypair);
}

int ls_hal_ecc_init(void *context)
{
    int ret = 0;
    impl_ecp_keypair *ctx;
    if (context == NULL) {
        LS_HAL_LOG("ls_hal_rsa_init failed\n");
        return HAL_CRYPT_BAD_PARAMETERS;
    }

    ctx = (impl_ecp_keypair *) context;
    impl_ecp_keypair_init(ctx);
    return ret;
}

void ls_hal_ecc_cleanup(void *context)
{
    impl_ecp_keypair_free(context);
}

int ls_hal_ecc_init_pubkey(void *context, int grp_id,
                           const uint8_t *x, size_t x_size,
                           const uint8_t *y, size_t y_size)
{
    impl_ecp_point *pt = NULL;
    impl_ecp_keypair *ctx = NULL;
    int ret = 0;

    if (context == NULL) {
        LS_HAL_LOG("invalid ctx\n");
        return HAL_CRYPT_INVALID_CONTEXT;
    }

    ctx = (impl_ecp_keypair *)context;
    pt = &ctx->Q;

    // init ecp group
    impl_ecp_group_init(&ctx->grp);
    HAL_MPI_CHK(impl_ecp_group_load(&ctx->grp, grp_id));
    // init public
    impl_ecp_point_init( pt );
    HAL_MPI_CHK(impl_mpi_read_binary(&pt->X, x, x_size));
    HAL_MPI_CHK(impl_mpi_read_binary(&pt->Y, y, y_size));
    HAL_MPI_CHK(impl_mpi_lset(&pt->Z, 1));
    // init secret
    ctx->d.p = NULL;

cleanup:
    if (ret) {
        LS_HAL_LOG("failed(0x%08x)\n", ret);
        return HAL_CRYPT_ERROR;
    }
    return ret;
}

int ls_hal_ecc_init_keypair(void *context, int grp_id,
                            const uint8_t *x, size_t x_size,
                            const uint8_t *y, size_t y_size,
                            const uint8_t *d, size_t d_size)
{
    impl_ecp_keypair *ctx = NULL;
    impl_ecp_point *pt = NULL;
    impl_mpi *secret = NULL;
    int ret = 0;

    if (context == NULL) {
        LS_HAL_LOG("invalid ctx\n");
        return HAL_CRYPT_INVALID_CONTEXT;
    }

    ctx = (impl_ecp_keypair *)context;
    pt = &ctx->Q;
    secret = &ctx->d;

    // init ecp group
    impl_ecp_group_init(&ctx->grp);
    HAL_MPI_CHK(impl_ecp_group_load(&ctx->grp, grp_id));
    // int public
    impl_ecp_point_init( pt );
    HAL_MPI_CHK(impl_mpi_read_binary(&pt->X, x, x_size));
    HAL_MPI_CHK(impl_mpi_read_binary(&pt->Y, y, y_size));
    HAL_MPI_CHK(impl_mpi_lset(&pt->Z, 1));
    // int private
    HAL_MPI_CHK(impl_mpi_read_binary(secret, d, d_size));

cleanup:
    if (ret) {
        LS_HAL_LOG("failed(0x%08x)\n", ret);
        return HAL_CRYPT_ERROR;
    }
    return ret;
}

int ls_hal_ecc_gen_keypair(void *context,
                           int grp_id,
                           int (*f_rng)(void *, uint8_t *, size_t),
                           void *p_rng,
                           hal_ecc_keypair_t *kp)
{
    int ret = 0;
    impl_ecp_keypair *ctx;

    if (context == NULL) {
        LS_HAL_LOG("invalid context\n");
        return HAL_CRYPT_INVALID_CONTEXT;
    }

    if (kp == NULL) {
        LS_HAL_LOG("invalid keypair\n");
        return HAL_CRYPT_INVALID_ARG;
    }

    ctx = (impl_ecp_keypair *) context;
    ret = impl_ecp_gen_key(grp_id, ctx, f_rng, p_rng);
    if (ret) {
        LS_HAL_LOG("failed(0x%08x)\n", ret);
        return HAL_CRYPT_ERROR;
    }

    // convert ctx to keypair
    kp->x_size = impl_mpi_size(&(ctx->Q.X));
    kp->x = (uint8_t *)ls_osa_malloc(kp->x_size);
    if (!kp->x) {
        LS_HAL_LOG("malloc %ld failed\n", kp->x_size);
        ret = HAL_CRYPT_OUTOFMEM;
        goto cleanup;
    }
    HAL_MPI_CHK( impl_mpi_write_binary(&(ctx->Q.X), kp->x, kp->x_size));

    kp->y_size = impl_mpi_size(&(ctx->Q.Y));
    kp->y = (uint8_t *)ls_osa_malloc(kp->y_size);
    if (!kp->y) {
        LS_HAL_LOG("malloc %ld failed\n", kp->y_size);
        ret = HAL_CRYPT_OUTOFMEM;
        goto cleanup;
    }
    HAL_MPI_CHK( impl_mpi_write_binary(&(ctx->Q.Y), kp->y, kp->y_size));

    kp->d_size = impl_mpi_size(&(ctx->d));
    kp->d = (uint8_t *)ls_osa_malloc(kp->d_size);
    if (!kp->d) {
        LS_HAL_LOG("malloc %ld failed\n", kp->d_size);
        ret = HAL_CRYPT_OUTOFMEM;
        goto cleanup;
    }
    HAL_MPI_CHK( impl_mpi_write_binary(&(ctx->d), kp->d, kp->d_size));

cleanup:
    if (ret) {
        if (kp->x) {
            ls_osa_free(kp->x);
        }
        if (kp->y) {
            ls_osa_free(kp->y);
        }
        if (kp->d) {
            ls_osa_free(kp->d);
        }
    }
    return ret;
}
