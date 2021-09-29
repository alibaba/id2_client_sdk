/*
 * Copyright (C) 2016-2020 Alibaba Group Holding Limited
 */

#include "ls_hal.h"
#include "ecp.h"
#include "sm2.h"
#include "sm3.h"

static int myrand(void *rng_state, unsigned char *output, size_t len)
{
    int ret = 0;
    long long time_ms = ls_osa_get_time_ms();

    ret = ls_hal_set_seed((uint8_t *)&time_ms, sizeof(long long));
    if (ret != HAL_CRYPT_SUCCESS) {
        LS_HAL_LOG("set seed failed(0x%08x)\n", ret);
        return ret;
    }

    ret = ls_hal_get_random(output, len);
    if (ret != HAL_CRYPT_SUCCESS) {
        LS_HAL_LOG("gen rand failed(%08x)\n", ret);
        return ret;
    }
    return ret;
}

int ls_hal_sm2_msg_digest(void *context,
                          int type,
                          const uint8_t *id, size_t id_size,
                          const uint8_t *msg, size_t msg_size,
                          uint8_t *dsg, size_t *dsg_size)
{
    int ret = 0;
    impl_ecp_keypair *ctx;
    uint8_t entla[2] = { 0 };
    impl_sm3_context hash_ctx;
    uint8_t *m = NULL; // m = zA || msg
    size_t m_size;
    uint8_t *e = NULL; // e = H256(m)
    size_t hash_size;
    uint8_t *tmp = NULL; // conver mpi to byte for hash update
    size_t tmp_size;

    if (type == HAL_TYPE_SM3) {
        hash_size = HAL_SM3_HASH_SIZE;
        m_size = hash_size + msg_size;
    } else {
        LS_HAL_LOG("Only support type is SM3\n");
        return HAL_CRYPT_BAD_PARAMETERS;
    }

    if (*dsg_size < hash_size) {
        *dsg_size = hash_size;
        return HAL_CRYPT_SHORT_BUFFER;
    }
    *dsg_size = hash_size;

    if (context == NULL) {
        LS_HAL_LOG("invalid context\n");
        return HAL_CRYPT_INVALID_CONTEXT;
    }
    ctx = (impl_ecp_keypair *)context;

    m = (uint8_t *)ls_osa_malloc(m_size);
    if (NULL == m) {
        LS_HAL_LOG("malloc %ld failed\n", m_size);
        goto cleanup;
    }

    e = (uint8_t *)ls_osa_malloc(hash_size);
    if (NULL == e) {
        LS_HAL_LOG("malloc %ld failed\n", hash_size);
        goto cleanup;
    }

    tmp = (uint8_t *)ls_osa_malloc(IMPL_SM2_KEY_LEN * 2);
    if (NULL == tmp) {
        LS_HAL_LOG("malloc %d failed\n", IMPL_SM2_KEY_LEN * 2);
        goto cleanup;
    }

    // update ENTLa
    entla[0] = ((id_size << 3) & 0xFF00) >> 3;
    entla[1] = (id_size << 3) & 0xFF;

    // Za = ENTLa||IDa||a||b||xG||yG||xA||yA
    impl_sm3_init(&hash_ctx);
    impl_sm3_starts(&hash_ctx);
    // ENTLa
    impl_sm3_update(&hash_ctx, entla, 2);
    // IDa
    impl_sm3_update(&hash_ctx, id, id_size);
    // a
    tmp_size = impl_mpi_size(&(ctx->grp.A));
    if (tmp_size > IMPL_SM2_KEY_LEN) {
        LS_HAL_LOG("invalid size(%ld)\n", tmp_size);
        ret = HAL_CRYPT_ERROR;
        goto cleanup;
    }
    HAL_MPI_CHK(impl_mpi_write_binary(&(ctx->grp.A), tmp, tmp_size));
    impl_sm3_update(&hash_ctx, tmp, tmp_size);
    // b
    tmp_size = impl_mpi_size(&(ctx->grp.B));
    if (tmp_size > IMPL_SM2_KEY_LEN) {
        LS_HAL_LOG("invalid size(%ld)\n", tmp_size);
        ret = HAL_CRYPT_ERROR;
        goto cleanup;
    }
    HAL_MPI_CHK(impl_mpi_write_binary(&(ctx->grp.B), tmp, tmp_size));
    impl_sm3_update(&hash_ctx, tmp, tmp_size);

    // xG
    tmp_size = impl_mpi_size(&(ctx->grp.G.X));
    if (tmp_size > IMPL_SM2_KEY_LEN) {
        LS_HAL_LOG("invalid size(%ld)\n", tmp_size);
        ret = HAL_CRYPT_ERROR;
        goto cleanup;
    }
    HAL_MPI_CHK(impl_mpi_write_binary(&(ctx->grp.G.X), tmp, tmp_size));
    impl_sm3_update(&hash_ctx, tmp, tmp_size);

    // yG
    tmp_size = impl_mpi_size(&(ctx->grp.G.Y));
    if (tmp_size > IMPL_SM2_KEY_LEN) {
        LS_HAL_LOG("invalid size(%ld)\n", tmp_size);
        ret = HAL_CRYPT_ERROR;
        goto cleanup;
    }
    HAL_MPI_CHK(impl_mpi_write_binary(&(ctx->grp.G.Y), tmp, tmp_size));
    impl_sm3_update(&hash_ctx, tmp, tmp_size);

    if (ctx->d.p) {
        // ctx has priv key, use d to derive Q
        tmp_size = IMPL_SM2_KEY_LEN * 2;
        impl_sm2_derive_p(ctx, tmp, &tmp_size);
        impl_sm3_update(&hash_ctx, tmp, tmp_size);
    } else {
        // ctx has only pubkey
        // xA
        tmp_size = impl_mpi_size(&(ctx->Q.X));
        if (tmp_size > IMPL_SM2_KEY_LEN) {
            LS_HAL_LOG("invalid size(%ld)\n", tmp_size);
            ret = HAL_CRYPT_ERROR;
            goto cleanup;
        }
        HAL_MPI_CHK(impl_mpi_write_binary(&(ctx->Q.X), tmp, tmp_size));
        impl_sm3_update(&hash_ctx, tmp, tmp_size);

        // yA
        tmp_size = impl_mpi_size(&(ctx->Q.Y));
        if (tmp_size > IMPL_SM2_KEY_LEN) {
            LS_HAL_LOG("invalid size(%ld)\n", tmp_size);
            ret = HAL_CRYPT_ERROR;
            goto cleanup;
        }
        HAL_MPI_CHK(impl_mpi_write_binary(&(ctx->Q.Y), tmp, tmp_size));
        impl_sm3_update(&hash_ctx, tmp, tmp_size);
    }

    // calc M
    impl_sm3_finish(&hash_ctx, m);
    // M' = Za || M
    memcpy(m + hash_size, msg, msg_size);
    // e = H256(M')
    impl_sm3_starts(&hash_ctx);
    impl_sm3_update(&hash_ctx, m, m_size);
    impl_sm3_finish(&hash_ctx, dsg);

cleanup:
    if (m) {
        ls_osa_free(m);
    }

    if (e) {
        ls_osa_free(e);
    }

    if (tmp) {
        ls_osa_free(tmp);
    }

    return ret;
}

int ls_hal_sm2_encrypt(void *context,
                       const uint8_t *src, size_t src_size,
                       uint8_t *dst, size_t *dst_size)
{
    int ret = 0;
    impl_ecp_keypair *ctx;

    if (context == NULL) {
        LS_HAL_LOG("invalid context\n");
        return HAL_CRYPT_INVALID_CONTEXT;
    }
    ctx = (impl_ecp_keypair *)context;

    ret = impl_sm2_encrypt(ctx,
                           src, src_size,
                           dst, dst_size,
                           myrand, NULL);
    if (ret == IMPL_ERR_ECP_BUFFER_TOO_SMALL) {
        return HAL_CRYPT_SHORT_BUFFER;
    }

    if (ret) {
        LS_HAL_LOG("failed(0x%08x)\n", ret);
        return HAL_CRYPT_ERROR;
    }

    return HAL_CRYPT_SUCCESS;
}

int ls_hal_sm2_decrypt(void *context,
                       const uint8_t *src, size_t src_size,
                       uint8_t *dst, size_t *dst_size)
{
    int ret = 0;
    impl_ecp_keypair *ctx;

    if (context == NULL) {
        LS_HAL_LOG("invalid context\n");
        return HAL_CRYPT_INVALID_CONTEXT;
    }

    ctx = (impl_ecp_keypair *)context;
    ret = impl_sm2_decrypt(ctx,
                           src, src_size,
                           dst, dst_size);
    if (ret == IMPL_ERR_ECP_BUFFER_TOO_SMALL) {
        return HAL_CRYPT_SHORT_BUFFER;
    }

    if (ret) {
        LS_HAL_LOG("failed(0x%08x)\n", ret);
        return HAL_CRYPT_ERROR;
    }

    return HAL_CRYPT_SUCCESS;
}

int ls_hal_sm2_sign(void *context,
                    const uint8_t *src, size_t src_size,
                    uint8_t *sig, size_t *sig_size)
{
    int ret = 0;
    impl_ecp_keypair *ctx;

    if (context == NULL) {
        LS_HAL_LOG("invalid context\n");
        return HAL_CRYPT_INVALID_CONTEXT;
    }

    ctx = (impl_ecp_keypair *)context;
    ret = impl_sm2_sign(ctx,
                        src, src_size,
                        sig, sig_size,
                        myrand, NULL);
    if (ret == IMPL_ERR_ECP_BUFFER_TOO_SMALL) {
        return HAL_CRYPT_SHORT_BUFFER;
    }

    if (ret) {
        LS_HAL_LOG("failed(%d)\n", ret);
        goto cleanup;
    }

cleanup:
    return ret;
}

int ls_hal_sm2_verify(void *context,
                      const uint8_t *src, size_t src_size,
                      const uint8_t *sig, size_t sig_size)
{
    int ret = 0;
    impl_ecp_keypair *ctx;

    if (context == NULL) {
        LS_HAL_LOG("invalid context\n");
        return HAL_CRYPT_INVALID_CONTEXT;
    }
    ctx = (impl_ecp_keypair *)context;

    ret = impl_sm2_verify(ctx,
                          src, src_size,
                          sig, sig_size);

    if (IMPL_ERR_ECP_VERIFY_FAILED == ret) {
        ret = HAL_CRYPT_INVALID_AUTH;
    } else if (ret) {
        LS_HAL_LOG("failed(0x%08x)\n", ret);
    }

    return ret;
}
