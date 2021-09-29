/**
 * Copyright (C) 2018  Alibaba Group Holding Limited.
 */

#include "ali_crypto.h"
#include "ls_hal_crypt.h"

static int _get_pkcs_padding(unsigned char *input, size_t input_len, size_t *output_len)
{
    unsigned char i;
    unsigned char padding;

    padding = input[input_len - 1];

    for (i = padding; i > 0; i--) {
        if (input[input_len - i] != padding) {
            CRYPTO_DBG_LOG("pkcs unpadding fail\n");
            return -1;
        }
    }

    *output_len = input_len - padding;

    return 0;
}

static ali_crypto_result _ali_sm4_final(const uint8_t *src, size_t src_size,
                                              uint8_t *dst, size_t *dst_size,
                                              sym_padding_t padding,
                                              api_sm4_ctx_t *ctx)
{
    ali_crypto_result result = ALI_CRYPTO_SUCCESS;
    int ret = HAL_CRYPT_SUCCESS;
    uint32_t padding_len = 0;
    uint8_t *tmp_buf = NULL;
    size_t tmp_size = 0;

    if (padding == SYM_PKCS5_PAD) {
        if (ctx->is_enc) {
            padding_len = SM4_BLOCK_SIZE - src_size % SM4_BLOCK_SIZE;
            tmp_size = src_size + padding_len;
        } else {
            tmp_size = src_size;
        }
    } else if (padding == SYM_NOPAD) {
        tmp_size = src_size;
    } else {
        CRYPTO_DBG_LOG("padding type(%d) not supported\n", padding);
        return ALI_CRYPTO_NOSUPPORT;
    }

    if (ctx->is_enc && *dst_size < tmp_size) {
        *dst_size = tmp_size;
        return ALI_CRYPTO_SHORT_BUFFER;
    }

    tmp_buf = ls_osa_malloc(tmp_size);
    if (NULL == tmp_buf) {
        CRYPTO_DBG_LOG("malloc(%ld) failed\n", src_size + SM4_BLOCK_SIZE);
        return ALI_CRYPTO_OUTOFMEM;
    }

    memcpy(tmp_buf, src, src_size);
    if (padding_len) {
        memset(tmp_buf + src_size, padding_len, padding_len);
    }

    switch(ctx->type) {
        case SM4_ECB:
            ret = ls_hal_sm4_ecb_process(ctx->hal_ctx, tmp_buf, tmp_buf, tmp_size);
            break;
        case SM4_CBC:
            ret = ls_hal_sm4_cbc_process(ctx->hal_ctx, tmp_buf, tmp_buf, tmp_size);
            break;
        case SM4_CTR:
            ret = ls_hal_sm4_ctr_process(ctx->hal_ctx, tmp_buf, tmp_buf, tmp_size);
            break;
        default:
            CRYPTO_DBG_LOG("sm4 type(%d) not supported\n", ctx->type);
            goto _out;
    }

    if (HAL_CRYPT_SUCCESS != ret) {
        CRYPTO_DBG_LOG("hal sm4(%d) process fail, 0x%x\n", ctx->type, ret);
        result = ALI_CRYPTO_ERROR;
        goto _out;
    }

    /* unpadding for decrypt */
    if ( !ctx->is_enc && padding == SYM_PKCS5_PAD) {
        if (_get_pkcs_padding(tmp_buf, tmp_size, &tmp_size)) {
            CRYPTO_DBG_LOG("get pkcs padding fail\n");
            result = ALI_CRYPTO_ERROR;
            goto _out;
        }
    }

    if (*dst_size < tmp_size) {
        result = ALI_CRYPTO_SHORT_BUFFER;
        *dst_size = tmp_size;
        goto _out;
    }

    *dst_size = tmp_size;
    if (dst == NULL) {
        CRYPTO_DBG_LOG("NULL dst\n");
        result = ALI_CRYPTO_INVALID_ARG;
        goto _out;
    }

    memcpy(dst, tmp_buf, tmp_size);

_out:
    if (tmp_buf != NULL) {
        ls_osa_free(tmp_buf);
    }

    return result;
}

ali_crypto_result ali_sm4_get_ctx_size(sm4_type_t type, size_t *size)
{
    if (size == NULL) {
        CRYPTO_ERR_LOG("invalid size\n");
        return ALI_CRYPTO_INVALID_ARG;
    }

    switch(type) {
        case SM4_ECB:
            *size = sizeof(api_sm4_ctx_t) + ls_hal_sm4_ecb_get_size();
            break;
        case SM4_CBC:
            *size = sizeof(api_sm4_ctx_t) + ls_hal_sm4_cbc_get_size();
            break;
        case SM4_CTR:
            *size = sizeof(api_sm4_ctx_t) + ls_hal_sm4_ctr_get_size();
            break;
        default:
            CRYPTO_ERR_LOG("not support type(%d)\n", type);
            return ALI_CRYPTO_NOSUPPORT;
    }

    return ALI_CRYPTO_SUCCESS;
}

ali_crypto_result ali_sm4_init(sm4_type_t type, bool is_enc,
                               const uint8_t *key1, const uint8_t *key2,
                               size_t keybytes, const uint8_t *iv,
                               void *context)
{
    ali_crypto_result result = ALI_CRYPTO_SUCCESS;
    int ret = HAL_CRYPT_SUCCESS;
    api_sm4_ctx_t *ctx = NULL;

    if (key1 == NULL) {
        CRYPTO_ERR_LOG("invalid key1\n");
        return ALI_CRYPTO_INVALID_ARG;
    }

    if (context == NULL) {
        CRYPTO_ERR_LOG("invalid context\n");
        return ALI_CRYPTO_INVALID_CONTEXT;
    }

    // sm4 has 128bit fixed length key
    if (keybytes != 16) {
        CRYPTO_ERR_LOG("bad keybytes(%ld)\n", keybytes);
        return ALI_CRYPTO_LENGTH_ERR;
    }

    ctx = (api_sm4_ctx_t *)context;
    ctx->hal_ctx = (char *)&(ctx->hal_ctx) + sizeof(ctx->hal_ctx);
    ctx->is_enc = is_enc;
    ctx->type = type;

    switch(ctx->type) {
        case SM4_ECB:
            ctx->hal_size = ls_hal_sm4_ecb_get_size();
            ret = ls_hal_sm4_ecb_init(ctx->hal_ctx, is_enc, key1, keybytes);
            break;
        case SM4_CBC:
            ctx->hal_size = ls_hal_sm4_cbc_get_size();
            ret = ls_hal_sm4_cbc_init(ctx->hal_ctx, is_enc, key1, keybytes, (uint8_t *)iv);
            break;
        case SM4_CTR:
            ctx->hal_size = ls_hal_sm4_ctr_get_size();
            ret = ls_hal_sm4_ctr_init(ctx->hal_ctx, is_enc, key1, keybytes, (uint8_t *)iv);
            break;
        default:
            CRYPTO_ERR_LOG("not support type(%d)\n", ctx->type);
            return ALI_CRYPTO_NOSUPPORT;
    }

    if (HAL_CRYPT_SUCCESS != ret) {
        CRYPTO_ERR_LOG("sm4(%d) init failed, 0x%x\n", type, ret);
        result = ALI_CRYPTO_ERROR;
    }

    return result;
}

ali_crypto_result ali_sm4_process(const uint8_t *src, uint8_t *dst, size_t size,
                                  void *context)
{
    int ret = HAL_CRYPT_SUCCESS;
    ali_crypto_result result = ALI_CRYPTO_SUCCESS;
    api_sm4_ctx_t *ctx = NULL;

    if (context == NULL) {
        CRYPTO_ERR_LOG("invalid context\n");
        return ALI_CRYPTO_INVALID_CONTEXT;
    }

    if (src == NULL || dst == NULL || size == 0) {
        CRYPTO_ERR_LOG("invalid src/dst/size(%ld)\n", size);
        return ALI_CRYPTO_INVALID_ARG;
    }

    ctx = (api_sm4_ctx_t *)context;

    switch(ctx->type) {
        case SM4_ECB:
            ret = ls_hal_sm4_ecb_process(ctx->hal_ctx, src, dst, size);
            break;
        case SM4_CBC:
            ret = ls_hal_sm4_cbc_process(ctx->hal_ctx, src, dst, size);
            break;
        case SM4_CTR:
            ret = ls_hal_sm4_ctr_process(ctx->hal_ctx, src, dst, size);
            break;
        default:
            CRYPTO_ERR_LOG("not support type(%d)\n", ctx->type);
            return ALI_CRYPTO_NOSUPPORT;
    }

    if (HAL_CRYPT_SUCCESS != ret) {
        CRYPTO_ERR_LOG("hal sm4(%d) process fail, 0x%x\n", ctx->type, ret);
        result = ALI_CRYPTO_ERROR;
    }

    return result;
}

ali_crypto_result ali_sm4_finish(const uint8_t *src, size_t src_size,
                                 uint8_t *dst, size_t *dst_size,
                                 sym_padding_t padding, void *context)
{
    ali_crypto_result   ret = ALI_CRYPTO_SUCCESS;
    api_sm4_ctx_t *ctx;

    if (context == NULL) {
        CRYPTO_ERR_LOG("invalid context\n");
        return ALI_CRYPTO_INVALID_CONTEXT;
    }

    if (src == NULL || src_size == 0) {
        if (dst_size != NULL) {
            *dst_size = 0;
        }
        return ALI_CRYPTO_SUCCESS;
    }

    if (dst_size == NULL) {
        CRYPTO_ERR_LOG("invalid dst_size\n");
        return ALI_CRYPTO_INVALID_ARG;
    }

    if (dst == NULL && *dst_size != 0) {
        CRYPTO_ERR_LOG("NULL dst but non-zero dst_size(%ld)\n", *dst_size);
        return ALI_CRYPTO_INVALID_ARG;
    }

    ctx = (api_sm4_ctx_t *)context;
    ctx->hal_ctx = (char *)&(ctx->hal_ctx) + sizeof(ctx->hal_ctx);

    if (padding != SYM_NOPAD && padding != SYM_PKCS5_PAD) {
        CRYPTO_ERR_LOG("not support this padding, %d\n", padding);
        return ALI_CRYPTO_NOSUPPORT;
    }

    switch(ctx->type) {
        case SM4_ECB:
        case SM4_CBC:
        case SM4_CTR:
            ret = _ali_sm4_final(src, src_size,
                                 dst, dst_size,
                                 padding, ctx);
            break;
        default:
            CRYPTO_ERR_LOG("invalid type(%d)\n", ctx->type);
            return ALI_CRYPTO_NOSUPPORT;
    }

    if (ret != ALI_CRYPTO_SUCCESS && ret != ALI_CRYPTO_SHORT_BUFFER) {
        CRYPTO_ERR_LOG("type(%d) failed(%08x)\n", ctx->type, ret);
    }

    return ret;
}

ali_crypto_result ali_sm4_reset(void *context)
{
    api_sm4_ctx_t *ctx;

    if (context == NULL) {
        CRYPTO_ERR_LOG("bad input args!\n");
        return ALI_CRYPTO_INVALID_CONTEXT;
    }

    ctx = (api_sm4_ctx_t *)context;
    memset(ctx->hal_ctx, 0, ctx->hal_size);

    return ALI_CRYPTO_SUCCESS;
}
