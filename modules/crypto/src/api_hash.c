/**
 * Copyright (C) 2017  Alibaba Group Holding Limited.
 */

#include "ali_crypto.h"
#include "ls_hal_crypt.h"

static ali_crypto_result _trans_errno(int code)
{
    ali_crypto_result result;

    switch(code) {
        case HAL_CRYPT_SUCCESS:
            result = ALI_CRYPTO_SUCCESS;
            break;
        case HAL_CRYPT_NOSUPPORT:
            result = ALI_CRYPTO_NOSUPPORT;
            break;
        case HAL_CRYPT_INVALID_CONTEXT:
            result = ALI_CRYPTO_INVALID_CONTEXT;
            break;
        case HAL_CRYPT_INVALID_ARG:
            result = ALI_CRYPTO_INVALID_ARG;
            break;
        case HAL_CRYPT_LENGTH_ERR:
            result = ALI_CRYPTO_LENGTH_ERR;
            break;
        case HAL_CRYPT_OUTOFMEM:
            result = ALI_CRYPTO_OUTOFMEM;
            break;
        case HAL_CRYPT_SHORT_BUFFER:
            result = ALI_CRYPTO_SHORT_BUFFER;
            break;
        default:
            result = ALI_CRYPTO_ERROR;
            break;
        }

    return result;
}

// hash crypto api get ctx size according to hash mode
ali_crypto_result ali_sha1_get_ctx_size(size_t *size)
{
    if (size == NULL) {
        CRYPTO_ERR_LOG("bad input\n");
        return ALI_CRYPTO_INVALID_ARG;
    }

    *size = sizeof(api_hash_ctx_t) + ls_hal_sha1_get_size();
    return ALI_CRYPTO_SUCCESS;
}

ali_crypto_result ali_sha256_get_ctx_size(size_t *size)
{
    if (size == NULL) {
        CRYPTO_ERR_LOG("bad input\n");
        return ALI_CRYPTO_INVALID_ARG;
    }

    *size = sizeof(api_hash_ctx_t) + ls_hal_sha256_get_size();
    return ALI_CRYPTO_SUCCESS;
}

ali_crypto_result ali_md5_get_ctx_size(size_t *size)
{
    if (size == NULL) {
        CRYPTO_ERR_LOG("bad input\n");
        return ALI_CRYPTO_INVALID_ARG;
    }

    *size = sizeof(api_hash_ctx_t) + ls_hal_md5_get_size();
    return ALI_CRYPTO_SUCCESS;
}

ali_crypto_result ali_sm3_get_ctx_size(size_t *size)
{
    if (size == NULL) {
        CRYPTO_ERR_LOG("bad input\n");
        return ALI_CRYPTO_INVALID_ARG;
    }

    *size = sizeof(api_hash_ctx_t) + ls_hal_sm3_get_size();
    return ALI_CRYPTO_SUCCESS;
}

ali_crypto_result ali_hash_get_ctx_size(hash_type_t type, size_t *size)
{

    ali_crypto_result result;

    if (size == NULL) {
        CRYPTO_ERR_LOG("bad input\n");
        return ALI_CRYPTO_INVALID_ARG;
    }

    switch(type) {
        case SHA1:
            result = ali_sha1_get_ctx_size(size);
            break;
        case SHA256:
            result = ali_sha256_get_ctx_size(size);
            break;
        case MD5:
            result = ali_md5_get_ctx_size(size);
            break;
        case SM3:
            result = ali_sm3_get_ctx_size(size);
            break;
        default:
            CRYPTO_ERR_LOG("invalid type(%d)\n", type);
            return ALI_CRYPTO_NOSUPPORT;
    }

    return result;
}

// hash crypto api hash init according to hash mode
ali_crypto_result ali_sha1_init(void *context)
{
    int ret;
    api_hash_ctx_t *ctx;

    if (NULL == context) {
        CRYPTO_ERR_LOG("invalid ctx\n");
        return ALI_CRYPTO_INVALID_CONTEXT;
    }

    ctx = (api_hash_ctx_t *) context;
    ctx->hal_ctx = (char *)&(ctx->hal_ctx) + sizeof(ctx->hal_ctx);
    ctx->type = SHA1;
    ctx->hal_size = ls_hal_sha1_get_size();
    ret = ls_hal_sha1_init(ctx->hal_ctx);

    return _trans_errno(ret);
}

ali_crypto_result ali_sha256_init(void *context)
{
    int ret;
    api_hash_ctx_t *ctx;

    if (NULL == context) {
        CRYPTO_ERR_LOG("invalid ctx\n");
        return ALI_CRYPTO_INVALID_CONTEXT;
    }
    
    ctx = (api_hash_ctx_t *) context;
    ctx->hal_ctx = (char *)&(ctx->hal_ctx) + sizeof(ctx->hal_ctx);
    ctx->type = SHA256;
    ctx->hal_size = ls_hal_sha256_get_size();
    ret = ls_hal_sha256_init(ctx->hal_ctx);

    return _trans_errno(ret);
}

ali_crypto_result ali_md5_init(void *context)
{
    int ret;
    api_hash_ctx_t *ctx;

    if (NULL == context) {
        CRYPTO_ERR_LOG("invalid ctx\n");
        return ALI_CRYPTO_INVALID_CONTEXT;
    }

    ctx = (api_hash_ctx_t *) context;
    ctx->hal_ctx = (char *)&(ctx->hal_ctx) + sizeof(ctx->hal_ctx);
    ctx->type = MD5;
    ctx->hal_size = ls_hal_md5_get_size();
    ret = ls_hal_md5_init(ctx->hal_ctx);

    return _trans_errno(ret);
}

ali_crypto_result ali_sm3_init(void *context)
{
    int ret;
    api_hash_ctx_t *ctx;

    if (NULL == context) {
        CRYPTO_ERR_LOG("invalid ctx\n");
        return ALI_CRYPTO_INVALID_CONTEXT;
    }

    ctx = (api_hash_ctx_t *) context;
    ctx->hal_ctx = (char *)&(ctx->hal_ctx) + sizeof(ctx->hal_ctx);
    ctx->type = SM3;
    ctx->hal_size = ls_hal_sm3_get_size();
    ret = ls_hal_sm3_init(ctx->hal_ctx);

    return _trans_errno(ret);
}

ali_crypto_result ali_hash_init(hash_type_t type, void *context)
{
    ali_crypto_result result;

    if (NULL == context) {
        CRYPTO_ERR_LOG("invalid ctx\n");
        return ALI_CRYPTO_INVALID_CONTEXT;
    }

    switch(type) {
        case SHA1:
            result = ali_sha1_init(context);
            break;
        case SHA256:
            result = ali_sha256_init(context);
            break;
        case MD5:
            result = ali_md5_init(context);
            break;
        case SM3:
            result = ali_sm3_init(context);
            break;
        default:
            CRYPTO_ERR_LOG("not support this type(%d)\n", type);
            return ALI_CRYPTO_NOSUPPORT;
    }

    return result;
}

// hash crypto api hash update according to hash mode
ali_crypto_result ali_sha1_update(const uint8_t *src, size_t size, void *context)
{
    int ret;
    api_hash_ctx_t *ctx;
    
    if (context == NULL) {
        CRYPTO_ERR_LOG("invalid ctx\n");
        return ALI_CRYPTO_INVALID_CONTEXT;
    }

    if (src == NULL && size != 0) {
        CRYPTO_ERR_LOG("bad input\n");
        return ALI_CRYPTO_INVALID_ARG;
    }

    ctx = (api_hash_ctx_t *) context;
    ctx->hal_ctx = (char *)&(ctx->hal_ctx) + sizeof(ctx->hal_ctx);
    ret = ls_hal_sha1_update(ctx->hal_ctx, src, size);

    return _trans_errno(ret);
}

ali_crypto_result ali_sha256_update(const uint8_t *src, size_t size, void *context)
{
    int ret;
    api_hash_ctx_t *ctx;

    if (context == NULL) {
        CRYPTO_ERR_LOG("invalid ctx\n");
        return ALI_CRYPTO_INVALID_CONTEXT;
    }

    if (src == NULL && size != 0) {
        CRYPTO_ERR_LOG("bad input\n");
        return ALI_CRYPTO_INVALID_ARG;
    }

    ctx = (api_hash_ctx_t *) context;
    ctx->hal_ctx = (char *)&(ctx->hal_ctx) + sizeof(ctx->hal_ctx);
    ret = ls_hal_sha256_update(ctx->hal_ctx, src, size);

    return _trans_errno(ret);
}

ali_crypto_result ali_md5_update(const uint8_t *src, size_t size, void *context)
{
    int ret;
    api_hash_ctx_t *ctx;
    
    if (context == NULL) {
        CRYPTO_ERR_LOG("invalid ctx\n");
        return ALI_CRYPTO_INVALID_CONTEXT;
    }

    if (src == NULL && size != 0) {
        CRYPTO_ERR_LOG("bad input\n");
        return ALI_CRYPTO_INVALID_ARG;
    }

    ctx = (api_hash_ctx_t *) context;
    ctx->hal_ctx = (char *)&(ctx->hal_ctx) + sizeof(ctx->hal_ctx);
    ret = ls_hal_md5_update(ctx->hal_ctx, src, size);

    return _trans_errno(ret);
}

ali_crypto_result ali_sm3_update(const uint8_t *src, size_t size, void *context)
{
    int ret;
    api_hash_ctx_t *ctx;
    
    if (context == NULL) {
        CRYPTO_ERR_LOG("invalid ctx\n");
        return ALI_CRYPTO_INVALID_CONTEXT;
    }

    if (src == NULL && size != 0) {
        CRYPTO_ERR_LOG("bad input\n");
        return ALI_CRYPTO_INVALID_ARG;
    }

    ctx = (api_hash_ctx_t *) context;
    ctx->hal_ctx = (char *)&(ctx->hal_ctx) + sizeof(ctx->hal_ctx);
    ret = ls_hal_sm3_update(ctx->hal_ctx, src, size);

    return _trans_errno(ret);
}

ali_crypto_result ali_hash_update(const uint8_t *src, size_t size, void *context)
{
    ali_crypto_result  result;
    api_hash_ctx_t *ctx;

    if (context == NULL) {
        CRYPTO_ERR_LOG("invalid ctx\n");
        return ALI_CRYPTO_INVALID_CONTEXT;
    }

    if (src == NULL && size != 0) {
        CRYPTO_ERR_LOG("bad input\n");
        return ALI_CRYPTO_INVALID_ARG;
    }

    ctx = (api_hash_ctx_t *) context;
    switch(ctx->type) {
        case SHA1:
            result = ali_sha1_update(src, size, ctx);
            break;
        case SHA256:
            result = ali_sha256_update(src, size, ctx);
            break;
        case MD5:
            result = ali_md5_update(src, size, ctx);
            break;
        case SM3:
            result = ali_sm3_update(src, size, ctx);
            break;
        default:
            CRYPTO_ERR_LOG("invalid type(%d)\n", ctx->type);
            return ALI_CRYPTO_NOSUPPORT;
    }

    return result;
}

// hash crypto api hash final according to hash mode
ali_crypto_result ali_sha1_final(uint8_t *dgst, void *context)
{
    int ret;
    api_hash_ctx_t *ctx;

    if (context == NULL) {
        CRYPTO_ERR_LOG("invalid ctx\n");
        return ALI_CRYPTO_INVALID_CONTEXT;
    }
    if (dgst == NULL) {
        CRYPTO_ERR_LOG("bad input args!\n");
        return ALI_CRYPTO_INVALID_ARG;
    }

    ctx = (api_hash_ctx_t *) context;
    ctx->hal_ctx = (char *)&(ctx->hal_ctx) + sizeof(ctx->hal_ctx);
    ret = ls_hal_sha1_finish(ctx->hal_ctx, dgst);

    return _trans_errno(ret);
}

ali_crypto_result ali_sha256_final(uint8_t *dgst, void *context)
{
    int ret;
    api_hash_ctx_t *ctx;

    if (context == NULL) {
        CRYPTO_ERR_LOG("invalid ctx\n");
        return ALI_CRYPTO_INVALID_CONTEXT;
    }
    if (dgst == NULL) {
        CRYPTO_ERR_LOG("bad input args!\n");
        return ALI_CRYPTO_INVALID_ARG;
    }

    ctx = (api_hash_ctx_t *) context;
    ctx->hal_ctx = (char *)&(ctx->hal_ctx) + sizeof(ctx->hal_ctx);
    ret = ls_hal_sha256_finish(ctx->hal_ctx, dgst);

    return _trans_errno(ret);
}

ali_crypto_result ali_md5_final(uint8_t *dgst, void *context)
{
    int ret;
    api_hash_ctx_t *ctx;

    if (context == NULL) {
        CRYPTO_ERR_LOG("invalid ctx\n");
        return ALI_CRYPTO_INVALID_CONTEXT;
    }
    if (dgst == NULL) {
        CRYPTO_ERR_LOG("bad input args!\n");
        return ALI_CRYPTO_INVALID_ARG;
    }

    ctx = (api_hash_ctx_t *) context;
    ctx->hal_ctx = (char *)&(ctx->hal_ctx) + sizeof(ctx->hal_ctx);
    ret = ls_hal_md5_finish(ctx->hal_ctx, dgst);

    return _trans_errno(ret);
}

ali_crypto_result ali_sm3_final(uint8_t *dgst, void *context)
{
    int ret;
    api_hash_ctx_t *ctx;

    if (context == NULL) {
        CRYPTO_ERR_LOG("invalid ctx\n");
        return ALI_CRYPTO_INVALID_CONTEXT;
    }
    if (dgst == NULL) {
        CRYPTO_ERR_LOG("bad input args!\n");
        return ALI_CRYPTO_INVALID_ARG;
    }

    ctx = (api_hash_ctx_t *) context;
    ctx->hal_ctx = (char *)&(ctx->hal_ctx) + sizeof(ctx->hal_ctx);
    ret = ls_hal_sm3_finish(ctx->hal_ctx, dgst);

    return _trans_errno(ret);
}

ali_crypto_result ali_hash_final(uint8_t *dgst, void *context)
{
    ali_crypto_result  result;
    api_hash_ctx_t *ctx;

    if (context == NULL) {
        CRYPTO_ERR_LOG("invalid ctx\n");
        return ALI_CRYPTO_INVALID_CONTEXT;
    }
    if (dgst == NULL) {
        CRYPTO_ERR_LOG("bad input args!\n");
        return ALI_CRYPTO_INVALID_ARG;
    }

    ctx = (api_hash_ctx_t *) context;
    switch(ctx->type) {
        case SHA1:
            result = ali_sha1_final(dgst, ctx);
            break;
        case SHA256:
            result = ali_sha256_final(dgst, ctx);
            break;
        case MD5:
            result = ali_md5_final(dgst, ctx);
            break;
        case SM3:
            result = ali_sm3_final(dgst, ctx);
            break;
        default:
            CRYPTO_ERR_LOG("not support this type(%d)\n", ctx->type);
            return ALI_CRYPTO_NOSUPPORT;
    }

    return result;
}

// hash crypto api hash digest according to hash mode
ali_crypto_result ali_sha1_digest(const uint8_t *src,
                                  size_t size, uint8_t *dgst)
{
    ali_crypto_result result;
    api_hash_ctx_t *ctx;
    size_t ctx_size;

    if ((src == NULL && size != 0) || dgst == NULL) {
        CRYPTO_ERR_LOG("bad input\n");
        return ALI_CRYPTO_INVALID_ARG;
    }

    result = ali_sha1_get_ctx_size(&ctx_size);
    if (ALI_CRYPTO_SUCCESS != result) {
        CRYPTO_ERR_LOG("get ctx err!\n");
        return result;
    }

    ctx = ls_osa_malloc(ctx_size);
    if (!ctx) {
        CRYPTO_ERR_LOG("ctx malloc(%ld) failed!\n", ctx_size);
        result = ALI_CRYPTO_OUTOFMEM;
        goto _out;
    }

    result = ali_sha1_init(ctx);
    if (ALI_CRYPTO_SUCCESS != result) {
        CRYPTO_ERR_LOG("init failed(0x%08x)\n", result);
        goto _out;
    }

    result = ali_sha1_update(src, size, ctx);
    if (ALI_CRYPTO_SUCCESS != result) {
        CRYPTO_ERR_LOG("update failed(0x%08x)\n", result);
        goto _out;
    }

    result = ali_sha1_final(dgst, ctx);
    if (ALI_CRYPTO_SUCCESS != result) {
        CRYPTO_ERR_LOG("final failed(0x%08x)\n", result);
        goto _out;
    }

_out:
    if (ctx) {
        ls_osa_free(ctx);
    }

    return result;
}

ali_crypto_result ali_sha256_digest(const uint8_t *src,
                                  size_t size, uint8_t *dgst)
{
    ali_crypto_result result;
    api_hash_ctx_t *ctx;
    size_t ctx_size;

    if ((src == NULL && size != 0) || dgst == NULL) {
        CRYPTO_ERR_LOG("bad input\n");
        return ALI_CRYPTO_INVALID_ARG;
    }

    result = ali_sha256_get_ctx_size(&ctx_size);
    if (ALI_CRYPTO_SUCCESS != result) {
        CRYPTO_ERR_LOG("get ctx err!\n");
        return result;
    }

    ctx = ls_osa_malloc(ctx_size);
    if (!ctx) {
        CRYPTO_ERR_LOG("ctx malloc(%ld) failed!\n", ctx_size);
        result = ALI_CRYPTO_OUTOFMEM;
        goto _out;
    }

    result = ali_sha256_init(ctx);
    if (ALI_CRYPTO_SUCCESS != result) {
        CRYPTO_ERR_LOG("init failed(0x%08x)\n", result);
        goto _out;
    }

    result = ali_sha256_update(src, size, ctx);
    if (ALI_CRYPTO_SUCCESS != result) {
        CRYPTO_ERR_LOG("update failed(0x%08x)\n", result);
        goto _out;
    }

    result = ali_sha256_final(dgst, ctx);
    if (ALI_CRYPTO_SUCCESS != result) {
        CRYPTO_ERR_LOG("final failed(0x%08x)\n", result);
        goto _out;
    }

_out:
    if (ctx) {
        ls_osa_free(ctx);
    }

    return result;
}

ali_crypto_result ali_md5_digest(const uint8_t *src,
                                  size_t size, uint8_t *dgst)
{
    ali_crypto_result result;
    api_hash_ctx_t *ctx;
    size_t ctx_size;

    if ((src == NULL && size != 0) || dgst == NULL) {
        CRYPTO_ERR_LOG("bad input\n");
        return ALI_CRYPTO_INVALID_ARG;
    }

    result = ali_md5_get_ctx_size(&ctx_size);
    if (ALI_CRYPTO_SUCCESS != result) {
        CRYPTO_ERR_LOG("get ctx err!\n");
        return result;
    }

    ctx = ls_osa_malloc(ctx_size);
    if (!ctx) {
        CRYPTO_ERR_LOG("ctx malloc(%ld) failed!\n", ctx_size);
        result = ALI_CRYPTO_OUTOFMEM;
        goto _out;
    }

    result = ali_md5_init(ctx);
    if (ALI_CRYPTO_SUCCESS != result) {
        CRYPTO_ERR_LOG("init failed(0x%08x)\n", result);
        goto _out;
    }

    result = ali_md5_update(src, size, ctx);
    if (ALI_CRYPTO_SUCCESS != result) {
        CRYPTO_ERR_LOG("update failed(0x%08x)\n", result);
        goto _out;
    }

    result = ali_md5_final(dgst, ctx);
    if (ALI_CRYPTO_SUCCESS != result) {
        CRYPTO_ERR_LOG("final failed(0x%08x)\n", result);
        goto _out;
    }

_out:
    if (ctx) {
        ls_osa_free(ctx);
    }

    return result;
}

ali_crypto_result ali_sm3_digest(const uint8_t *src,
                                 size_t size, uint8_t *dgst)
{
    ali_crypto_result result;
    api_hash_ctx_t *ctx;
    size_t ctx_size;

    if ((src == NULL && size != 0) || dgst == NULL) {
        CRYPTO_ERR_LOG("bad input\n");
        return ALI_CRYPTO_INVALID_ARG;
    }

    result = ali_sm3_get_ctx_size(&ctx_size);
    if (ALI_CRYPTO_SUCCESS != result) {
        CRYPTO_ERR_LOG("get ctx err!\n");
        return result;
    }

    ctx = ls_osa_malloc(ctx_size);
    if (!ctx) {
        CRYPTO_ERR_LOG("ctx malloc(%ld) failed!\n", ctx_size);
        result = ALI_CRYPTO_OUTOFMEM;
        goto _out;
    }

    result = ali_sm3_init(ctx);
    if (ALI_CRYPTO_SUCCESS != result) {
        CRYPTO_ERR_LOG("init failed(0x%08x)\n", result);
        goto _out;
    }

    result = ali_sm3_update(src, size, ctx);
    if (ALI_CRYPTO_SUCCESS != result) {
        CRYPTO_ERR_LOG("update failed(0x%08x)\n", result);
        goto _out;
    }

    result = ali_sm3_final(dgst, ctx);
    if (ALI_CRYPTO_SUCCESS != result) {
        CRYPTO_ERR_LOG("final failed(0x%08x)\n", result);
        goto _out;
    }

_out:
    if (ctx) {
        ls_osa_free(ctx);
    }

    return result;
}

ali_crypto_result ali_hash_digest(hash_type_t type, const uint8_t *src,
                                  size_t size, uint8_t *dgst)
{
    ali_crypto_result result;

    if ((src == NULL && size != 0) || dgst == NULL) {
        CRYPTO_ERR_LOG("bad input\n");
        return ALI_CRYPTO_INVALID_ARG;
    }

    switch(type) {
        case SHA1:
            result = ali_sha1_digest(src, size, dgst);
            break;
        case SHA256:
            result = ali_sha256_digest(src, size, dgst);
            break;
        case MD5:
            result = ali_md5_digest(src, size, dgst);
            break;
        case SM3:
            result = ali_sm3_digest(src, size, dgst);
            break;
        default:
            CRYPTO_ERR_LOG("not support this type(%d)\n", type);
            return ALI_CRYPTO_NOSUPPORT;
    }

    return result;
}

ali_crypto_result ali_hash_reset(void *context)
{
    ali_crypto_result  ret = ALI_CRYPTO_SUCCESS;
    api_hash_ctx_t *ctx;
 
    if (context == NULL) {
        CRYPTO_ERR_LOG("invalid ctx\n");
        return ALI_CRYPTO_INVALID_CONTEXT;
    }

    ctx = (api_hash_ctx_t *) context;
    memset(ctx->hal_ctx, 0, ctx->hal_size);

    return ret;
}
