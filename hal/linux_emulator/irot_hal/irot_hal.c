/*
 * Copyright (C) 2018 Alibaba Group Holding Limited
 */


#include <string.h>
#include <time.h>
#include <stdlib.h>
#include <mbedtls/sha1.h>
#include <mbedtls/sha256.h>
#include <mbedtls/des.h>
#include <mbedtls/aes.h>
#include <mbedtls/rsa.h>
#include "config.h"
#include "irot_pal.h"
#include "irot_hal.h"

enum
{
    HAL_INITED_NO   =   0,
    HAL_INITED_YES  =   1,
};

static int s_hal_inited = 0;

enum
{
    DES_BLOCK_SIZE      =   0x08,
    AES_BLOCK_SIZE      =   0x10,
};

enum
{
    LENGTH_DES3_2KEY    =   16,
    LENGTH_DES3_3KEY    =   24,
};

enum
{
    LENGTH_AES_128      =   16,
    LENGTH_AES_192      =   24,
    LENGTH_AES_256      =   32,
};

enum
{
    LENGTH_RSA_1024     =   128,
};

enum
{
    DES_MAX_KEY_SIZE    =   LENGTH_DES3_3KEY,
    AES_MAX_KEY_SIZE    =   LENGTH_AES_256,
    RSA_MAX_KEY_SIZE    =   LENGTH_RSA_1024,
};

#define ID2_HEX_LEN         12

#if (ID2_SECURE_TYPE_CONFIG == ID2_SECURE_TYPE_MCU)

#include "id2_key_3des.h"
#include "id2_key_aes.h"
#include "id2_key_rsa.h"

////////////////////////////////////////////////////////////////////////////////

static uint8_t s_id2[ID2_HEX_LEN] = {0};

#if (ID2_CRYPTO_TYPE_CONFIG == ID2_CRYPTO_TYPE_3DES)

static uint8_t s_3des_key[DES_MAX_KEY_SIZE];
static uint32_t s_3des_key_len = 0;

#elif (ID2_CRYPTO_TYPE_CONFIG == ID2_CRYPTO_TYPE_AES)

static uint8_t s_aes_key[AES_MAX_KEY_SIZE];
static uint32_t s_aes_key_len = 0;

#elif (ID2_CRYPTO_TYPE_CONFIG == ID2_CRYPTO_TYPE_RSA)
static uint8_t s_rsa_e[RSA_MAX_KEY_SIZE];
static uint8_t s_rsa_d[RSA_MAX_KEY_SIZE];
static uint8_t s_rsa_n[RSA_MAX_KEY_SIZE];
static uint32_t s_rsa_e_len = 0;
static uint32_t s_rsa_d_len = 0;
static uint32_t s_rsa_n_len = 0;

static uint8_t s_rsa_p[RSA_MAX_KEY_SIZE >> 1];
static uint8_t s_rsa_q[RSA_MAX_KEY_SIZE >> 1];
static uint8_t s_rsa_dp[RSA_MAX_KEY_SIZE >> 1];
static uint8_t s_rsa_dq[RSA_MAX_KEY_SIZE >> 1];
static uint8_t s_rsa_qinv[RSA_MAX_KEY_SIZE >> 1];
static uint32_t s_rsa_crt_len = 0;

#else
#error("id2 crypto type configuration error.");
#endif

////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////

static void load_id2_and_key()
{
#if (ID2_CRYPTO_TYPE_CONFIG == ID2_CRYPTO_TYPE_3DES)
    memcpy(s_id2, g_3des_id2, sizeof(g_3des_id2));
    memcpy(s_3des_key, g_3des_key, sizeof(g_3des_key));
    s_3des_key_len = sizeof(g_3des_key);
#elif (ID2_CRYPTO_TYPE_CONFIG == ID2_CRYPTO_TYPE_AES)
    memcpy(s_id2, g_aes_id2, sizeof(g_aes_id2));
    memcpy(s_aes_key, g_aes_key, sizeof(g_aes_key));
    s_aes_key_len = sizeof(g_aes_key);
#elif (ID2_CRYPTO_TYPE_CONFIG == ID2_CRYPTO_TYPE_RSA)
    memcpy(s_id2, g_rsa_id2, sizeof(g_rsa_id2));
    memcpy(s_rsa_e, g_rsa_e, sizeof(g_rsa_e));
    memcpy(s_rsa_d, g_rsa_d, sizeof(g_rsa_d));
    memcpy(s_rsa_n, g_rsa_n, sizeof(g_rsa_n));
    s_rsa_e_len = sizeof(g_rsa_e);
    s_rsa_d_len = sizeof(g_rsa_d);
    s_rsa_n_len = sizeof(g_rsa_n);

    memcpy(s_rsa_p, g_rsa_p, sizeof(g_rsa_p));
    memcpy(s_rsa_q, g_rsa_q, sizeof(g_rsa_q));
    memcpy(s_rsa_dp, g_rsa_dp, sizeof(g_rsa_dp));
    memcpy(s_rsa_dq, g_rsa_dq, sizeof(g_rsa_dq));
    memcpy(s_rsa_qinv, g_rsa_qinv, sizeof(g_rsa_qinv));
    s_rsa_crt_len = sizeof(g_rsa_p);
#else
#endif
}

////////////////////////////////////////////////////////////////////////////////

irot_result_t irot_hal_get_id2(uint8_t* id2, uint32_t* len)
{
    if (s_hal_inited != HAL_INITED_YES)
    {
        load_id2_and_key();
        s_hal_inited = HAL_INITED_YES;
    }

    if (*len < ID2_HEX_LEN)
    {
        return IROT_ERROR_SHORT_BUFFER;
    }
    memcpy(id2, s_id2, ID2_HEX_LEN);
    *len = ID2_HEX_LEN;
    return IROT_SUCCESS;
}

#if (ID2_CRYPTO_TYPE_CONFIG == ID2_CRYPTO_TYPE_3DES)
static irot_result_t des3_ecb(const uint8_t* key, uint32_t key_len, const uint8_t* in, uint32_t in_len, uint8_t* out, uint32_t* out_len, crypto_mode_t mode)
{
    irot_result_t ret = IROT_SUCCESS;
    uint32_t i;
    mbedtls_des3_context des_context;

    mbedtls_des3_init(&des_context);
    if ((in_len % DES_BLOCK_SIZE != 0) || (*out_len < in_len))
    {
        ret = IROT_ERROR_SHORT_BUFFER;
        goto EXIT;
    }
    if (key_len == 0x10)
    {
        if (mode == MODE_ENCRYPT)
        {
            mbedtls_des3_set2key_enc(&des_context, key);
        }
        else
        {
            mbedtls_des3_set2key_dec(&des_context, key);
        }
    }
    else if (key_len == 0x18)
    {
        if (mode == MODE_ENCRYPT)
        {
            mbedtls_des3_set3key_enc(&des_context, key);
        }
        else
        {
            mbedtls_des3_set3key_dec(&des_context, key);
        }
    }
    else
    {
        ret = IROT_ERROR_BAD_PARAMETERS;
        goto EXIT;
    }

    i = 0;
    while (i < in_len)
    {
        mbedtls_des3_crypt_ecb(&des_context, in + i, out + i);
        i += DES_BLOCK_SIZE;
    }

EXIT:
    mbedtls_des3_free(&des_context);
    return ret;
}
#endif

#if (ID2_CRYPTO_TYPE_CONFIG == ID2_CRYPTO_TYPE_AES)
static irot_result_t aes_ecb(const uint8_t* key, uint32_t key_len, const uint8_t* in, uint32_t in_len, uint8_t* out, uint32_t* out_len, crypto_mode_t mode)
{
    irot_result_t ret = IROT_SUCCESS;
    uint32_t i;
    mbedtls_aes_context aes_context;

    mbedtls_aes_init(&aes_context);
    if ((in_len % AES_BLOCK_SIZE != 0) || (*out_len < in_len))
    {
        ret = IROT_ERROR_SHORT_BUFFER;
        goto EXIT;
    }
    i = 0;
    if (mode == MODE_ENCRYPT)
    {
        mbedtls_aes_setkey_enc(&aes_context, key, key_len * 8);
        while (i < in_len)
        {
            mbedtls_aes_crypt_ecb(&aes_context, MBEDTLS_AES_ENCRYPT, in + i, out + i);
            i += AES_BLOCK_SIZE;
        }
    }
    else if (mode == MODE_DECRYPT)
    {
        mbedtls_aes_setkey_dec(&aes_context, key, key_len * 8);
        while (i < in_len)
        {
            mbedtls_aes_crypt_ecb(&aes_context, MBEDTLS_AES_DECRYPT, in + i, out + i);
            i += AES_BLOCK_SIZE;
        }
    }
    else
    {
        ret = IROT_ERROR_BAD_PARAMETERS;
        goto EXIT;
    }

EXIT:
    mbedtls_aes_free(&aes_context);
    return ret;
}
#endif

irot_result_t irot_hal_sym_crypto(key_object* key_obj, uint8_t key_id,
                                  const uint8_t* iv, uint32_t iv_len,
                                  const uint8_t* in, uint32_t in_len,
                                  uint8_t* out, uint32_t* out_len,
                                  sym_crypto_param_t* crypto_param)
{
    irot_result_t ret = IROT_SUCCESS;
    uint32_t block_size;

    //check key_obj
    if (s_hal_inited != HAL_INITED_YES)
    {
        load_id2_and_key();
        s_hal_inited = HAL_INITED_YES;
    }

    if (key_obj != NULL)
    {
        ret = IROT_ERROR_NOT_SUPPORTED;
        goto EXIT;
    }

    //check key_id
    if (key_id != KEY_ID_ID2)
    {
        ret = IROT_ERROR_NOT_SUPPORTED;
        goto EXIT;
    }
    //check cipher_type
    if (crypto_param->cipher_type == CIPHER_TYPE_3DES)
    {
        block_size = DES_BLOCK_SIZE;
    }
    else if (crypto_param->cipher_type == CIPHER_TYPE_AES)
    {
        block_size = AES_BLOCK_SIZE;
    }
    else
    {
        ret = IROT_ERROR_NOT_SUPPORTED;
        goto EXIT;
    }
    //check block_mode
    if (crypto_param->block_mode != BLOCK_MODE_ECB)
    {
        ret = IROT_ERROR_NOT_SUPPORTED;
        goto EXIT;
    }

    //check padding_type
    if (crypto_param->padding_type != SYM_PADDING_NOPADDING)
    {
        ret = IROT_ERROR_NOT_SUPPORTED;
        goto EXIT;
    }

    //check length
    if ((in == NULL) || (out == NULL) || (in_len == 0) || (in_len % block_size != 0) || (*out_len < in_len))
    {
        ret = IROT_ERROR_SHORT_BUFFER;
        goto EXIT;
    }

    if ((crypto_param->mode) != MODE_ENCRYPT && (crypto_param->mode != MODE_DECRYPT))
    {
        ret = IROT_ERROR_BAD_PARAMETERS;
        goto EXIT;
    }
#if (ID2_CRYPTO_TYPE_CONFIG == ID2_CRYPTO_TYPE_3DES)
    ret = des3_ecb(s_3des_key, s_3des_key_len, in, in_len, out, out_len, crypto_param->mode);
#elif (ID2_CRYPTO_TYPE_CONFIG == ID2_CRYPTO_TYPE_AES)
    ret = aes_ecb(s_aes_key, s_aes_key_len, in, in_len, out, out_len, crypto_param->mode);
#elif (ID2_CRYPTO_TYPE_CONFIG == ID2_CRYPTO_TYPE_RSA)
#else
#error("crypto type configuration error.");
#endif
    *out_len = in_len;
EXIT:
    return ret;
}


irot_result_t irot_hal_hash_sum(const uint8_t* in, uint32_t in_len, uint8_t* out, uint32_t* out_len, hash_t type)
{
    irot_result_t ret = IROT_SUCCESS;

    if (type == HASH_TYPE_SHA1)
    {
        if (*out_len < 20)
        {
            ret = IROT_ERROR_SHORT_BUFFER;
            goto EXIT;
        }
        mbedtls_sha1(in, in_len, out);
        *out_len = 20;
    }
    else if (type == HASH_TYPE_SHA256)
    {
        if (*out_len < 32)
        {
            ret = IROT_ERROR_SHORT_BUFFER;
            goto EXIT;
        }
        mbedtls_sha256(in, in_len, out, 0);
        *out_len = 32;
    }
    else
    {
        ret = IROT_ERROR_NOT_SUPPORTED;
        goto EXIT;
    }

EXIT:
    return ret;
}

#if (ID2_CRYPTO_TYPE_CONFIG == ID2_CRYPTO_TYPE_RSA)
irot_result_t irot_hal_asym_priv_sign(key_object* key_obj, uint8_t key_id,
                                      const uint8_t* in, uint32_t in_len,
                                      uint8_t* out, uint32_t* out_len,
                                      asym_sign_verify_t type)
{

    irot_result_t ret = IROT_SUCCESS;
    int mbed_ret;
    mbedtls_rsa_context rsa_context;
    uint8_t hash_buf[32];
    uint32_t hash_len = sizeof(hash_buf);
    hash_t hash_type;
    int mbed_hash_type;

    if (s_hal_inited != HAL_INITED_YES)
    {
        load_id2_and_key();
        s_hal_inited = HAL_INITED_YES;
    }

    mbedtls_rsa_init(&rsa_context, MBEDTLS_RSA_PKCS_V15, 0);

    if (key_obj != NULL)
    {
        ret = IROT_ERROR_NOT_SUPPORTED;
        goto EXIT;
    }

    if (key_id != KEY_ID_ID2)
    {
        ret = IROT_ERROR_NOT_SUPPORTED;
        goto EXIT;
    }

    if ((in == NULL) || (out == NULL) || (in_len == 0) || (*out_len < RSA_MAX_KEY_SIZE))
    {
        ret = IROT_ERROR_BAD_PARAMETERS;
        goto EXIT;
    }

    if (type == ASYM_TYPE_RSA_SHA1_PKCS1)
    {
        hash_type = HASH_TYPE_SHA1;
        mbed_hash_type = MBEDTLS_MD_SHA1;
    }
    else if (type == ASYM_TYPE_RSA_SHA256_PKCS1)
    {
        hash_type = HASH_TYPE_SHA256;
        mbed_hash_type = MBEDTLS_MD_SHA256;
    }
    else
    {
        ret = IROT_ERROR_BAD_PARAMETERS;
        goto EXIT;
    }
    if ((mbedtls_mpi_read_binary(&rsa_context.N, s_rsa_n, s_rsa_n_len) != 0) ||
            (mbedtls_mpi_read_binary(&rsa_context.E, s_rsa_e, s_rsa_e_len) != 0) ||
            (mbedtls_mpi_read_binary(&rsa_context.D, s_rsa_d, s_rsa_d_len) != 0) ||

            (mbedtls_mpi_read_binary(&rsa_context.P, s_rsa_p, s_rsa_crt_len) != 0) ||
            (mbedtls_mpi_read_binary(&rsa_context.Q, s_rsa_q, s_rsa_crt_len) != 0) ||
            (mbedtls_mpi_read_binary(&rsa_context.DP, s_rsa_dp, s_rsa_crt_len) != 0) ||
            (mbedtls_mpi_read_binary(&rsa_context.DQ, s_rsa_dq, s_rsa_crt_len) != 0) ||
            (mbedtls_mpi_read_binary(&rsa_context.QP, s_rsa_qinv, s_rsa_crt_len) != 0)
       )
    {
        ret = IROT_ERROR_BAD_PARAMETERS;
        goto EXIT;
    }
    rsa_context.len = (mbedtls_mpi_bitlen(&rsa_context.N) + 7) >> 3;

    if (mbedtls_rsa_check_pubkey(&rsa_context) != 0 || mbedtls_rsa_check_privkey(&rsa_context) != 0)
    {
        ret = IROT_ERROR_BAD_PARAMETERS;
        goto EXIT;
    }

    ret = irot_hal_hash_sum(in, in_len, hash_buf, &hash_len, hash_type);
    if (ret != IROT_SUCCESS)
    {
        goto EXIT;
    }

    mbed_ret = mbedtls_rsa_pkcs1_sign(&rsa_context, NULL, NULL, MBEDTLS_RSA_PRIVATE, mbed_hash_type, hash_len, hash_buf, out);
    if (mbed_ret != 0)
    {
        ret = IROT_ERROR_BAD_PARAMETERS;
        goto EXIT;
    }
    *out_len = rsa_context.len;
EXIT:
    mbedtls_rsa_free(&rsa_context);
    return ret;
}

irot_result_t irot_hal_asym_priv_decrypt(key_object* key_obj, uint8_t key_id,
        const uint8_t* in, uint32_t in_len,
        uint8_t* out, uint32_t* out_len,
        irot_asym_padding_t padding)
{
    irot_result_t ret = IROT_SUCCESS;
    int mbed_ret;
    size_t olen;
    mbedtls_rsa_context rsa_context;
    size_t max_out_len = *out_len;

    if (s_hal_inited != HAL_INITED_YES)
    {
        load_id2_and_key();
        s_hal_inited = HAL_INITED_YES;
    }

    mbedtls_rsa_init(&rsa_context, MBEDTLS_RSA_PKCS_V15, 0);

    if (key_obj != NULL)
    {
        ret = IROT_ERROR_NOT_SUPPORTED;
        goto EXIT;
    }

    if (key_id != KEY_ID_ID2)
    {
        ret = IROT_ERROR_NOT_SUPPORTED;
        goto EXIT;
    }

    if ((in == NULL) || (out == NULL) || (in_len == 0) || (*out_len < LENGTH_RSA_1024))
    {
        ret = IROT_ERROR_BAD_PARAMETERS;
        goto EXIT;
    }

    if (padding != ASYM_PADDING_PKCS1)
    {
        ret = IROT_ERROR_BAD_PARAMETERS;
        goto EXIT;
    }

    if ((mbedtls_mpi_read_binary(&rsa_context.N, s_rsa_n, s_rsa_n_len) != 0) ||
            (mbedtls_mpi_read_binary(&rsa_context.E, s_rsa_e, s_rsa_e_len) != 0) ||
            (mbedtls_mpi_read_binary(&rsa_context.D, s_rsa_d, s_rsa_d_len) != 0) ||

            (mbedtls_mpi_read_binary(&rsa_context.P, s_rsa_p, s_rsa_crt_len) != 0) ||
            (mbedtls_mpi_read_binary(&rsa_context.Q, s_rsa_q, s_rsa_crt_len) != 0) ||
            (mbedtls_mpi_read_binary(&rsa_context.DP, s_rsa_dp, s_rsa_crt_len) != 0) ||
            (mbedtls_mpi_read_binary(&rsa_context.DQ, s_rsa_dq, s_rsa_crt_len) != 0) ||
            (mbedtls_mpi_read_binary(&rsa_context.QP, s_rsa_qinv, s_rsa_crt_len) != 0)
       )
    {
        ret = IROT_ERROR_BAD_PARAMETERS;
        goto EXIT;
    }
    rsa_context.len = (mbedtls_mpi_bitlen(&rsa_context.N) + 7) >> 3;

    if (mbedtls_rsa_check_pubkey(&rsa_context) != 0 || mbedtls_rsa_check_privkey(&rsa_context) != 0)
    {
        ret = IROT_ERROR_BAD_PARAMETERS;
        goto EXIT;
    }
    mbed_ret = mbedtls_rsa_pkcs1_decrypt(&rsa_context, NULL, NULL, MBEDTLS_RSA_PRIVATE, &olen, in, out, max_out_len);
    if (mbed_ret != 0)
    {
        ret = IROT_ERROR_GENERIC;
        goto EXIT;
    }
    *out_len = olen;
EXIT:
    mbedtls_rsa_free(&rsa_context);
    return ret;;
}
#endif

irot_result_t irot_hal_get_random(uint8_t* buf, uint32_t len)
{
    //this is only a sample, you must use the real random number on your chip!!!
    uint32_t i;
    for (i = 0; i < len; ++i)
    {
        buf[i] = (uint8_t)0xAB;
    }
    return IROT_SUCCESS;
}

#endif
