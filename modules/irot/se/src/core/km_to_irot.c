/*
 * Copyright (C) 2015-2017 Alibaba Group Holding Limited
 */

#include "km.h"
#include "irot_hal.h"
#include "chip_log.h"
#include "chip_config.h"

#define ID2_KEY_NAME                "id2_key"
#define ID2_KEY_NAME_LEN             7

static void _dump_chip_conf_info()
{
#if defined(CONFIG_CHIP_DEBUG)
    chip_log_info("CONFIG_CHIP_DEBUG is defined!\n");
#else
    chip_log_info("CONFIG_CHIP_DEBUG is not defined!\n");
#endif

    if (CONFIG_CHIP_TYPE == CHIP_TYPE_SE_STD_CMD) {
        chip_log_info("CONFIG_CHIP_TYPE: %s\n", "CHIP_TYPE_SE_STD_CMD");
    } else if (CONFIG_CHIP_TYPE == CHIP_TYPE_SE_MTK_CMD){
        chip_log_info("CONFIG_CHIP_TYPE: %s\n", "CHIP_TYPE_SE_MTK_CMD");
    }

    if (CONFIG_CHIP_KEY_TYPE == CHIP_KEY_TYPE_3DES) {
        chip_log_info("CONFIG_CHIP_KEY_TYPE: %s\n", "CHIP_KEY_TYPE_3DES");
    } else if (CONFIG_CHIP_KEY_TYPE == CHIP_KEY_TYPE_AES){
        chip_log_info("CONFIG_CHIP_KEY_TYPE: %s\n", "CHIP_KEY_TYPE_AES");
    } else if (CONFIG_CHIP_KEY_TYPE == CHIP_KEY_TYPE_RSA) {
        chip_log_info("CONFIG_CHIP_KEY_TYPE: %s\n", "CHIP_KEY_TYPE_RSA");
    } else if (CONFIG_CHIP_KEY_TYPE == CHIP_KEY_TYPE_SM1) {
        chip_log_info("CONFIG_CHIP_KEY_TYPE: %s\n", "CHIP_KEY_TYPE_SM1");
    } else if (CONFIG_CHIP_KEY_TYPE == CHIP_KEY_TYPE_SM2) {
        chip_log_info("CONFIG_CHIP_KEY_TYPE: %s\n", "CHIP_KEY_TYPE_SM2");
    } else if (CONFIG_CHIP_KEY_TYPE == CHIP_KEY_TYPE_SM4) {
        chip_log_info("CONFIG_CHIP_KEY_TYPE: %s\n", "CHIP_KEY_TYPE_SM4");
    }

    chip_log_info("========================================\n");
}

static uint32_t _check_km_key_name(const char* name, const uint32_t name_len)
{
    if (name == NULL || name_len != ID2_KEY_NAME_LEN) {
        return KM_ERR_BAD_PARAMS;
    }

    if (memcmp(ID2_KEY_NAME, name, ID2_KEY_NAME_LEN) != 0) {
        return KM_ERR_BAD_PARAMS;
    }

    return KM_SUCCESS;
}

uint32_t km_init()
{
    irot_result_t result;

    _dump_chip_conf_info();

    result = irot_hal_init();
    if (result != IROT_SUCCESS) {
        return KM_ERR_GENERIC;
    }

    return KM_SUCCESS;
}

void km_cleanup()
{
    irot_hal_cleanup();
}

uint32_t km_get_id2(uint8_t* id2, uint32_t* len)
{
    irot_result_t result;

    result = irot_hal_get_id2(id2, len);
    if(result == IROT_ERROR_ITEM_NOT_FOUND) {
        return KM_ERR_ITEM_NOT_FOUND;
    } else if (result != IROT_SUCCESS) {
        return KM_ERR_GENERIC;
    }

    return KM_SUCCESS;
}

#if (CONFIG_CHIP_KEY_TYPE == CHIP_KEY_TYPE_3DES || \
     CONFIG_CHIP_KEY_TYPE == CHIP_KEY_TYPE_AES  || \
     CONFIG_CHIP_KEY_TYPE == CHIP_KEY_TYPE_SM1  || \
     CONFIG_CHIP_KEY_TYPE == CHIP_KEY_TYPE_SM4)
uint32_t km_cipher(const char* name, uint32_t name_len,
                   km_sym_param* cipher_params,
                   uint8_t* iv, uint32_t iv_len,
                   uint8_t* src, size_t src_len, uint8_t* dest, size_t* dest_len)
{
    km_block_mode_type block_mode = cipher_params->cipher_param.block_mode;
    km_padding_type padding_type = cipher_params->cipher_param.padding_type;
    km_purpose_type purpose_type = cipher_params->cipher_param.purpose_type;
    sym_crypto_param_t sym_param;
    irot_result_t result;
    uint32_t out_len;
    uint32_t km_ret;

    km_ret = _check_km_key_name(name, name_len);
    if (km_ret != KM_SUCCESS) {
        chip_log_error("name is not match, %s\n", name);
        return km_ret;
    }

    if (block_mode != KM_ECB || padding_type != KM_NO_PADDING) {
        chip_log_error("bad block_mode(%d) or padding_type(%d)\n", block_mode, padding_type);
        return KM_ERR_BAD_PARAMS;
    }

    sym_param.block_mode = BLOCK_MODE_ECB;
    sym_param.padding_type = SYM_PADDING_NOPADDING;

    if (purpose_type == KM_PURPOSE_ENCRYPT) {
        sym_param.mode = MODE_ENCRYPT;
    } else if (purpose_type == KM_PURPOSE_DECRYPT) {
        sym_param.mode = MODE_DECRYPT;
    } else {
        chip_log_error("bad purpose type, %d\n", purpose_type);
        return KM_ERR_BAD_PARAMS;
    }

    out_len = *dest_len;
    result = irot_hal_sym_crypto(NULL, KEY_ID_ID2, NULL, 0,
                  src, src_len, dest, &out_len, &sym_param);
    if (result != IROT_SUCCESS) {
        return KM_ERR_GENERIC;
    }

    *dest_len = out_len;

    return KM_SUCCESS;
}

#elif (CONFIG_CHIP_KEY_TYPE == CHIP_KEY_TYPE_RSA)

uint32_t km_sign(const char* name, uint32_t name_len,
                 km_sign_param* sign_params,
                 uint8_t* digest, uint32_t digest_len,
                 uint8_t* signature, uint32_t* signature_len)
{
    km_sign_param* km_params = sign_params;
    asym_sign_verify_t type;
    irot_result_t result;
    uint32_t km_ret;

    km_ret = _check_km_key_name(name, name_len);
    if (km_ret != KM_SUCCESS) {
        chip_log_error("name is not match, %s\n", name);
        return km_ret;
    }

    if (km_params->padding_type != KM_PKCS1) {
        return KM_ERR_BAD_PARAMS;
    }

    if (km_params->digest_type == KM_SHA1) {
        type = ASYM_TYPE_RSA_SHA1_PKCS1;
    } else if (km_params->digest_type == KM_SHA256) {
        type = ASYM_TYPE_RSA_SHA256_PKCS1;
    } else {
        return KM_ERR_BAD_PARAMS;
    }

    result = irot_hal_asym_priv_sign(NULL, 0,
                  digest, digest_len, signature, signature_len, type);
    if (result != IROT_SUCCESS) {
        return KM_ERR_GENERIC;
    }

    return KM_SUCCESS;
}

uint32_t km_asym_decrypt(const char* name, uint32_t name_len,
                         km_enc_param* enc_params,
                         uint8_t* src, uint32_t src_len,
                         uint8_t* dest, uint32_t* dest_len)
{
    irot_result_t result;
    uint32_t km_ret;

    km_ret = _check_km_key_name(name, name_len);
    if (km_ret != KM_SUCCESS) {
        chip_log_error("name is not match, %s\n", name);
        return km_ret;
    }

    if (enc_params->padding_type != KM_PKCS1) {
        chip_log_error("bad padding type, %d\n", enc_params->padding_type);
        return KM_ERR_BAD_PARAMS;
    }

    result = irot_hal_asym_priv_decrypt(NULL, 0,
                  src, src_len, dest, dest_len, ASYM_PADDING_PKCS1);
    if (result != IROT_SUCCESS) {
        return KM_ERR_GENERIC;
    }

    return KM_SUCCESS;
}

uint32_t km_verify(const char *name, uint32_t name_len,
               km_sign_param *sign_params,
               const uint8_t *digest, uint32_t digest_len,
               const uint8_t *signature, uint32_t signature_len)
{
    return KM_ERR_NOT_SUPPORTED;
}

uint32_t km_asym_encrypt(const char *name, uint32_t name_len,
                         km_enc_param *enc_params,
                         uint8_t *src, uint32_t src_len,
                         uint8_t *dest, uint32_t *dest_len)
{
    return KM_ERR_NOT_SUPPORTED;
}

#elif (CONFIG_CHIP_KEY_TYPE == CHIP_KEY_TYPE_SM2)

uint32_t km_msg_sign(const char* name, uint32_t name_len,
                km_sign_param* sign_params,
                uint8_t *id, size_t id_len,
                uint8_t* msg, size_t msg_len,
                uint8_t* signature, uint32_t* signature_len)
{
    km_sign_param* km_params = sign_params;
    asym_sign_verify_t type;
    irot_result_t result;
    uint32_t km_ret;
    char *fix_id = "1234567812345678";

    km_ret = _check_km_key_name(name, name_len);
    if (km_ret != KM_SUCCESS) {
        chip_log_error("name is not match, %s\n", name);
        return km_ret;
    }

    if (km_params->padding_type != KM_NO_PADDING) {
        return KM_ERR_BAD_PARAMS;
    }

    if (km_params->digest_type == KM_SM3) {
        type = ASYM_TYPE_SM2_SM3;
    } else {
        return KM_ERR_BAD_PARAMS;
    }

    if (id_len != strlen(fix_id) || memcmp(id, fix_id, id_len)) {
        chip_log_error("user id is not correct, %s\n", id);
        return KM_ERR_BAD_PARAMS;
    }

    result = irot_hal_asym_priv_sign(NULL, 0,
                  msg, msg_len, signature, signature_len, type);
    if (result != IROT_SUCCESS) {
        return KM_ERR_GENERIC;
    }

    return KM_SUCCESS;
}

uint32_t km_asym_decrypt(const char* name, uint32_t name_len,
                         km_enc_param* enc_params,
                         uint8_t* src, uint32_t src_len,
                         uint8_t* dest, uint32_t* dest_len)
{
    irot_result_t result;
    uint32_t km_ret;

    km_ret = _check_km_key_name(name, name_len);
    if (km_ret != KM_SUCCESS) {
        chip_log_error("name is not match, %s\n", name);
        return km_ret;
    }

    if (enc_params->padding_type != KM_NO_PADDING) {
        chip_log_error("bad padding type, %d\n", enc_params->padding_type);
        return KM_ERR_BAD_PARAMS;
    }

    result = irot_hal_asym_priv_decrypt(NULL, 0,
                  src, src_len, dest, dest_len, ASYM_PADDING_NOPADDING);
    if (result != IROT_SUCCESS) {
        return KM_ERR_GENERIC;
    }

    return KM_SUCCESS;
}

uint32_t km_msg_verify(const char *name, uint32_t name_len,
                       km_sign_param *sign_params,
                       uint8_t *id, size_t id_len,
                       uint8_t *msg, size_t msg_len,
                       uint8_t *signature, uint32_t signature_len)
{
    return KM_ERR_NOT_SUPPORTED;
}

uint32_t km_asym_encrypt(const char *name, uint32_t name_len,
                         km_enc_param *enc_params,
                         uint8_t *src, uint32_t src_len,
                         uint8_t *dest, uint32_t *dest_len)
{
    return KM_ERR_NOT_SUPPORTED;
}

#endif  /* CONFIG_CHIP_KEY_TYPE */

uint32_t km_set_id2(uint8_t* id2, uint32_t len)
{
    return KM_ERR_NOT_SUPPORTED;
}

uint32_t km_generate_key(const char *name, uint32_t name_len,
                         km_gen_param_t *arg)
{
    return KM_ERR_NOT_SUPPORTED;
}

uint32_t km_import_key(const char* name, uint32_t name_len,
             km_format_t format, const km_key_data_t* key_data, const uint32_t key_data_len)
{
    return KM_ERR_NOT_SUPPORTED;
}

uint32_t km_get_attestation(uint8_t* id, uint32_t* id_len)
{
    return KM_ERR_NOT_SUPPORTED;
}

uint32_t km_delete_key(const char *name, uint32_t name_len)
{
    return KM_ERR_NOT_SUPPORTED;
}

uint32_t km_envelope_begin(void **ctx, const char *name, uint32_t name_len,
        uint8_t *iv, uint32_t iv_len,
        uint8_t *protected_key, uint32_t *protected_key_len, km_purpose_type is_enc)
{
    return KM_ERR_NOT_SUPPORTED;
}

uint32_t km_envelope_update(void *ctx, uint8_t *src, size_t src_len,
        uint8_t *dest, size_t *dest_len)
{
    return KM_ERR_NOT_SUPPORTED;
}

uint32_t km_envelope_finish(void *ctx, uint8_t *src, size_t src_len,
        uint8_t *dest, size_t *dest_len)
{
    return KM_ERR_NOT_SUPPORTED;
}

uint32_t km_set_id2_state(uint32_t state)
{
    return KM_ERR_NOT_SUPPORTED;
}

uint32_t km_get_id2_state(uint32_t *state)
{
    return KM_ERR_NOT_SUPPORTED;
}

uint32_t km_id2_dkey_encrypt(const uint8_t *in, uint32_t in_len, uint8_t *out, uint32_t *out_len)
{
    return KM_ERR_NOT_SUPPORTED;
}

