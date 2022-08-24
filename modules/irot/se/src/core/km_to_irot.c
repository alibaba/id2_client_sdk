/*
 * Copyright (C) 2015-2017 Alibaba Group Holding Limited
 */

#include <string.h>
#include "km.h"
#include "irot_hal.h"
#include "chip_log.h"
#include "chip_config.h"
#include "se_key_list.h"

#define INDEX_NAME_MAGIC "ID2IntStr_"
#define INDEX_NAME_MAGIC_LEN 10

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

/* "0123456789ABCDEF" -> 0, 1, 2, ... */
static int char_to_hex(char c)
{
    int hex = -1;

    if (c >= '0' && c <= '9') {
        hex = c - '0';
    } else if (c >= 'a' && c <= 'f') {
        hex = c - 'a' + 10;
    } else if (c >= 'A' && c <= 'F') {
        hex = c - 'A' + 10;
    }

    return hex;
}

static uint32_t _get_key_id(const char* name, uint32_t name_len, uint8_t *key_id)
{
    uint32_t i = 0;
    uint32_t key_num = sizeof(key_list) / sizeof(key_index_t);

    if (!name || !key_id) {
        chip_log_error("null parameters\n");
        return KM_ERR_BAD_PARAMS;
    }

    //key index passed by user
    if (!memcmp(name, INDEX_NAME_MAGIC, INDEX_NAME_MAGIC_LEN)) {
        if (INDEX_NAME_MAGIC_LEN + 2 != name_len) {
            chip_log_error("invalid key name %s\n", name);
            return KM_ERR_BAD_PARAMS;
        }
        *key_id = (char_to_hex(name[INDEX_NAME_MAGIC_LEN]) << 4) +
                   char_to_hex(name[INDEX_NAME_MAGIC_LEN + 1]);
        return KM_SUCCESS;
    }

    //use system reserved key index
    for (i = 0; i < key_num; i++) {
        if (!strcmp(name, key_list[i].key_name)) {
            *key_id = key_list[i].key_id;
            return KM_SUCCESS;
        }
    }

    chip_log_error("not supported key name %s\n", name);

    return KM_ERR_BAD_PARAMS;
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

uint32_t km_get_irot_type(void)
{
    return KM_IROT_TYPE_SE;
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
    uint8_t key_id = 0;

    km_ret = _get_key_id(name, name_len, &key_id);
    if (km_ret != KM_SUCCESS) {
        chip_log_error("name is not match, %s\n", name);
        return km_ret;
    }

    if (block_mode != KM_ECB || padding_type != KM_NO_PADDING) {
        chip_log_error("bad block_mode(%d) or padding_type(%d)\n", block_mode, padding_type);
        return KM_ERR_BAD_PARAMS;
    }

    if (cipher_params->key_type == KM_AES) {
        sym_param.key_type = HAL_KEY_TYPE_AES;
    } else if (cipher_params->key_type == KM_DES) {
        sym_param.key_type = HAL_KEY_TYPE_DES;
    } else if (cipher_params->key_type == KM_DES3) {
        sym_param.key_type = HAL_KEY_TYPE_DES3;
    } else if (cipher_params->key_type == KM_SM4) {
        sym_param.key_type = HAL_KEY_TYPE_SM4;
    } else {
        chip_log_error("not support key_type %d\n", sym_param.key_type);
        return KM_ERR_NOT_SUPPORTED;
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
    result = irot_hal_sym_crypto(NULL, key_id, NULL, 0,
                  src, src_len, dest, &out_len, &sym_param);
    if (result != IROT_SUCCESS) {
        chip_log_error("irot_hal_sym_crypto failed %d\n", result);
        return KM_ERR_GENERIC;
    }

    *dest_len = out_len;

    return KM_SUCCESS;
}

uint32_t km_sign(const char* name, uint32_t name_len,
                 km_sign_param* sign_params,
                 uint8_t* digest, uint32_t digest_len,
                 uint8_t* signature, uint32_t* signature_len)
{
    return KM_ERR_NOT_SUPPORTED;
}

uint32_t km_asym_decrypt(const char* name, uint32_t name_len,
                         km_enc_param* enc_params,
                         uint8_t* src, uint32_t src_len,
                         uint8_t* dest, uint32_t* dest_len)
{
    irot_result_t result;
    uint32_t km_ret;
    uint8_t key_id = 0;
    irot_asym_padding_t padding_type;

    km_ret = _get_key_id(name, name_len, &key_id);
    if (km_ret != KM_SUCCESS) {
        chip_log_error("name is not match, %s\n", name);
        return km_ret;
    }

    if (enc_params->key_type == KM_RSA) {
        if (enc_params->padding_type != KM_PKCS1) {
            chip_log_error("bad padding type, %d\n", enc_params->padding_type);
            return KM_ERR_BAD_PARAMS;
    }
        padding_type = ASYM_RSA_PADDING_PKCS1;
    } else if (enc_params->key_type == KM_SM2) {
        if (enc_params->padding_type != KM_NO_PADDING) {
            chip_log_error("bad padding type, %d\n", enc_params->padding_type);
            return KM_ERR_BAD_PARAMS;
    }
        padding_type = ASYM_SM2_NOPADDING;
    } else {
        chip_log_error("not support key type %d\n", enc_params->key_type);
        return KM_ERR_NOT_SUPPORTED;
    }

    result = irot_hal_asym_priv_decrypt(NULL, key_id,
                  src, src_len, dest, dest_len, padding_type);
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
    uint8_t key_id = 0;

    km_ret = _get_key_id(name, name_len, &key_id);
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

    result = irot_hal_asym_priv_sign(NULL, key_id,
                  msg, msg_len, signature, signature_len, type);
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

uint32_t km_import_keyring(const char *name, uint32_t name_len,
                       km_keyring_t *keyring)
{
    uint32_t ret = 0;
    hal_keyring_t hal_keyring;
    int hal_ret = 0;
    uint8_t key_id = 0;

    if (!name || !name_len || !keyring) {
        chip_log_error("invalid parameters\n");
        return KM_ERR_BAD_PARAMS;
    }

    ret = _get_key_id(name, name_len, &key_id);
    if (ret != KM_SUCCESS) {
        chip_log_error("name is not match, %s\n", name);
        return ret;
    }

    if (keyring->key_type == KM_AES) {
        hal_keyring.key_type = HAL_KEY_TYPE_AES;
    } else if (keyring->key_type == KM_SM4) {
        hal_keyring.key_type = HAL_KEY_TYPE_SM4;
    } else {
        return KM_ERR_NOT_SUPPORTED;
    }

    hal_keyring.key_bit = keyring->key_bit;
    hal_keyring.payload_len = keyring->payload_len;
    hal_keyring.payload = keyring->payload;

    hal_ret = irot_hal_import_keyring(key_id, &hal_keyring);
    if (hal_ret != IROT_SUCCESS) {
        chip_log_error("irot hal import keyring failed %d\n", hal_ret);
        return KM_ERR_GENERIC;
    }

    return KM_SUCCESS;
}

uint32_t km_get_prov_state(const char *name, uint32_t name_len, uint32_t *state)
{
    uint32_t ret = 0;
    uint8_t key_id = 0;
    int hal_ret = 0;

    if (!name || !name_len || !state) {
        chip_log_error("invalid parameters\n");
        return KM_ERR_BAD_PARAMS;
    }

    ret = _get_key_id(name, name_len, &key_id);
    if (ret != KM_SUCCESS) {
        chip_log_error("name is not match, %s\n", name);
        return ret;
    }

    hal_ret = irot_hal_get_prov_state(key_id, state);
    if (hal_ret) {
        chip_log_error("hal get prov state failed %d\n", hal_ret);
        return KM_ERR_NOT_SUPPORTED;
    }

    return KM_SUCCESS;
}

uint32_t km_get_key_type(const char *name, uint32_t name_len, km_key_type *key_type)
{
    int ret = 0;
    uint32_t km_ret = 0;
    uint8_t key_id = 0;
    hal_key_type_t type;

    if (!name || !name_len || !key_type) {
        chip_log_error("invalid parameters\n");
        return KM_ERR_BAD_PARAMS;
    }

    km_ret = _get_key_id(name, name_len, &key_id);
    if (km_ret != KM_SUCCESS) {
        chip_log_error("name is not match, %s\n", name);
        return km_ret;
    }

    ret = irot_hal_get_key_type(key_id, &type);
    if (ret == IROT_ERROR_ITEM_NOT_FOUND) {
        return KM_ERR_ITEM_NOT_FOUND;
    } else if (ret) {
        return KM_ERR_GENERIC;
    }

    if (type == HAL_KEY_TYPE_AES) {
        *key_type = KM_AES;
    } else if (type == HAL_KEY_TYPE_DES) {
        *key_type = KM_DES;
    } else if (type == HAL_KEY_TYPE_DES3) {
        *key_type = KM_DES3;
    } else if (type == HAL_KEY_TYPE_SM4) {
        *key_type = KM_SM4;
    } else if (type == HAL_KEY_TYPE_RSA) {
        *key_type = KM_RSA;
    } else if (type == HAL_KEY_TYPE_ECC) {
        *key_type = KM_ECC;
    } else if (type == HAL_KEY_TYPE_SM2) {
        *key_type = KM_SM2;
    } else {
        return KM_ERR_GENERIC;
    }

    return KM_SUCCESS;
}

uint32_t km_get_attestation(uint8_t* id, uint32_t* id_len)
{
    return KM_ERR_NOT_SUPPORTED;
}

uint32_t km_delete_key(const char *name, uint32_t name_len)
{
    int ret = 0;
    uint8_t key_id = 0;
    uint32_t km_ret = 0;

    if (!name || !name_len) {
        chip_log_error("invalid parameters\n");
        return KM_ERR_BAD_PARAMS;
    }

    km_ret = _get_key_id(name, name_len, &key_id);
    if (km_ret != KM_SUCCESS) {
        chip_log_error("name is not match, %s\n", name);
        return km_ret;
    }

    ret = irot_hal_delete_key(key_id);
    if (ret) {
        chip_log_error("hal delete key %d failed %d\n", key_id, ret);
        return KM_ERR_GENERIC;
    }

    return KM_SUCCESS;
}

uint32_t km_export_key(const char *name, uint32_t name_len, km_format_t format,
                   uint8_t *export_data, size_t *export_data_len)
{
    return KM_ERR_NOT_SUPPORTED;
}

uint32_t km_mac(const char *name, uint32_t name_len, km_sym_param *mac_params,
        uint8_t *iv, uint32_t iv_len, uint8_t *src, size_t src_len,
        uint8_t *mac, uint32_t *mac_len)
{
    return KM_ERR_NOT_SUPPORTED;
}

uint32_t km_delete_all(void)
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

uint32_t km_generate_key_blob(km_gen_param_t *arg, uint8_t *key_blob, uint32_t *key_blob_len)
{
    return KM_ERR_NOT_SUPPORTED;
}

uint32_t km_import_key_blob(km_format_t format,
                   const km_key_data_t *key_data, uint32_t key_data_len,
                   uint8_t *key_blob, uint32_t *key_blob_len)
{
    return KM_ERR_NOT_SUPPORTED;
}

uint32_t km_blob_export_key(uint8_t *blob, uint32_t key_blob_len, km_format_t format,
                   uint8_t *export_data, size_t *export_data_size)
{
    return KM_ERR_NOT_SUPPORTED;
}

uint32_t km_blob_mac(uint8_t *key_blob, uint32_t key_blob_len, km_sym_param *mac_params,
        uint8_t *iv, uint32_t iv_len, uint8_t *src, size_t src_len,
        uint8_t *mac, uint32_t *mac_len)
{
    return KM_ERR_NOT_SUPPORTED;
}

uint32_t km_blob_msg_sign(uint8_t *key_blob, uint32_t key_blob_len,
        km_sign_param *sign_params,
        uint8_t *id, size_t id_len,
        uint8_t *msg, size_t msg_len,
        uint8_t *signature, uint32_t *signature_len)
{
    return KM_ERR_NOT_SUPPORTED;
}
uint32_t km_blob_msg_verify(uint8_t *key_blob, uint32_t key_blob_len,
        km_sign_param *sign_params,
        uint8_t *id, size_t id_len,
        uint8_t *msg, size_t msg_len,
        uint8_t *signature, uint32_t signature_len)
{
    return KM_ERR_NOT_SUPPORTED;
}

uint32_t km_blob_sign(uint8_t *key_blob, uint32_t key_blob_len,
             km_sign_param *sign_params,
             uint8_t *digest, uint32_t digest_len,
             uint8_t *signature, uint32_t *signature_len)
{
    return KM_ERR_NOT_SUPPORTED;
}

uint32_t km_blob_verify(uint8_t *key_blob, uint32_t key_blob_len,
               km_sign_param *sign_params,
               const uint8_t *digest, uint32_t digest_len,
               const uint8_t *signature, uint32_t signature_len)
{
    return KM_ERR_NOT_SUPPORTED;
}

uint32_t km_blob_asym_encrypt(uint8_t *key_blob, uint32_t key_blob_len, km_enc_param *enc_params,
                uint8_t *src, uint32_t src_len,
             uint8_t *dest, uint32_t *dest_len)
{
    return KM_ERR_NOT_SUPPORTED;
}

uint32_t km_blob_asym_decrypt(uint8_t *key_blob, uint32_t key_blob_len, km_enc_param *enc_params,
                uint8_t *src, uint32_t src_len,
               uint8_t *dest, uint32_t *dest_len)
{
    return KM_ERR_NOT_SUPPORTED;
}

uint32_t km_blob_cipher(uint8_t *key_blob, uint32_t key_blob_len, km_sym_param *cipher_params,
        uint8_t *iv, uint32_t iv_len, uint8_t *src, size_t src_len,
        uint8_t *dest, size_t *dest_len)
{
    return KM_ERR_NOT_SUPPORTED;
}

