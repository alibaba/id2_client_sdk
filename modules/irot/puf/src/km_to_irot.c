/*
 * Copyright (C) 2015-2017 Alibaba Group Holding Limited
 */

#include "km.h"
#include "irot_hal.h"
#include "chip_log.h"
#include "chip_util.h"

static uint32_t s_curve_size = 0;

static void _dump_chip_conf_info()
{
#if defined(CONFIG_CHIP_DEBUG)
    chip_log_info("CONFIG_CHIP_DEBUG is defined!\n");
#else
    chip_log_info("CONFIG_CHIP_DEBUG is not defined!\n");
#endif

#if (CONFIG_CHIP_KEY_TYPE == CHIP_KEY_TYPE_ECC)
    chip_log_info("CONFIG_CHIP_KEY_TYPE: %s\n", "CONFIG_CHIP_KEY_ECC");

#if (CONFIG_CHIP_ECDP_TYPE == CHIP_ECDP_TYPE_SECT163K1)
    chip_log_info("CONFIG_CHIP_ECDP_TYPE: %s\n", "---CHIP_ECDP_TYPE_SECT163K1");
    s_curve_size = 21;
#elif (CONFIG_CHIP_ECDP_TYPE == CHIP_ECDP_TYPE_SECT233K1)
    chip_log_info("CONFIG_CHIP_ECDP_TYPE: %s\n", "CHIP_ECDP_TYPE_SECT233K1");
    s_curve_size = 30;
#elif (CONFIG_CHIP_ECDP_TYPE == CHIP_ECDP_TYPE_SECT283K1)
    chip_log_info("CONFIG_CHIP_ECDP_TYPE: %s\n", "CHIP_ECDP_TYPE_SECT283K1");
    s_curve_size = 36;
#elif (CONFIG_CHIP_ECDP_TYPE == CHIP_ECDP_TYPE_SECP192K1)
    chip_log_info("CONFIG_CHIP_ECDP_TYPE: %s\n", "CHIP_ECDP_TYPE_SECP192K1");
    s_curve_size = 24;
#elif (CONFIG_CHIP_ECDP_TYPE == CHIP_ECDP_TYPE_SECP224K1)
    chip_log_info("CONFIG_CHIP_ECDP_TYPE: %s\n", "CHIP_ECDP_TYPE_SECP224K1");
    s_curve_size = 28;
#elif (CONFIG_CHIP_ECDP_TYPE == CHIP_ECDP_TYPE_SECP256K1)
    chip_log_info("CONFIG_CHIP_ECDP_TYPE: %s\n", "CHIP_ECDP_TYPE_SECP256K1");
    s_curve_size = 32;
#endif

#endif

    chip_log_info("========================================\n");
}

uint32_t km_init(void)
{
    int ret;

    _dump_chip_conf_info();

    ret = irot_hal_init();
    if (ret < 0) {
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
    int ret;
    uint8_t tmp_buf[ID2_ID_SLEN_LEN];
    uint8_t *pos;
    uint32_t tmp_len;

    ret = irot_hal_get_id2(id2, len);
    if (ret < 0) {
        return KM_ERR_GENERIC;
    }

    if (memcmp(id2, ID2_ID_VERSION, ID2_ID_VERS_LEN)) {
        chip_log_error("invalid id version, %s\n", id2);
        return KM_ERR_GENERIC;
    }

    /* jump to uid_len position */
    pos = id2 + ID2_ID_VERS_LEN + ID2_ID_VEND_LEN + ID2_ID_RSVD_LEN;

    tmp_len = ID2_ID_SLEN_LEN;
    ret = chip_string_to_hex((char *)pos, ID2_ID_SLEN_LEN, tmp_buf, &tmp_len);
    if (ret < 0) {
        chip_log_error("chip_string_to_hex fail\n");
        return KM_ERR_GENERIC;
    }

    tmp_len = *len - (pos - id2) - ID2_ID_SLEN_LEN;
    if (tmp_len != tmp_buf[0]) {
        chip_log_error("invalid chip uid len, %d %d\n", tmp_len, tmp_buf[0]);
        return KM_ERR_GENERIC;
    }

    return KM_SUCCESS;
}

#if (CONFIG_CHIP_KEY_TYPE == CHIP_KEY_TYPE_ECC)

uint32_t km_msg_sign(const char *name, uint32_t name_len,
                     km_sign_param *sign_params,
                     uint8_t *id, size_t id_len,
                     uint8_t *msg, size_t msg_len,
                     uint8_t* sign, uint32_t* sign_len)
{
    int ret = 0;

    if (sign_params == NULL ||
        msg == NULL || msg_len == 0 ||
        sign == NULL || sign_len == NULL) {
        chip_log_error("invalid input args\n");
        return KM_ERR_BAD_PARAMS;
    }

    if (sign_params->digest_type != KM_SHA256) {
        chip_log_error("invalid digest type, %d\n", sign_params->digest_type);
        return KM_ERR_BAD_PARAMS;
    }

    ret = irot_hal_id2_sign(msg, msg_len, sign, sign_len);
    if (ret < 0) {
        chip_log_error("irot_hal_id2_sign fail\n");
        return KM_ERR_GENERIC;
    }

    if (*sign_len != 2 * s_curve_size) {
        chip_log_error("invalid sign length, %d %d\n", *sign_len, 2 * s_curve_size);
        return KM_ERR_GENERIC;
    }

    return KM_SUCCESS;
}

uint32_t km_msg_verify(const char *name, uint32_t name_len,
                       km_sign_param *sign_params,
                       uint8_t *id, size_t id_len,
                       uint8_t *msg, size_t msg_len,
                       uint8_t *sign, uint32_t sign_len)
{
    int ret = 0;

    if (sign_params == NULL ||
        msg == NULL || msg_len == 0 || sign == NULL || sign_len == 0) {
        chip_log_error("invalid input args\n");
        return KM_ERR_BAD_PARAMS;
    }

    if (sign_params->digest_type != KM_SHA256) {
        chip_log_error("invalid digest type, %d\n", sign_params->digest_type);
        return KM_ERR_BAD_PARAMS;
    }

    if (sign_len != 2 * s_curve_size) {
        chip_log_error("invalid sign length, %d %d\n", sign_len, 2 * s_curve_size);
        return KM_ERR_GENERIC;
    }

    ret = irot_hal_id2_verify(msg, (uint32_t)msg_len, sign, sign_len);
    if (ret < 0) {
        chip_log_error("irot_hal_id2_verify fail\n");
        return KM_ERR_GENERIC;
    }

    return KM_SUCCESS;
}

uint32_t km_asym_encrypt(const char *name, uint32_t name_len,
                         km_enc_param *enc_params,
                         uint8_t *src, uint32_t src_len,
                         uint8_t *dest, uint32_t *dest_len)
{
    int ret = 0;

    if (enc_params == NULL ||
        src == NULL || src_len == 0 || dest == NULL || dest_len == NULL) {
        chip_log_error("invalid input args\n");
        return KM_ERR_BAD_PARAMS;
    }

    if (enc_params->padding_type != KM_NO_PADDING) {
        chip_log_error("invalid padding type, %d\n", enc_params->padding_type);
        return KM_ERR_BAD_PARAMS;
    }

    ret = irot_hal_id2_encrypt(src, src_len, dest, dest_len);
    if (ret < 0) {
        chip_log_error("irot_hal_id2_encrypt fail\n");
        return KM_ERR_GENERIC;
    }

    return KM_SUCCESS;
}

uint32_t km_asym_decrypt(const char* name, uint32_t name_len,
                         km_enc_param  *enc_params,
                         uint8_t* src, uint32_t src_len,
                         uint8_t* dest, uint32_t* dest_len)
{
    int ret = 0;

    if (enc_params == NULL ||
        src == NULL || src_len == 0 || dest == NULL || dest_len == NULL) {
        chip_log_error("invalid input args\n");
        return KM_ERR_BAD_PARAMS;
    }

    if (enc_params->padding_type != KM_NO_PADDING) {
        chip_log_error("invalid padding type, %d\n", enc_params->padding_type);
        return KM_ERR_BAD_PARAMS;
    }

    ret = irot_hal_id2_decrypt(src, src_len, dest, dest_len);
    if (ret < 0) {
        chip_log_error("irot_hal_id2_decrypt fail\n");
        return KM_ERR_GENERIC;
    }

    return KM_SUCCESS;
}

#endif  /* CONFIG_CHIP_KEY_TYPE_ECC */

uint32_t km_cipher(const char* name, uint32_t name_len,
                   km_sym_param* cipher_params,
                   uint8_t* iv, uint32_t iv_len,
                   uint8_t* src, size_t src_len, uint8_t* dest, size_t* dest_len)
{
    return KM_ERR_NOT_SUPPORTED;
}

uint32_t km_set_id2(uint8_t* id2, uint32_t len)
{
    return KM_ERR_NOT_SUPPORTED;
}


uint32_t km_generate_key(const char *name, uint32_t name_len, km_gen_param_t *arg)
{
    return KM_ERR_NOT_SUPPORTED;
}

uint32_t km_import_key(const char* name, uint32_t name_len,
             km_format_t format, const km_key_data_t* key_data, uint32_t key_data_len)
{
    return KM_ERR_NOT_SUPPORTED;
}

uint32_t km_get_attestation(uint8_t* id, uint32_t* id_len)
{
    return KM_ERR_NOT_SUPPORTED;
}

uint32_t km_delete_key(const char *name, const uint32_t name_len)
{
    return KM_ERR_NOT_SUPPORTED;
}

uint32_t km_envelope_begin(void **ctx, const char *name, uint32_t name_len,
        uint8_t *iv, uint32_t iv_len,
        uint8_t *protected_key, uint32_t *protected_key_len, km_purpose_type purpose)
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

