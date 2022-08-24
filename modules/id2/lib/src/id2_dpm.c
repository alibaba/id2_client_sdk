/*
 * Copyright (C) 2020-2022 Alibaba Group Holding Limited
 */

#include "id2_config.h"
#include "id2_plat.h"
#include "id2_priv.h"
#include "id2_client_dpm.h"

#include "ali_crypto.h"

#define ID2_DPM_OTP_MSG_LEN     10
#define ID2_DPM_OTP_KEY_LEN     64

#define ID2_DPM_MAX_INDEX_SIZE  100

#define ID2_DPM_SHA256_SIZE         32
#define ID2_DPM_SHA256_BLOCK_SIZE   64

static irot_result_t  _dpm_hmac_sha256(
                           uint8_t *key, uint32_t key_len,
                           uint8_t *input, uint32_t ilen, uint8_t *output)
{
    ali_crypto_result result;
    size_t size;
    void *hash_ctx = NULL;
    uint8_t ipad[ID2_DPM_SHA256_BLOCK_SIZE];
    uint8_t opad[ID2_DPM_SHA256_BLOCK_SIZE];
    uint8_t hash[ID2_DPM_SHA256_SIZE];
    uint32_t i = 0;

    if (key == NULL || key_len == 0 ||
        input == NULL || ilen == 0 || output == NULL) {
        id2_log_error("invalid input args\n");
        return IROT_ERROR_BAD_PARAMETERS;
    }

    if (key_len > ID2_DPM_SHA256_BLOCK_SIZE) {
        id2_log_error("not support key length, %d\n", key_len);
        return IROT_ERROR_NOT_SUPPORTED;
    }

    memset(ipad, 0x36, ID2_DPM_SHA256_BLOCK_SIZE);
    memset(opad, 0x5C, ID2_DPM_SHA256_BLOCK_SIZE);

    for (i = 0; i < key_len; i++) {
        ipad[i] = ipad[i] ^ key[i];
        opad[i] = opad[i] ^ key[i];
    }

    result = ali_sha256_get_ctx_size(&size);
    if (result != ALI_CRYPTO_SUCCESS) {
        id2_log_error("get hash ctx size fail, %d\n", result);
        return IROT_ERROR_GENERIC;
    }

    hash_ctx = ls_osa_malloc(size);
    if (hash_ctx == NULL) {
        id2_log_error("out of mem, %d\n", size);
        return IROT_ERROR_OUT_OF_MEMORY;
    }

    ali_sha256_init(hash_ctx);
    ali_sha256_update(ipad, ID2_DPM_SHA256_BLOCK_SIZE, hash_ctx);
    ali_sha256_update(input, ilen, hash_ctx);
    ali_sha256_final(hash, hash_ctx);

    /* reset context */
    memset(hash_ctx, 0, size);

    ali_sha256_init(hash_ctx);
    ali_sha256_update(opad, ID2_DPM_SHA256_BLOCK_SIZE, hash_ctx);
    ali_sha256_update(hash, ID2_DPM_SHA256_SIZE, hash_ctx);
    ali_sha256_final(output, hash_ctx);

    ls_osa_free(hash_ctx);

    return IROT_SUCCESS;
}

static irot_result_t _dpm_otp_obf_enc(uint8_t *data, uint32_t len, uint32_t idx)
{
    uint32_t i, tmp;
    uint32_t mid_h, mid_l;
    uint32_t idx_h, idx_l;

    if (data == NULL || len <= 2) {
        id2_log_error("invalid input args\n");
        return IROT_ERROR_BAD_PARAMETERS;
    }

    /* XOR data[0:len-2] */
    tmp = data[0];
    for (i = 1; i < len - 2; i++) {
        tmp = tmp ^ data[i];
    }

    mid_h = (tmp) % 10;
    mid_l = (tmp + mid_h) % 10;

    idx_h = idx / 10;
    idx_l = idx % 10;

    if (mid_h >= idx_h) {
        data[len - 2] = mid_h - idx_h + '0';
    } else {
        data[len - 2] = mid_h - idx_h + 10 + '0';
    }

    if (mid_l >= idx_l) {
        data[len - 1] = mid_l - idx_l + '0';
    } else {
        data[len - 1] = mid_l - idx_l + 10 + '0';
    }

    return IROT_SUCCESS;
}

static irot_result_t _dpm_otp_obf_dec(uint8_t *data, uint32_t len, uint32_t *idx)
{
    uint32_t i, tmp;
    uint32_t mid_h, mid_l;
    uint32_t idx_h, idx_l;

    if (data == NULL || len <= 2 || idx == NULL) {
        id2_log_error("invalid input args\n");
        return IROT_ERROR_BAD_PARAMETERS;
    }

    /* XOR data[0:len-2] */
    tmp = data[0];
    for (i = 1; i < len - 2; i++) {
        tmp = tmp ^ data[i];
    }

    mid_h = (tmp) % 10;
    mid_l = (tmp + mid_h) % 10;

    if (mid_h >= data[len - 2] - '0') {
        idx_h = mid_h - data[len - 2] + '0';
    } else {
        idx_h = mid_h - data[len - 2] + 10 + '0';
    }

    if (mid_l >= data[len - 1] - '0') {
        idx_l = mid_l - data[len - 1] + '0';
    } else {
        idx_l = mid_l - data[len - 1] + 10 + '0';
    }

    *idx = idx_h * 10 + idx_l;

    return IROT_SUCCESS;
}

irot_result_t _dpm_generate_totp(uint8_t *key, uint32_t key_len,
                   uint8_t *msg, uint32_t msg_len, uint8_t *otp, uint32_t otp_len)
{
    irot_result_t result;
    uint8_t hash[ID2_DPM_SHA256_SIZE];
    uint32_t i = 0;
    uint32_t digits = 0;
    uint32_t offset = 0;
    uint64_t binary = 0;
    uint64_t module = 1;

    if (key == NULL || key_len == 0 ||
        msg == NULL || msg_len == 0 ||
        otp == NULL || otp_len == 0) {
        id2_log_error("invalid input args\n");
        return IROT_ERROR_BAD_PARAMETERS;
    }

    result = _dpm_hmac_sha256(key, key_len, msg, msg_len, hash);
    if (result != IROT_SUCCESS) {
        id2_log_error("dpm hmac-sha256 fail, %d\n", result);
        return result;
    }

    id2_log_hex_dump("hmac-sha:", hash, ID2_DPM_SHA256_SIZE);

    for (i = 0; i < otp_len; i++) {
        module = module * 10;
    }

    offset = hash[ID2_DPM_SHA256_SIZE - 1] & 0xf;

    /* specified calculate */
    binary = (((uint64_t)hash[offset] & 0x7f) << 56) |
	     (((uint64_t)hash[offset + 1] & 0xff) << 48) |
	     (((uint64_t)hash[offset + 2] & 0xff) << 40) |
	     (((uint64_t)hash[offset + 3] & 0xff) << 32) |
	     (((uint64_t)hash[offset + 4] & 0xff) << 24) |
	     (((uint64_t)hash[offset + 5] & 0xff) << 16) |
	     (((uint64_t)hash[offset + 6] & 0xff) << 8)  |
	     (((uint64_t)hash[offset + 7] & 0xff));

    id2_log_debug("binary: 0x%llx %lld\n", binary, binary);
    id2_log_debug("module: %lld\n", module);

    binary = binary % module;

    digits = 1;
    module = 1;
    do {
       module = module * 10;
       if (binary / module != 0) {
           digits++;
       } else {
           break;
       }
    } while(1);

    memset(otp, '0', otp_len);
    for (i = 0; i < digits; i++) {
        otp[otp_len - 1 - i] = binary % 10  + '0';
        binary = binary / 10;
    }

    id2_log_debug("otp_orig: %s\n", otp);

    return IROT_SUCCESS;
}

irot_result_t id2_client_dpm_get_totp(uint64_t timestamp, uint32_t index,
                         uint32_t otp_step, uint32_t otp_len, uint8_t *otp_data)
{
    irot_result_t result;
    uint32_t i, len;
    uint64_t steps = 0;
    uint8_t msg[ID2_DPM_OTP_MSG_LEN] = {0};
    uint8_t key[ID2_DPM_OTP_KEY_LEN] = {0};
    uint8_t id2[ID2_ID_MAX_LEN + 1] = {0};

    if (!is_id2_client_inited()) {
        id2_log_error("id2 not inited.\n");
        return IROT_ERROR_GENERIC;
    }

    id2_log_debug("timestamp: %lld\n", timestamp);
    id2_log_debug("index: %d\n", index);
    id2_log_debug("otp_step: %d\n", otp_step);
    id2_log_debug("otp_len: %d\n", otp_len);

    if (timestamp == 0 || otp_data == NULL) {
        id2_log_error("invalid input args\n");
        return IROT_ERROR_BAD_PARAMETERS;
    }

    if (index >= ID2_DPM_MAX_INDEX_SIZE) {
        id2_log_error("invalid index, %d\n", index);
        return IROT_ERROR_BAD_PARAMETERS;
    }

    if (otp_step == 0) {
        otp_step = ID2_DPM_OTP_STEP_MIN_LEN;
    }

    if (otp_step < ID2_DPM_OTP_STEP_MIN_LEN ||
        otp_step > ID2_DPM_OTP_STEP_MAX_LEN) {
        id2_log_error("invalid otp step, %d\n", otp_step);
        return IROT_ERROR_BAD_PARAMETERS;
    }

    if (otp_len < ID2_DPM_OTP_DATA_MIN_LEN ||
        otp_len > ID2_DPM_OTP_DATA_MAX_LEN) {
        id2_log_error("invalid otp data length, %d\n", otp_len);
        return IROT_ERROR_BAD_PARAMETERS;
    }

    steps = timestamp / otp_step;

    /* generate otp message */
    for (i = 0; i < ID2_DPM_OTP_MSG_LEN - 2; i++) {
        msg[ID2_DPM_OTP_MSG_LEN - 2 - 1 - i] = (steps >> i * 8) & 0xFF;
    }
    msg[ID2_DPM_OTP_MSG_LEN - 2] = (index / 10) + '0';
    msg[ID2_DPM_OTP_MSG_LEN - 1] = (index % 10) + '0';

    id2_log_hex_dump("otp_msg", msg, ID2_DPM_OTP_MSG_LEN);

    /* generate otp share key, use id2 id as seed */
    len = ID2_ID_MAX_LEN;
    result = id2_client_get_id(id2, &len);
    if (result != IROT_SUCCESS) {
        id2_log_error("id2 get id fail, %d\n", result);
        return IROT_ERROR_GENERIC;
    }

    len = ID2_DPM_OTP_KEY_LEN;
    result = id2_client_get_secret((char *)id2, key, &len);
    if (result != IROT_SUCCESS) {
        id2_log_error("id2 get secret fail, %d\n", result);
        return result;
    }

    id2_log_debug("otp secret: %s\n", key);

    /* generate original time-base one-time password */
    result = _dpm_generate_totp(key, len,
                  msg, ID2_DPM_OTP_MSG_LEN, otp_data, otp_len - 2);
    if (result != IROT_SUCCESS) {
        id2_log_error("generate totp fail, %d\n", result);
        return result;
    }

    result = _dpm_otp_obf_enc(otp_data, otp_len, index);
    if (result != IROT_SUCCESS) {
        id2_log_error("otp obf encode fail, %d\n", result);
        return result;
    }

    id2_log_debug("otp_data: %s\n", otp_data);

    return IROT_SUCCESS;
}

irot_result_t id2_client_dpm_get_index(uint8_t *otp_data, uint32_t otp_len, uint32_t *index)
{
    irot_result_t result;

    if (!is_id2_client_inited()) {
        id2_log_error("id2 not inited.\n");
        return IROT_ERROR_GENERIC;
    }

    if (otp_data == NULL || index == NULL) {
        id2_log_error("invalid input args\n");
        return IROT_ERROR_BAD_PARAMETERS;
    }

    if (otp_len < ID2_DPM_OTP_DATA_MIN_LEN ||
        otp_len > ID2_DPM_OTP_DATA_MAX_LEN) {
        id2_log_error("invalid otp data length, %d\n", otp_len);
        return IROT_ERROR_BAD_PARAMETERS;
    }

    result = _dpm_otp_obf_dec(otp_data, otp_len, index);
    if (result != IROT_SUCCESS) {
        id2_log_error("otp obf decode fail, %d\n", result);
        return result;
    }

    return IROT_SUCCESS;
}

