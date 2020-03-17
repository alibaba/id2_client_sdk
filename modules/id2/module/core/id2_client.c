/*
 * Copyright (C) 2015-2017 Alibaba Group Holding Limited
 */

#include "id2_priv.h"
#include "id2_client.h"
#include "module/mdu_id2.h"

#define ID2_AUTH_CODE_BUF_LEN    256

static uint8_t s_id2_client_inited = 0;

static void _dump_id2_conf_info(void)
{
    ls_osa_print("ID2 Client Build Time: %s %s\n", __DATE__, __TIME__);

    ls_osa_print("-------------------------------------------\n");

#if defined(CONFIG_ID2_DEBUG)
    ls_osa_print("CONFIG_ID2_DEBUG is defined!\n");
#else
    ls_osa_print("CONFIG_ID2_DEBUG is not defined!\n");
#endif

    if (CONFIG_ID2_MDU_TYPE == ID2_MDU_TYPE_QUECTEL) {
        ls_osa_print("CONFIG_ID2_MDU_TYPE: %s\n", "ID2_MDU_TYPE_QUECTEL");
    }

    ls_osa_print("-------------------------------------------\n");
}

int is_id2_client_inited(void)
{
    return s_id2_client_inited;
}

irot_result_t id2_client_init(void)
{
    irot_result_t ret;

    id2_log_debug("[id2_client_init enter.]\n");

    _dump_id2_conf_info();

    ret = mdu_id2_init();
    if (ret != IROT_SUCCESS) {
        id2_log_error("module init fail, %d\n", ret);
        return ret;
    }

    s_id2_client_inited = 1;

    return IROT_SUCCESS;
}

irot_result_t id2_client_cleanup(void)
{
    irot_result_t ret;

    id2_log_debug("[id2_client_cleanup enter.]\n");

    ret = mdu_id2_cleanup();
    if (ret != IROT_SUCCESS) {
        id2_log_error("module cleanup fail, %d\n", ret);
        return ret;
    }

    s_id2_client_inited = 0;

    return IROT_SUCCESS;
}

irot_result_t id2_client_get_version(uint32_t* version)
{
    irot_result_t ret;

    id2_log_debug("[id2_client_get_version enter.]\n");

    if (version == NULL) {
        id2_log_error("invalid input arg.\n");
        return IROT_ERROR_BAD_PARAMETERS;
    }

    ret = mdu_id2_get_version(version);
    if (ret != IROT_SUCCESS) {
        id2_log_error("module get version fail, %d\n", ret);
        return ret;
    }

    return IROT_SUCCESS;
}

irot_result_t id2_client_get_id(uint8_t* id, uint32_t* len)
{
    irot_result_t ret;

    id2_log_debug("[id2_client_get_id enter.]\n");

    if (id == NULL || len == NULL) {
        id2_log_error("id or len is NULL\n");
        return IROT_ERROR_BAD_PARAMETERS;
    }

    if (*len < ID2_ID_LEN) {
        id2_log_error("short buffer, %d\n", *len);
        *len = ID2_ID_LEN;
        return IROT_ERROR_SHORT_BUFFER;
    }

    ret = mdu_id2_get_id(id, ID2_ID_LEN);
    if (ret != IROT_SUCCESS) {
        id2_log_error("module get id fail, %d\n", ret);
        return ret;
    }

    *len = ID2_ID_LEN;

    return IROT_SUCCESS;
}

irot_result_t id2_client_get_challenge_auth_code(const char* server_random,
                                                 const uint8_t* extra, uint32_t extra_len,
                                                 uint8_t* auth_code, uint32_t* auth_code_len)
{
    irot_result_t ret;

    id2_log_debug("[id2_client_get_challenge_auth_code enter.]\n");

    if (auth_code == NULL || auth_code_len == NULL ||
        server_random == NULL) {
        id2_log_error("invalid input args\n");
        return IROT_ERROR_BAD_PARAMETERS;
    }

    if (strlen(server_random) == 0 ||
        strlen(server_random) > ID2_MAX_SERVER_RANDOM_LEN) {
        id2_log_error("invalid server random length, %d\n", strlen(server_random));
        return IROT_ERROR_BAD_PARAMETERS;
    }

    /* check extra */
    if (extra_len > ID2_MAX_EXTRA_LEN || (
        extra != NULL && extra_len == 0)) {
        id2_log_error("invalid extra data length, %d\n", extra_len);
        return IROT_ERROR_EXCESS_DATA;
    }

    /* check authcode */
    if (*auth_code_len < ID2_AUTH_CODE_BUF_LEN) {
        id2_log_error("auth code short buffer, %d %d\n",
                       *auth_code_len, ID2_AUTH_CODE_BUF_LEN);
        *auth_code_len = ID2_AUTH_CODE_BUF_LEN;
        return IROT_ERROR_SHORT_BUFFER;
    }

    ret = mdu_id2_get_auth_code(ID2_AUTH_TYPE_CHALLENGE,
              server_random, extra, extra_len, auth_code, auth_code_len);
    if (ret != IROT_SUCCESS) {
        id2_log_error("module get auth code fail, %d\n", ret);
        return ret;
    }

    return IROT_SUCCESS;
}

irot_result_t id2_client_get_timestamp_auth_code(const char* timestamp,
                                                 const uint8_t* extra, uint32_t extra_len,
                                                 uint8_t* auth_code, uint32_t* auth_code_len)
{
    irot_result_t ret;

    id2_log_debug("[id2_client_get_timestamp_auth_code enter.]\n");

    if (auth_code == NULL || auth_code_len == NULL ||
        timestamp == NULL) {
        id2_log_error("invalid input args.\n");
        return IROT_ERROR_BAD_PARAMETERS;
    }

    /* check extra */
    if (extra_len > ID2_MAX_EXTRA_LEN || (
        extra != NULL && extra_len == 0)) {
        id2_log_error("invalid extra data length, %d.\n", extra_len);
        return IROT_ERROR_EXCESS_DATA;
    }

    /* check authcode */
    if (*auth_code_len < ID2_AUTH_CODE_BUF_LEN) {
        id2_log_error("auth code short buffer, %d %d.\n",
                       *auth_code_len, ID2_AUTH_CODE_BUF_LEN);
        *auth_code_len = ID2_AUTH_CODE_BUF_LEN;
        return IROT_ERROR_SHORT_BUFFER;
    }

    ret = mdu_id2_get_auth_code(ID2_AUTH_TYPE_TIMESTAMP,
              timestamp, extra, extra_len, auth_code, auth_code_len);
    if (ret != IROT_SUCCESS) {
        id2_log_error("module get auth code fail, %d\n", ret);
        return ret;
    }

    return IROT_SUCCESS;
}

irot_result_t id2_client_decrypt(const uint8_t* in, uint32_t in_len, uint8_t* out, uint32_t* out_len)
{
    irot_result_t ret;

    id2_log_debug("[id2_client_decrypt enter.]\n");

    if (in == NULL || in_len == 0 || out == NULL || out_len == NULL) {
        id2_log_error("invalid input args.\n");
        return IROT_ERROR_BAD_PARAMETERS;
    }

    if (in_len > ID2_MAX_CRYPT_LEN) {
        id2_log_error("invalid input data length, %d.\n", in_len);
        return IROT_ERROR_EXCESS_DATA;
    }

    ret = mdu_id2_decrypt(in, in_len, out, out_len);
    if (ret != IROT_SUCCESS) {
        id2_log_error("module id2 decrypt, %d\n", ret);
        return ret;
    }

    return IROT_SUCCESS;
}

irot_result_t id2_client_get_device_challenge(uint8_t* random, uint32_t* random_len)
{
    irot_result_t ret;

    id2_log_debug("[id2_client_get_device_challenge enter.]\n");

    if (random == NULL || random_len == NULL || *random_len == 0) {
        id2_log_error("invalid input args.\n");
        return IROT_ERROR_BAD_PARAMETERS;
    }

    ret = mdu_id2_get_device_challenge(random, random_len);
    if (ret != IROT_SUCCESS) {
        id2_log_error("module get device challenge fail, %d\n", ret);
        return ret;
    }

    return IROT_SUCCESS;
}

irot_result_t id2_client_verify_server(
                         const uint8_t* auth_code, uint32_t auth_code_len,
                         const uint8_t* device_random, uint32_t device_random_len,
                         const uint8_t* server_extra, uint32_t server_extra_len)
{
    irot_result_t ret;

    id2_log_debug("[id2_client_verify_server enter.]\n");

    if (auth_code == NULL || auth_code_len == 0) {
        id2_log_error("invalid input args.\n");
        return IROT_ERROR_BAD_PARAMETERS;
    }

    if (device_random != NULL && device_random_len == 0) {
        id2_log_error("invalid device random length.\n");
        return IROT_ERROR_BAD_PARAMETERS;
    }

    if (server_extra_len > ID2_MAX_EXTRA_LEN || (
        server_extra != NULL && server_extra_len == 0)) {
        id2_log_error("invalid server extra length, %d.\n", server_extra_len);
        return IROT_ERROR_EXCESS_DATA;
    }

    ret = mdu_id2_verify_server(auth_code, auth_code_len,
              device_random, device_random_len, server_extra, server_extra_len);
    if (ret != IROT_SUCCESS) {
        id2_log_error("module id2 verify server fail, %d\n", ret);
        return ret;
    }

    return IROT_SUCCESS;
}

irot_result_t id2_client_get_secret(const char* seed, uint8_t* secret, uint32_t* secret_len)
{
    irot_result_t ret;
    uint32_t in_len;

    id2_log_debug("[id2_client_get_secret enter.]\n");

    if (seed == NULL || secret == NULL || secret_len == NULL) {
        id2_log_error("invalid input args.\n");
        return IROT_ERROR_BAD_PARAMETERS;
    }

    in_len = strlen(seed);
    if (in_len == 0) {
        id2_log_error("seed is null.\n");
        return IROT_ERROR_BAD_PARAMETERS;
    }
    if (in_len > ID2_MAX_SEED_LEN) {
        id2_log_error("seed is excess data.\n");
        return IROT_ERROR_EXCESS_DATA;
    }

    if (*secret_len < ID2_DERIV_SECRET_LEN) {
        id2_log_error("short buffer, %d.\n", *secret_len);
        *secret_len = ID2_DERIV_SECRET_LEN;
        return IROT_ERROR_SHORT_BUFFER;
    }

    ret = mdu_id2_get_secret(seed, secret, secret_len);
    if (ret != IROT_SUCCESS) {
        id2_log_error("module get secret fail, %d\n", ret);
        return ret;
    }

    return IROT_SUCCESS;
}

irot_result_t id2_client_get_prov_stat(bool* is_prov)
{
    uint8_t id2[ID2_ID_LEN];
    uint32_t len = ID2_ID_LEN;
    irot_result_t ret;

    id2_log_debug("[id2_client_get_prov_stat enter.]\n");

    if (!is_id2_client_inited()) {
        id2_log_error("id2 not inited\n");
        return IROT_ERROR_GENERIC;
    }

    if (is_prov == NULL) {
        id2_log_error("invalid input arg\n");
        return IROT_ERROR_BAD_PARAMETERS;
    }

    ret = mdu_id2_get_id(id2, len);
    if (ret != IROT_SUCCESS) {
        id2_log_error("module get id fail, %d\n", ret);
        return ret;
    }

    *is_prov = true;

    id2_log_info("id2 prov state: %s\n", *is_prov == true ? "true" : "false");

    return IROT_SUCCESS;
}

irot_result_t id2_client_get_otp_auth_code(const uint8_t* token, uint32_t token_len,
        uint8_t* auth_code, uint32_t* len)
{
    (void)token;
    (void)token_len;
    (void)auth_code;
    (void)len;

    id2_log_info("not supported!!\n");

    return IROT_ERROR_NOT_SUPPORTED;
}

irot_result_t id2_client_load_otp_data(const uint8_t* otp_data, uint32_t len)
{
    (void)otp_data;
    (void)len;

    id2_log_info("not supported!!\n");

    return IROT_ERROR_NOT_SUPPORTED;
}

irot_result_t id2_client_derive_key(const char* seed, uint8_t* key, uint32_t key_len)
{
    (void)seed;
    (void)key;
    (void)key_len;

    id2_log_info("not supported!!\n");

    return IROT_ERROR_NOT_SUPPORTED;
}

irot_result_t id2_client_set_id2_and_key(const char* id2, int key_type, const char* key_value)
{
    id2_log_info("not supported!\n");

    return IROT_ERROR_NOT_SUPPORTED;
}

