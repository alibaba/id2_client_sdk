/*
 * Copyright (C) 2020-2022 Alibaba Group Holding Limited
 */

#include "id2_priv.h"
#include "id2_client_kpm.h"

irot_result_t id2_client_kpm_get_prov_stat(uint8_t key_idx, bool *is_prov)
{
    id2_log_info("not supported!\n");

    return IROT_ERROR_NOT_SUPPORTED;
}

irot_result_t id2_client_kpm_get_key_type(uint8_t key_idx, uint32_t *key_type)
{
    id2_log_info("not supported!\n");

    return IROT_ERROR_NOT_SUPPORTED;
}

irot_result_t id2_client_kpm_get_auth_code(uint8_t key_idx, uint8_t key_info,
                  uint8_t mode, char *random, uint8_t *auth_code, uint32_t *auth_code_len)
{
    id2_log_info("not supported!\n");

    return IROT_ERROR_NOT_SUPPORTED;
}

irot_result_t id2_client_kpm_import_key(uint8_t key_idx, uint8_t *data, uint32_t size)
{
    id2_log_info("not supported!\n");

    return IROT_ERROR_NOT_SUPPORTED;
}

irot_result_t id2_client_kpm_delete_key(uint8_t key_idx)
{
    id2_log_info("not supported!\n");

    return IROT_ERROR_NOT_SUPPORTED;
}

irot_result_t id2_client_kpm_export_pub_key(uint8_t key_idx, uint8_t *data, uint32_t *size)
{
    id2_log_info("not supported!\n");

    return IROT_ERROR_NOT_SUPPORTED;
}

irot_result_t id2_client_kpm_encrypt(uint8_t key_idx, uint8_t cipher_suite, uint8_t padding_type,
                                     uint8_t *iv, uint32_t iv_len,
                                     uint8_t *in_data, uint32_t in_len, uint8_t *out_data, uint32_t *out_len)
{
    id2_log_info("not supported!\n");

    return IROT_ERROR_NOT_SUPPORTED;
}

irot_result_t id2_client_kpm_decrypt(uint8_t key_idx, uint8_t cipher_suite, uint8_t padding_type,
                                     uint8_t *iv, uint32_t iv_len,
                                     uint8_t *in_data, uint32_t in_len, uint8_t *out_data, uint32_t *out_len)
{
    id2_log_info("not supported!\n");

    return IROT_ERROR_NOT_SUPPORTED;
}

irot_result_t id2_client_kpm_sign(uint8_t key_idx, uint8_t *msg, uint32_t msg_len, uint8_t *sign, uint32_t *sign_len)
{
    id2_log_info("not supported!\n");

    return IROT_ERROR_NOT_SUPPORTED;
}

irot_result_t id2_client_kpm_verify(uint8_t key_idx, uint8_t *msg, uint32_t msg_len, uint8_t *sign, uint32_t sign_len)
{
    id2_log_info("not supported!\n");

    return IROT_ERROR_NOT_SUPPORTED;
}

