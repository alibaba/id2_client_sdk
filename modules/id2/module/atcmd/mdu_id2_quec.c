/*
 * Copyright (C) 2017-2019 Alibaba Group Holding Limited
 */

#include "id2_priv.h"
#include "module/mdu_driver.h"

static void *handle = NULL;

irot_result_t mdu_id2_init(void)
{
    irot_result_t ret;

    ret = mdu_open_session(&handle);
    if (ret != IROT_SUCCESS) {
        id2_log_error("module open session fail, %d\n", ret);
        return ret;
    }

    id2_log_info("not implemented!\n");

    return IROT_ERROR_NOT_IMPLEMENTED;
}

irot_result_t mdu_id2_cleanup(void)
{
    irot_result_t ret;

    ret = mdu_close_session(handle);
    if (ret != IROT_SUCCESS) {
        id2_log_error("module close session fail, %d\n", ret);
        return ret;
    }

    id2_log_info("not implemented!\n");

    return IROT_ERROR_NOT_IMPLEMENTED;
}

irot_result_t mdu_id2_get_version(uint32_t* version)
{
    id2_log_info("not implemented!\n");

    return IROT_ERROR_NOT_IMPLEMENTED;
}

irot_result_t mdu_id2_get_id(uint8_t* id, uint32_t len)
{
    id2_log_info("not implemented!\n");

    return IROT_ERROR_NOT_IMPLEMENTED;
}

irot_result_t mdu_id2_get_auth_code(uint32_t type, const char* random,
                                    const uint8_t* extra, uint32_t extra_len,
                                    uint8_t* auth_code, uint32_t* auth_code_len)
{
    id2_log_info("not implemented!\n");

    return IROT_ERROR_NOT_IMPLEMENTED;
}

irot_result_t mdu_id2_decrypt(const uint8_t* in,
                  uint32_t in_len, uint8_t* out, uint32_t* out_len)
{
    id2_log_info("not implemented!\n");

    return IROT_ERROR_NOT_IMPLEMENTED;
}

irot_result_t mdu_id2_get_device_challenge(uint8_t* random, uint32_t* random_len)
{
    id2_log_info("not implemented!\n");

    return IROT_ERROR_NOT_IMPLEMENTED;
}

irot_result_t mdu_id2_verify_server(
                         const uint8_t* auth_code, uint32_t auth_code_len,
                         const uint8_t* device_random, uint32_t device_random_len,
                         const uint8_t* server_extra,  uint32_t server_extra_len)
{
    id2_log_info("not implemented!\n");

    return IROT_ERROR_NOT_IMPLEMENTED;
}

irot_result_t mdu_id2_get_secret(const char* seed, uint8_t* secret, uint32_t* secret_len)
{
    id2_log_info("not implemented!\n");

    return IROT_ERROR_NOT_IMPLEMENTED;
}

