/*
 * Copyright (C) 2020-2022 Alibaba Group Holding Limited
 */

#include "id2_priv.h"
#include "id2_client_dpm.h"


irot_result_t id2_client_dpm_get_totp(uint64_t timestamp, uint32_t index,
                         uint32_t otp_step, uint32_t otp_len, uint8_t *otp_data)
{
    id2_log_info("not supported!\n");

    return IROT_ERROR_NOT_SUPPORTED;
}

irot_result_t id2_client_dpm_get_index(uint8_t *otp_data, uint32_t otp_len, uint32_t *index)
{
    id2_log_info("not supported!\n");

    return IROT_ERROR_NOT_SUPPORTED;
}

