/*
 * Copyright (C) 2020-2022 Alibaba Group Holding Limited
 */

#ifndef __ID2_CLIENT_DPM_H__
#define __ID2_CLIENT_DPM_H__

#include "id2_client.h"

#ifdef __cplusplus
extern "C" {
#endif

/* milli-seconds */
#define ID2_DPM_OTP_STEP_MIN_LEN    180
#define ID2_DPM_OTP_STEP_MAX_LEN    1800

/* one-time password length */
#define ID2_DPM_OTP_DATA_MIN_LEN    6
#define ID2_DPM_OTP_DATA_MAX_LEN    16

/**
 * @brief Get Time-based One-Time Password.
 *
 * @param [in] timestamp: Current Unix Time.
 * @param [in] index: Password index.
 * @param [in] otp_len: Specify the length of password.
 * @param [in] otp_step: Specify the step size of password.
 * @param [out] otp_data: Specify the buffer to contain output password data.
 *
 * @return: @see Error Codes.
 */
irot_result_t id2_client_dpm_get_totp(uint64_t timestamp, uint32_t index,
                         uint32_t otp_step, uint32_t otp_len, uint8_t *otp_data);

/**
 * @brief Extract index from password.
 *
 * @param [in] otp_data: Password data.
 * @param [in] otp_len: The length of Password.
 * @param [out] index: Password index.
 *
 * @return: @see Error Codes.
 */
irot_result_t id2_client_dpm_get_index(uint8_t *otp_data, uint32_t otp_len, uint32_t *index);

#ifdef __cplusplus
}
#endif

#endif  /* __ID2_CLIENT_DPM_H__ */

