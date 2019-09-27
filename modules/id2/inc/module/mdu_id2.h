/*
 * Copyright (C) 2015-2017 Alibaba Group Holding Limited
 */

#ifndef __MDU_ID2_H__
#define __MDU_ID2_H__

#include "id2_client.h"

#ifdef __cplusplus
extern "C"
#endif

#define ID2_AUTH_TYPE_CHALLENGE    0
#define ID2_AUTH_TYPE_TIMESTAMP    1

/**
 * @brief module id2 init.
 *
 * @return @see error code definitions.
 */
irot_result_t mdu_id2_init(void);

/**
 * @brief module id2 cleanup.
 *
 * @return @see error code definitions.
 */
irot_result_t mdu_id2_cleanup(void);

/**
 * @brief get the id2 sdk version from module.
 *
 * @param[out] version: the hexadecimal version number.
 *
 * @return @see error code definitions.
 */
irot_result_t mdu_id2_get_version(uint32_t* version);

/**
 * @brief get ID2 ID String.
 *
 * @param[out]    id:   the ID2 buffer, containing ID2 ID string.
 * @param[in]     len:  the ID2 buffer size, should be more than ID2_ID_LEN.
 *
 * @return @see error code definitions.
 */
irot_result_t mdu_id2_get_id(uint8_t* id, uint32_t len);

/**
 * @brief get the authentication code with the challenge mode.
 *
 * @param[in]    type:           auth code type, challenge or timestamp.
 * @param[in]    random:         random string, terminated with '\0'.
 * @param[in]    extra:          extra string, optional, no more than 512 bytes.
 * @param[in]    extra_len:      the length of extra string.
 * @param[out]   auth_code:      the output buffer, containing authcode string.
 * @param[inout] auth_code_len:  in - the buffer size, more than 256 bytes.
 *                               out - the actual length.
 *
 * @return @see error code definitions.
 */
irot_result_t mdu_id2_get_auth_code(uint32_t type, const char* random,
                                    const uint8_t* extra, uint32_t extra_len,
                                    uint8_t* auth_code, uint32_t* auth_code_len);

/**
 * @brief decrypt the cipher data with id2 key.
 *
 * @param[in]    in:       input hexadecimal data.
 * @param[in]    in_len:   lenth of the input data, less than ID2_MAX_CRYPT_LEN bytes.
 * @param[out]   out:      output buffer, containing decrypted hexadecimal data.
 * @param[inout] out_len:  in - the buffer size; out - the actual length.
 *
 * @return @see error code definitions.
 */
irot_result_t mdu_id2_decrypt(const uint8_t* in,
                  uint32_t in_len, uint8_t* out, uint32_t* out_len);

/**
 * @brief get the device challenge, less than ID2_MAX_DEVICE_RANDOM_LEN bytes.
 *
 * @param[out]   random:      output buffer, containing device challenge string.
 * @param[inout] random_len:  in - the output buffer size; out - the actual length.
 *
 * @return @see error code definitions.
 */
irot_result_t mdu_id2_get_device_challenge(uint8_t* random, uint32_t* random_len);

/**
 * @brief   verify the auth code from server.
 *
 * @param[in] auth_code:             auth code string of server.
 * @param[in] auth_code_len:         the length of auth code.
 * @param[in] device_random:         device challenge string.
 * @param[in] device_random_len:     the length of device challenge.
 * @param[in] server_extra:          extra string of server.
 * @param[in] server_extra_len:      the length of extra.
 *
 * @return @see id2 error code definitions.
 */
irot_result_t mdu_id2_verify_server(
                         const uint8_t* auth_code, uint32_t auth_code_len,
                         const uint8_t* device_random, uint32_t device_random_len,
                         const uint8_t* server_extra,  uint32_t server_extra_len);

/* @brief derive device secret based on id2.
 *
 * @param[in]    seed:       seed string, terminated with '\0', less than ID2_MAX_SEED_LEN.
 * @param[out]   secret:     output buffer, containing secret string.
 * @param[inout] secret_len: in - the length of secret buffer, should be more than ID2_DERIV_SECRET_LEN bytes.
 *                           out - the actual secret string length.
 *
 * @return @see id2 error code definitions.
 */
irot_result_t mdu_id2_get_secret(const char* seed, uint8_t* secret, uint32_t* secret_len);

#ifdef __cplusplus
}
#endif

#endif  /* __MDU_ID2_H__ */

