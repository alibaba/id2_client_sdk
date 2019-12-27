/*
 * Copyright (C) 2015-2017 Alibaba Group Holding Limited
 */

#ifndef __ID2_CLIENT_H__
#define __ID2_CLIENT_H__

#include <stdint.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

#define ID2_ID_LEN                   24
#define ID2_DERIV_KEY_LEN            32
#define ID2_DERIV_SECRET_LEN         64

#define ID2_MAX_SERVER_RANDOM_LEN    32
#define ID2_MAX_DEVICE_RANDOM_LEN    16
#define ID2_MAX_SEED_LEN             128
#define ID2_MAX_EXTRA_LEN            512
#define ID2_MAX_CRYPT_LEN            4096

/* id2 error code definitions */
#define IROT_SUCCESS                 0  /* The operation was successful */
#define IROT_ERROR_GENERIC          -1  /* The generic error */
#define IROT_ERROR_BAD_PARAMETERS   -2  /* Input parameters are invalid */
#define IROT_ERROR_SHORT_BUFFER     -3  /* The supplied buffer is too short for output */
#define IROT_ERROR_EXCESS_DATA      -4  /* Too much data for the requested operation */
#define IROT_ERROR_OUT_OF_MEMORY    -5  /* Out of memory */
#define IROT_ERROR_COMMUNICATION    -7  /* Communication error */
#define IROT_ERROR_NOT_SUPPORTED    -8  /* The request operation is not supported */
#define IROT_ERROR_NOT_IMPLEMENTED  -9  /* The request operation is not implemented */
#define IROT_ERROR_TIMEOUT          -10 /* Communication timeout */
#define IROT_ERROR_ITEM_NOT_FOUND   -11 /* The item is not exist */

typedef int irot_result_t;

/**
 * @brief id2 client initialization.
 *
 * @return @see id2 error code definitions.
 */
irot_result_t id2_client_init(void);

/**
 * @brief id2 client cleanup.
 *
 * @return @see id2 error code definitions.
 */
irot_result_t id2_client_cleanup(void);

/**
 * @brief get the id2 client version.
 * @param[out] version: the version number.
 *
 * @return @see id2 error code definitions.
 */
irot_result_t id2_client_get_version(uint32_t* version);

/**
 * @brief get ID2 ID String.
 *
 * @param[out]    id:   the ID2 buffer, containing ID2 ID string.
 * @param[inout]  len:  in -  the ID2 buffer size, which must >= ID2_ID_LEN;
 *                      out - the actual length.
 *
 * @return @see id2 error code definitions.
 */
irot_result_t id2_client_get_id(uint8_t* id, uint32_t* len);

/**
 * @brief get the authentication code with the challenge mode.
 *
 * @param[in]    server_random:  random string from ID2 server, terminated with '\0'.
 * @param[in]    extra:          extra string, optional, no more than 512 bytes.
 * @param[in]    extra_len:      the length of extra string.
 * @param[out]   auth_code:      the output buffer, containing auth code string.
 * @param[inout] auth_code_len:  in - the buffer size, more than 256 bytes.
 *                               out - the actual length.
 *
 * @return @see id2 error code definitions.
 */
irot_result_t id2_client_get_challenge_auth_code(const char* server_random,
                                                 const uint8_t* extra, uint32_t extra_len,
                                                 uint8_t* auth_code, uint32_t* auth_code_len);

/**
 * @brief get the authentication code with timestamp mode.
 *
 * @param[in]    timestamp:      the number string of milliseconds since the Epoch, terminated with '\0'.
 * @param[in]    extra:          extra string, optional, no more than 512 bytes.
 * @param[in]    extra_len:      the length of extra string.
 * @param[out]   auth_code:      the output buffer, containing auth code string.
 * @param[inout] auth_code_len:  in - the buffer size, more than 256 bytes.
 *                               out - the actual length.
 *
 * @return @see id2 error code definitions.
 */
irot_result_t id2_client_get_timestamp_auth_code(const char* timestamp,
                                                 const uint8_t* extra, uint32_t extra_len,
                                                 uint8_t* auth_code, uint32_t* auth_code_len);

/**
 * @brief decrypt the cipher data with ID2 key.
 *
 * @param[in]    in:       input hexadecimal data.
 * @param[in]    in_len:   lenth of the input data, less than ID2_MAX_CRYPT_LEN bytes.
 * @param[out]   out:      output buffer, containing decrypted hexadecimal data.
 * @param[inout] out_len:  in - the buffer size; out - the actual length.
 *
 * @return @see id2 error code definitions.
 */
irot_result_t id2_client_decrypt(const uint8_t* in,
                  uint32_t in_len, uint8_t* out, uint32_t* out_len);

/**
 * @brief get the device challenge, less than ID2_MAX_DEVICE_RANDOM_LEN bytes.
 *
 * @param[out]   random:      output buffer, containing device challenge string.
 * @param[inout] random_len:  in - the output buffer size; out - the actual length.
 *
 * @return @see id2 error code definitions.
 */
irot_result_t id2_client_get_device_challenge(uint8_t* random, uint32_t* random_len);

/**
 * @brief   verify the auth code from server.
 *
 * @param[in] auth_code:             auth code string of server.
 * @param[in] auth_code_len:         the length auth code.
 * @param[in] device_random:         device challenge string.
 * @param[in] device_random_len:     the length of device challenge.
 * @param[in] server_extra:          extra string of server.
 * @param[in] server_extra_len:      the length of extra.
 *
 * @return @see id2 error code definitions.
 */
irot_result_t id2_client_verify_server(
                         const uint8_t* auth_code, uint32_t auth_code_len,
                         const uint8_t* device_random, uint32_t device_random_len,
                         const uint8_t* server_extra,  uint32_t server_extra_len);

/* @brief derive device secret based on id2.
 *
 * @param[in]    seed:       seed string, terminated with '\0', less than ID2_MAX_SEED_LEN.
 * @param[out]   secret:     output buffer, containing secret string.
 * @param[inout] secret_len: in - the length of secret buffer, should be more than ID2_DERIV_SECRET_LEN bytes.
 *                           out - the actual secret length.
 *
 * @return @see id2 error code definitions.
 */
irot_result_t id2_client_get_secret(const char* seed, uint8_t* secret, uint32_t* secret_len);

/* @brief derive hex format key based on id2.
 *
 * @param[in]    seed:       seed string, terminated with '\0', less than ID2_MAX_SEED_LEN.
 * @param[out]   key:        output buffer, containing hex format key .
 * @param[inout] key_len:    the length of derived key, no more than ID2_DERIVE_KEY_LEN bytes.
 *
 * @return @see id2 error code definitions.
 */
irot_result_t id2_client_derive_key(const char* seed, uint8_t* key, uint32_t key_len);

/******************************************************************************
 *                         ID2 Client Debug Functions
 ******************************************************************************
 */

/**
 * @brief set ID2 and key only for debug.
 *
 * @param[in] id2:	   the id2 id string.
 * @param[in] key_type:    the id2 key type, 3DES = 0x01, AES = 0x02
 * @param[in] key_value:   the key value (hex string)
 *
 * example: id2_client_set_id2_and_key("0102030405060708090A0B0C", 0x01, "0102030405060708090A0B0C0D0E0F101112131415161718");
 *
 * @return @see id2 error code definitions.
 */
irot_result_t id2_client_set_id2_and_key(const char* id2, int key_type, const char* key_value);


/******************************************************************************
 *                         ID2 Client OTP Functions
 ******************************************************************************
 */

/**
 * @brief get id2 provisiong status.
 * @param[out] is_prov:  the provisioning status.
 *
 * @return @see id2 error code definitions.
 */
irot_result_t id2_client_get_prov_stat(bool *is_prov);

/**
 * @brief get the otp authentication code.
 *
 * @param[in]    token:          the provisioning token buffer.
 * @param[in]    token_len:      the length of provisioning token.
 * @param[out]   auth_code:      output buffer, containing auth code string.
 * @param[inout] auth_code_len:  in - the output buffer size; out - the actual length.
 *
 * @return @see id2 error code definitions.
 */
irot_result_t id2_client_get_otp_auth_code(const uint8_t* token, uint32_t token_len,
                                           uint8_t* auth_code, uint32_t* auth_code_len);
/**
 * @brief load the id2 otp data into device.
 *
 * @param[in]  otp_data:     the otp hexadecimal data, which is got from id2 server.
 * @param[in]  otp_data_len: the length of otp data.
 *
 * @return @see id2 error code definitions.
 */
irot_result_t id2_client_load_otp_data(const uint8_t *otp_data, uint32_t otp_data_len);

#ifdef __cplusplus
}
#endif

#endif  /* __ID2_CLIENT_H__ */

