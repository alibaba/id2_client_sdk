/*
 * Copyright (C) 2020-2022 Alibaba Group Holding Limited
 */

#ifndef __ID2_CLIENT_KPM_H__
#define __ID2_CLIENT_KPM_H__

#include "id2_client.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Pre-defined Key Index */
#define LS_KPM_KEY_IDX_ID2       0x00    /* reserved for ID2 */
#define LS_KPM_KEY_IDX_CTID      0x01    /* reserved for CTID */
#define LS_KPM_KEY_IDX_INVALID   0xFF

/* authentication mode */
#define LS_ID2_MODE_CHALLENGE    0x00
#define LS_ID2_MODE_TIMESTAMP    0x01

/* should be same with server */
typedef enum {
    LS_KPM_KEY_INFO_AES_128 = 1,
    LS_KPM_KEY_INFO_AES_192 = 2,
    LS_KPM_KEY_INFO_AES_256 = 3,
    LS_KPM_KEY_INFO_SM4_128 = 9
} ls_kpm_key_info_t;

typedef enum {
    LS_KPM_KEY_TYPE_AES = 81,
    LS_KPM_KEY_TYPE_SM4 = 82,
    LS_KPM_KEY_TYPE_SM2 = 83,
    LS_KPM_KEY_TYPE_RSA = 84
} ls_kpm_key_type_t;

typedef enum {
    LS_KPM_CIPHER_SUITE_AES_ECB = 101,
    LS_KPM_CIPHER_SUITE_AES_CBC = 102,
    LS_KPM_CIPHER_SUITE_SM4_ECB = 103,
    LS_KPM_CIPHER_SUITE_SM4_CBC = 104
} ls_kpm_cipher_suite_t;

typedef enum {
    LS_KPM_SYM_NO_PADDING    = 0,
    LS_KPM_SYM_PADDING_PKCS5 = 1,
} ls_kpm_padding_t;

/**
 * @brief get key provisioning status.
 *
 * @param[in]  key_idx: specify the user-defined key index, excluding LS_KPM_KEY_IDX_ID2.
 * @param[out] is_prov: the output provisioning status.
 *
 * @return @see id2 error code definitions.
 */
irot_result_t id2_client_kpm_get_prov_stat(uint8_t key_idx, bool *is_prov);

/**
 * @brief get key type.
 *
 * @param[in]  key_idx:  specify the user-defined key index, including LS_KPM_KEY_IDX_ID2.
 * @param[out] key_type: the output key type, see "ls_kpm_key_type_t" definitions.
 *
 * @return @see id2 error code definitions.
 */
irot_result_t id2_client_kpm_get_key_type(uint8_t key_idx, uint32_t *key_type);

/**
 * @brief get device authentication code, base64 encoded data.
 *
 * @param[in]    key_idx:  specify the user-defined key index, excluding LS_KPM_KEY_IDX_ID2.
 * @param[in]    key_info: specify the key info, see "ls_kpm_key_info_t" definitions.
 * @param[in]    mode:   specify authentication mode, LS_KPM_AUTH_CHALLENGE or LS_KPM_AUTH_TIMESTAMP.
 * @param[in]    random: specify the random string used to generate authentication code:
                         LS_KPM_AUTH_CHALLENGE - challenge string from ID2 server, terminated with '\0'.
                         LS_KPM_AUTH_TIMESTAMP - number string of milliseconds since the Epoch, terminated with '\0'
 * @param[out]   auth_code:     The output auth code.
 * @param[inout] auth_code_len: in - the buffer size, no less than ID2_MAX_AUTH_CODE_LEN.
 *                              out - the actual length.
 *
 * @return @see id2 error code definitions.
 */
irot_result_t id2_client_kpm_get_auth_code(uint8_t key_idx, uint8_t key_info,
                  uint8_t mode, char *random, uint8_t *auth_code, uint32_t *auth_code_len);

/**
 * @brief import ID2 encrypted key, base64 encoded data.
 *
 * @param[in] key_idx: specify the user-defined key index, excluding LS_KPM_KEY_IDX_ID2.
 * @param[in] data: the encrypted key data.
 * @param[in] size: the encrypted key data size.
 *
 * @return @see id2 error code definitions.
 */
irot_result_t id2_client_kpm_import_key(uint8_t kidx, uint8_t *data, uint32_t size);

/**
 * @brief delete the imported key.
 *
 * @param[in] key_idx: specify the user-defined key index, excluding LS_KPM_KEY_IDX_ID2.
 *
 * @return @see id2 error code definitions.
 */
irot_result_t id2_client_kpm_delete_key(uint8_t kidx);

/**
 * @brief export asymmetric public key, base64 encoded data.
 *
 * @param[in] key_idx: specify the user-defined key index, including LS_KPM_KEY_IDX_ID2.
 * @param[in] data: the public key data.
 * @param[in] size: the public key data size.
 *
 * @return @see id2 error code definitions.
 */
irot_result_t id2_client_kpm_export_pub_key(uint8_t kidx, uint8_t *data, uint32_t *size);

/**
 * @brief encrypt data with specified key, hexadecimal data.
 *
 * @param[in]    key_idx:  specify the user-defined key index, excluding LS_KPM_KEY_IDX_ID2.
 * @param[in]    cipher_suite: specify the cipher algorithm, see "ls_kpm_cipher_suite_t" definitions.
 * @param[in]    padding_type: specify padding type, see "ls_kpm_padding_t" definitions.
 * @param[in]    iv:       the initialization counter, set to NULL if no need.
 * @param[in]    iv_len:   the length of initialization counter.
 * @param[in]    in_data:  the input data to be encrypted.
 * @param[in]    in_len:   the input data length.
 * @param[out]   out_data: the output buffer, which is used to store cipher data.
 * @param[inout] out_len:  in - the buffer length;
 *                         out - the actual cipher data length.
 *
 * @return @see id2 error code definitions.
 */
irot_result_t id2_client_kpm_encrypt(uint8_t key_idx, uint8_t cipher_suite, uint8_t padding_type,
                                     uint8_t *iv, uint32_t iv_len,
                                     uint8_t *in_data, uint32_t in_len, uint8_t *out_data, uint32_t *out_len);

/**
 * @brief decrypt cipher data with specified key, hexadecimal data.
 *
 * @param[in]    key_idx: specify the user-defined key index, excluding LS_KPM_KEY_IDX_ID2.
 * @param[in]    cipher_suite: specify the cipher algorithm, see "ls_kpm_cipher_suite_t" definitions.
 * @param[in]    padding_type: specify padding type, see "ls_kpm_padding_t" definitions.
 * @param[in]    iv:       the initialization counter, set to NULL if no need.
 * @param[in]    iv_len:   the length of initialization counter.
 * @param[in]    in_data:  the input cipher data.
 * @param[in]    in_len:   the input data length.
 * @param[out]   out_data: the output buffer, which is used to store plaintext data.
 * @param[inout] out_len:  in - the buffer length;
 *                         out - the actual plaintext data length.
 *
 * @return @see id2 error code definitions.
 */
irot_result_t id2_client_kpm_decrypt(uint8_t key_idx, uint8_t cipher_suite, uint8_t padding_type,
                                     uint8_t *iv, uint32_t iv_len,
                                     uint8_t *in_data, uint32_t in_len, uint8_t *out_data, uint32_t *out_len);

 /* @brief generate signature with specified key, hexadecimal message and signature.
 *
 * @param[in]    key_idx:  specify the user-defined key index, excluding LS_KPM_KEY_IDX_ID2.
 * @param[in]    msg:      the message to be signed.
 * @param[in]    msg_len:  the input message length.
 * @param[out]   sign:     the output buffer, which is used to store signature.
 * @param[inout] sign_len: in - the buffer length;
 *                         out - the actual signature length.
 *
 * @return @see id2 error code definitions.
 */
irot_result_t id2_client_kpm_sign(uint8_t key_idx, uint8_t *msg, uint32_t msg_len, uint8_t *sign, uint32_t *sign_len);

 /* @brief verify signature with specified key, hexadecimal message and signature.
 *
 * @param[in] key_idx:  specify the user-defined key index, excluding LS_KPM_KEY_IDX_ID2.
 * @param[in] msg:      the message to be signed.
 * @param[in] msg_len:  the input message length.
 * @param[in] sign:     the input signature to be verified.
 * @param[in] sign_len: the input signature length.
 *
 * @return @see id2 error code definitions.
 */
irot_result_t id2_client_kpm_verify(uint8_t key_idx, uint8_t *msg, uint32_t msg_len, uint8_t *sign, uint32_t sign_len);

#ifdef __cplusplus
}
#endif

#endif  /* __ID2_CLIENT_KPM_H__ */

