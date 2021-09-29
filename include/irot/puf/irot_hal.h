/**
 * Copyright (C) 2019 - 2021 Alibaba Group Holding Limited.
 */

#ifndef __IROT_HAL_H__
#define __IROT_HAL_H__

#include "ls_osa.h"

#define ID2_ID_VERSION       "05"
#define ID2_ID_RESERVE       "0000"

#define ID2_ID_VERS_LEN      2   /* ID version field length in bytes */
#define ID2_ID_VEND_LEN      8   /* ID vendor code field length in bytes */
#define ID2_ID_RSVD_LEN      4   /* ID reserved field length in bytes */
#define ID2_ID_SLEN_LEN      2   /* ID chip uid size field length in bytes */

/**
 * @brief irot hal initialization.
 *
 * @return 0 - success; -1 - error.
 */
int irot_hal_init(void);

/**
 * @brief irot hal cleanup.
 */
void irot_hal_cleanup(void);

/**
 * @brief get the unique identifier.
 *
 * @param[out]   id_buf:  the output buffer, which is used to store uid.
 * @param[inout] id_len:  in - the buffer length;
 *                        out - the actual uid length.
 *
 * @return 0 - success; -1 - error.
 */
int irot_hal_get_uid(uint8_t *id_buf, uint32_t *id_len);

/**
 * @brief get the ID2 ID string.
 *
 * @param[out]   id_buf:  the output buffer, which is used to store ID2 ID string.
 * @param[inout] id_len:  in - the buffer length;
 *                        out - the actual ID2 ID length.
 *
 * @return 0 - success; -1 - error.
 */
int irot_hal_get_id2(uint8_t *id_buf, uint32_t *id_len);

/**
 * @brief generate signature with ID2 client private key.
 *
 * @param[in]    msg:  the message to be signed.
 * @param[in]    msg_len:  the input message length.
 * @param[out]   sign: the output buffer, which is used to store signature.
 * @param[inout] sign_len:  in - the buffer length;
 *                          out - the actual signdature length.
 *
 * @return 0 - success; -1 - error.
 */
int irot_hal_id2_sign(
         uint8_t *msg, uint32_t msg_len, uint8_t *sign, uint32_t *sign_len);

/**
 * @brief verify signature with ID2 server public key.
 *
 * @param[in] msg:  the message to be signed.
 * @param[in] msg_len:  the input message length.
 * @param[in] sign:  the input signature to be verified.
 * @param[in] sign_len:  the input signature length.
 *
 * @return 0 - success; -1 - error.
 */
int irot_hal_id2_verify(
         uint8_t *msg, uint32_t msg_len, uint8_t *sign, uint32_t sign_len);

/**
 * @brief encrypt data with ID2 server public key.
 *
 * @param[in]    in_data: the input data to be encrypted.
 * @param[in]    in_len: the input data length.
 * @param[out]   out_data: the output buffer, which is used to store cipher data.
 * @param[inout] out_len:  in - the buffer length;
 *                         out - the actual cipher data length.
 *
 * @return 0 - success; -1 - error.
 */
int irot_hal_id2_encrypt(
         uint8_t *in_data, uint32_t in_len, uint8_t *out_data, uint32_t *out_len);

/**
 * @brief decrypt cipher data with ID2 client private key.
 *
 * @param[in]    in_data:  the input cipher data to be decrypted.
 * @param[in]    in_len:  the input cipher data length.
 * @param[out]   out_data: the output buffer, which is used to store plaintext data.
 * @param[inout] out_len:  in - the buffer length
 *                         out - the actual plaintext data length.
 *
 * @return 0 - success; -1 - error.
 */
int irot_hal_id2_decrypt(
         uint8_t *in_data, uint32_t in_len, uint8_t *out_data, uint32_t *out_len);

#endif /* __IROT_HAL_H__ */

