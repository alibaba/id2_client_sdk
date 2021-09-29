/*
 * Copyright (C) 2016-2019 Alibaba Group Holding Limited
 */

#ifndef __LS_HAL_SM2_H__
#define __LS_HAL_SM2_H__

/********************************************************************/
/*              SM2 HAL CRYPTO API                                 */
/********************************************************************/

/*
 * SM2 public key operation
 *
 * context[in]: hal_ctx, must be pre-allocated by the caller,
 *              the size is got through ls_hal_ecc_get_ctx_size()
 * src[in]:       input buffer
 * src_size[in]:  input buffer size
 * dst[in]:       output buffer
 * dst_size[in]:  output buffer size
 */
int ls_hal_sm2_encrypt(void *context,
                       const uint8_t *src, size_t src_size,
                       uint8_t *dst, size_t *dst_size);

/*
 * SM2 private key operation
 *
 * context[in]:   hal_ctx, must be pre-allocated by the caller,
 *                the size is got through ls_hal_ecc_get_ctx_size()
 * f_rng:         Random function
 * src[in]:       input buffer
 * src_size[in]:  input buffer size
 * dst[in]:       output buffer
 * dst_size[in]:  output buffer size
 */
int ls_hal_sm2_decrypt(void *context,
                       const uint8_t *src, size_t src_size,
                       uint8_t *dst, size_t *dst_size);


/*
 * SM2 msg digest operation
 *
 * context[in]:   		hal_ctx, must be pre-allocated by the caller,
 *                		the size is got through ls_hal_ecc_get_ctx_size()
 * type:          		hash type (defined in ls_hal_hash.h)
 * id[in]:        		user identifier (a string, like ALICE123@YAHOO.COM)
 * id_size[in]:   		string length of id
 * msg[in]:       		msg to be signed
 * msg_size[in]:  		msg buffer length in byte
 * dsg[out]:            digest of input msg
 * dsg_size[in/out]: 	digest buffer size
 */
int ls_hal_sm2_msg_digest(void *context,
                          int type,
                          const uint8_t *id, size_t id_size,
                          const uint8_t *msg, size_t msg_size,
                          uint8_t *dsg, size_t *dsg_size);

/*
 * SM2 sign operation
 *
 * context[in]:   hal_ctx, must be pre-allocated by the caller,
 *                the size is got through ls_hal_ecc_get_ctx_size()
 * src[in]:       input buffer
 * src_size[in]:  input buffer size
 * dst[in]:       output buffer
 * dst_size[in]:  output buffer size
 */
int ls_hal_sm2_sign(void *context,
                    const uint8_t *src, size_t src_size,
                    uint8_t *dst, size_t *dst_size);

/*
 * SM2 verify operation
 *
 * context[in]:   hal_ctx, must be pre-allocated by the caller,
 *                the size is got through ls_hal_ecc_get_ctx_size()
 * src[in]:       input buffer
 * src_size[in]:  input buffer size
 * dst[in]:       output buffer
 * dst_size[in]:  output buffer size
 */
int ls_hal_sm2_verify(void *context,
                      const uint8_t *src, size_t src_size,
                      const uint8_t *dst, size_t dst_size);


#endif // __LS_HAL_SM2_H__
