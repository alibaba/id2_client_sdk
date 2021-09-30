/*
 * Copyright (C) 2016-2019 Alibaba Group Holding Limited
 */

#ifndef __LS_HAL_SM4_H__
#define __LS_HAL_SM4_H__

/********************************************************************/
/*              SM4 HAL CRYPTO API                                  */
/********************************************************************/

/*
 * Return the hal ctx size for hal aes ecb process
 * the hal ctx should defined by the user according 
 * to the user's implementation
 */
int ls_hal_sm4_ecb_get_size(void);

/*
 * Initialize the hal_ctx
 *
 * ctx[in]:     hal_ctx, must be pre-allocated by the caller,
 *              the size is got through ls_hal_sm4_ecb_get_size()
 * is_enc[in]:  encrypt(1)/decrypt(0) mode
 * key[in]:     the aes encrypt/decrypt key
 * size[in]:    key size(byte), the keysize can only be 16/24/32
 */
int ls_hal_sm4_ecb_init(void *ctx,
           int is_enc, const uint8_t *key, size_t size);

/*
 * AES ECB mode process
 *
 * ctx[in]:     hal_ctx, must be pre-allocated by the caller,
 *              the size is got through ls_hal_sm4_ecb_get_size()
 * src[in]:     input buffer
 * dst[out]:    output buffer
 * size[in]:    the number of bytes to process,
 *              must be multiple of BLOCK_SIZE(16) 
 */
int ls_hal_sm4_ecb_process(void *ctx, const uint8_t *src, uint8_t *dst, size_t size);

/*
 * return the hal ctx size for hal aes cbc process
 * the hal ctx should defined by the user according 
 * to the user's implementation
 */
int ls_hal_sm4_cbc_get_size(void);

/*
 * Initialize the hal_ctx
 *
 * ctx[in]:     hal_ctx, must be pre-allocated by the caller,
 *              the size is got through ls_hal_sm4_cbc_get_size()
 * is_enc[in]:  encrypt(1)/decrypt(0) mode
 * key[in]:     the aes encrypt/decrypt key
 * size[in]:    key size(byte), the keysize can only be 16/24/32
 * iv[in/out]:  initial vector
 */
int ls_hal_sm4_cbc_init(void *ctx, int is_enc,
           const uint8_t *key, size_t key_size, uint8_t iv[16]);

/*
 * AES CBC mode process
 *
 * ctx[in]:     hal_ctx, must be pre-allocated by the caller,
 *              the size is got through ls_hal_sm4_cbc_get_size()
 * src[in]:     input buffer
 * dst[out]:    output buffer
 * size[in]:    the number of bytes to process,
 *              must be multiple of BLOCK_SIZE(16) 
 */
int ls_hal_sm4_cbc_process(void *ctx, const uint8_t *src, uint8_t *dst, size_t size);

/*
 * Return the hal ctx size for hal aes ctr process
 * the hal ctx should defined by the user according 
 * to the user's implementation
 */
int ls_hal_sm4_ctr_get_size(void);

/*
 * Initialize the hal_ctx
 *
 * ctx[in]:     hal_ctx, must be pre-allocated by the caller,
 *              the size is got through ls_hal_sm4_ctr_get_size()
 * is_enc[in]:  encrypt(1)/decrypt(0) mode
 * key[in]:     the aes encrypt/decrypt key
 * size[in]:    key size(byte), the keysize can only be 16/24/32
 * iv[in/out]:  initial vector
 */
int ls_hal_sm4_ctr_init(void *ctx, int is_enc,
           const uint8_t *key, size_t key_size, uint8_t iv[16]);

/*
 * AES CTR mode process
 *
 * ctx[in]:     hal_ctx, must be pre-allocated by the caller,
 *              the size is got through ls_hal_sm4_ctr_get_size()
 * src[in]:     input buffer
 * dst[out]:    output buffer
 * size[in]:    the number of bytes to process
 */
int ls_hal_sm4_ctr_process(void *ctx, const uint8_t *src, uint8_t *dst, size_t size);

#endif // __LS_HAL_SM4_H__
