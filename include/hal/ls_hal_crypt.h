/*
 * Copyright (C) 2016-2019 Alibaba Group Holding Limited
 */

#ifndef __LS_HAL_CRYPT_H__
#define __LS_HAL_CRYPT_H__

#include "ls_osa.h"
#include "ls_hal_rsa.h"
#include "ls_hal_aes.h"
#include "ls_hal_hash.h"
#include "ls_hal_sm4.h"
#include "ls_hal_ecc.h"
#include "ls_hal_sm2.h"

#define HAL_CRYPT_ERROR                 0xFFFF0000     /* Generic Error */
#define HAL_CRYPT_BAD_PARAMETERS        0xFFFF0001     /* Bad Parameters */
#define HAL_CRYPT_NOSUPPORT             0xFFFF0002     /* Scheme not support */
#define HAL_CRYPT_INVALID_CONTEXT       0xFFFF0003     /* Invalid context */
#define HAL_CRYPT_INVALID_ARG           0xFFFF0004     /* Invalid argument */
#define HAL_CRYPT_LENGTH_ERR            0xFFFF0005     /* Invalid Length in arguments */
#define HAL_CRYPT_OUTOFMEM              0xFFFF0006     /* Memory alloc NULL */
#define HAL_CRYPT_SHORT_BUFFER          0xFFFF0007     /* Output buffer is too short to store result */
#define HAL_CRYPT_INVALID_AUTH          0xFFFF0008     /* Invalid authentication in verify */
#define HAL_CRYPT_SUCCESS               0              /* Success */

/*
 * Generate random data with len bytes
 *
 * buf[in/out]:  buffer to store the results
 * len[in]:      size of buffer
 */
int ls_hal_get_random(uint8_t *buf, size_t len);

/*
 * NOTE: if you use hw randon generator in ls_hal_get_random(),
 *       it is not needed to impl this function.
 *       (just return HAL_CRYPT_SUCCESS)
 *
 * Set seed for random generator
 *
 * seed[in]: seed data buffer
 * seed_len: length of seed data buffer
 */
int ls_hal_set_seed(uint8_t *seed, size_t seed_len);

#endif /*__LS_HAL_CRYPT_H__ */
