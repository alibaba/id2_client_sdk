/*
 * Copyright (C) 2019-2021 Alibaba Group Holding Limited
 */

#ifndef __CHIP_UTIL_H__
#define __CHIP_UTIL_H__

#include "ls_osa.h"

#define DIGEST_MAX_SIZE       64

#define DIGEST_SHA256_SIZE    32

typedef enum {
    DIGEST_TYPE_SHA1     = 0x01,
    DIGEST_TYPE_SHA256   = 0x02,
    DIGEST_TYPE_SM3      = 0x03,
} digest_t;

int chip_string_to_hex(const char *in, uint32_t in_len, uint8_t *out, uint32_t *out_len);

int chip_hex_to_string(const uint8_t *in, uint32_t in_len, char *out, uint32_t *out_len);

int chip_hash_digest(uint8_t* in, uint32_t in_len,
                     uint8_t* out, uint32_t* out_len, digest_t type);

int chip_hmac_digest(uint8_t* key, uint32_t key_len,
                     uint8_t *in, uint32_t in_len,
                     uint8_t *out, uint32_t* out_len, digest_t type);

#endif  /* __CHIP_UTIL_H__ */
