/*
 * Copyright (C) 2018 Alibaba Group Holding Limited
 */


#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <time.h>
#include <mbedtls/base64.h>
#include <mbedtls/sha1.h>
#include <mbedtls/sha256.h>
#include "config.h"
#include "irot_pal.h"
#include "log/log.h"

////////////////////////////////////////////////////////////////////////////////
// implement irot pal interface use mbedtls library.
////////////////////////////////////////////////////////////////////////////////

void* irot_pal_memory_malloc(int size)
{
    void* ptr;
    ptr = malloc(size);
    id2_log_debug("irot_pal_memory_malloc, (ptr = %p, size = %d)\n", ptr, size);
    return ptr;
}

void irot_pal_memory_free(void* ptr)
{
    id2_log_debug("irot_pal_memory_free, (ptr = %p)\n", ptr);
    free(ptr);
}

irot_result_t irot_pal_base64_encode(const uint8_t* in, uint32_t in_len, uint8_t* out, uint32_t* out_len)
{
    int base64_ret;
    size_t olen;
    id2_log_hex_data("base64 input", in, in_len);
    base64_ret = mbedtls_base64_encode(out, *out_len, &olen, in, in_len);
    if (base64_ret != 0)
    {
        return IROT_ERROR_GENERIC;
    }
    *out_len = (uint32_t)olen;
    id2_log_hex_data("base64 output", out, *out_len);
    return IROT_SUCCESS;
}

irot_result_t irot_pal_hash_sum(const uint8_t* in, uint32_t in_len, uint8_t* out, uint32_t* out_len, digest_t type)
{
    irot_result_t ret = IROT_SUCCESS;

    if (type == DIGEST_TYPE_SHA1)
    {
        if (*out_len < 20)
        {
            ret = IROT_ERROR_SHORT_BUFFER;
            goto EXIT;
        }
        mbedtls_sha1(in, in_len, out);
        *out_len = 20;
    }
    else if (type == DIGEST_TYPE_SHA256)
    {
        if (*out_len < 32)
        {
            ret = IROT_ERROR_SHORT_BUFFER;
            goto EXIT;
        }
        mbedtls_sha256(in, in_len, out, 0);
        *out_len = 32;
    }
    else
    {
        ret = IROT_ERROR_NOT_SUPPORTED;
        goto EXIT;
    }

EXIT:
    return ret;
}


irot_result_t irot_pal_get_random(uint8_t* buf, uint32_t len)
{
    //this is only a sample, you must use the real random number on your chip!!!
    uint32_t i;
    for (i = 0; i < len; ++i)
    {
        buf[i] = (uint8_t)0xAB;
    }
    return IROT_SUCCESS;
}

void irot_pal_log(const char* fmt, ...)
{
    va_list args;

    va_start(args, fmt);
    vprintf(fmt, args);
    va_end(args);
}
