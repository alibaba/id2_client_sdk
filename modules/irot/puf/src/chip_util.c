/**
 * Copyright (C) 2019-2021 Alibaba Group Holding Limited.
 */

#include "chip_log.h"
#include "chip_util.h"

#include "ali_crypto.h"

static char* const string_table = "0123456789ABCDEF";

static int char_to_hex(char c)
{
    int hex = -1;

    if (c >= '0' && c <= '9') {
        hex = c - '0';
    } else if (c >= 'a' && c <= 'f') {
        hex = c - 'a' + 10;
    } else if (c >= 'A' && c <= 'F') {
        hex = c - 'A' + 10;
    }

    return hex;
}

int chip_string_to_hex(const char *in, uint32_t in_len, uint8_t *out, uint32_t *out_len)
{
    uint32_t i = 0;
    int high, low;

    if (in == NULL || out == NULL ||
        in_len % 2 != 0 || out_len == NULL) {
        chip_log_error("invalid input args\n");
        return -1;
    }

    if (*out_len * 2 < in_len) {
        chip_log_error("short buffer, %d %d\n", *out_len * 2, in_len);
        return -1;
    }

    while (i < in_len) {
        high = char_to_hex(in[i]);
        if (high < 0) {
            return -1;
        }

        low = char_to_hex(in[i + 1]);
        if (low < 0) {
            return -1;
        }

        out[i >> 1] = (uint8_t)((high << 4) | (low & 0x0F));
        i += 2;
    }

    *out_len = in_len >> 1;

    return 0;
}

int chip_hex_to_string(const uint8_t *in, uint32_t in_len, char *out, uint32_t *out_len)
{
    int32_t i;
    uint8_t temp;
    uint8_t high, low;

    if (in == NULL || in_len == 0 ||
        out == NULL || out_len == NULL) {
        chip_log_error("invalid input args\n");
        return -1;
    }

    if (*out_len < 2 * in_len) {
        chip_log_error("short buffer, %d %d\n", *out_len, 2 * in_len);
        return -1;
    }

    for (i = in_len - 1; i >= 0; i--) {
        temp = in[i];
        high = (temp >> 4) & 0x0F;
        low  = (temp >> 0) & 0x0F;

        out[i * 2] = string_table[high];
        out[i * 2 + 1] = string_table[low];
    }

    *out_len = in_len * 2;

    return 0;
}

int chip_hash_digest(uint8_t *in, uint32_t in_len,
                     uint8_t *out, uint32_t *out_len, digest_t type)
{
    uint32_t result;
    hash_type_t hash_type;

    if (in == NULL || in_len == 0 ||
        out == NULL || out_len == NULL) {
        chip_log_error("invalid input args\n");
        return -1;
    }

    if (type != DIGEST_TYPE_SHA256) {
        chip_log_error("not support this type, %d\n", type);
        return -1;
    } else {
        hash_type = SHA256;
    }

    if (*out_len < DIGEST_SHA256_SIZE) {
        chip_log_error("short buffer, %d %d\n", *out_len, DIGEST_SHA256_SIZE);
        return -1;
    } else {
        *out_len = DIGEST_SHA256_SIZE;
    }

    result = ali_hash_digest(hash_type, in, in_len, out);
    if (result != ALI_CRYPTO_SUCCESS) {
        chip_log_error("ali_hash_digest fail, 0x%x\n", result);
        return -1;
    }

    return 0;
}

int chip_hmac_digest(uint8_t *key, uint32_t key_len,
                     uint8_t *in, uint32_t in_len,
                     uint8_t *out, uint32_t *out_len, digest_t type)
{
    uint32_t result;
    hash_type_t hash_type;

    if (key == NULL || key_len == 0 ||
        in == NULL || in_len == 0 ||
        out == NULL || out_len == NULL) {
        chip_log_error("invalid input args\n");
        return -1;
    }

    if (type != DIGEST_TYPE_SHA256) {
        chip_log_error("not support this type, %d\n", type);
        return -1;
    } else {
        hash_type = SHA256;
    }

    if (*out_len < DIGEST_SHA256_SIZE) {
        chip_log_error("short buffer, %d %d\n", *out_len, DIGEST_SHA256_SIZE);
        return -1;
    } else {
        *out_len = DIGEST_SHA256_SIZE;
    }

    result = ali_hmac_digest(hash_type,
                      key, key_len, in, in_len, out);
    if (result != ALI_CRYPTO_SUCCESS) {
        chip_log_error("ali_hmac_digest fail, 0x%x\n", result);
        return -1;
    }

    return 0;
}

#if defined(CONFIG_CHIP_DEBUG)
void chip_dump_buf(const char *name, uint8_t *buf, uint32_t len)
{
    char *str = NULL;
    uint32_t str_len;

    if (buf == NULL || len == 0) {
        return;
    }

    str_len = 2 * len;
    str = ls_osa_malloc(str_len + 1);
    if (str == NULL) {
        ls_osa_print("out of mem, %d\n", str_len + 1);
        return;
    } else {
        memset(str, 0, str_len + 1);
    }

    chip_hex_to_string(buf, len, str, &str_len);

    ls_osa_print("%s[len = %d]: %s\n", name, len, str);

    ls_osa_free(str);

    return;
}

#else

void chip_dump_buf(const char *name, uint8_t *buf, uint32_t len)
{
    (void)name;
    (void)buf;
    (void)len;

    return;
}

#endif

