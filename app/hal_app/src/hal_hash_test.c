/**
 * Copyright (C) 2017-2019 Alibaba Group Holding Limited.
 */

#include "ls_osa.h"
#include "ls_hal.h"
#include "hal_test.h"

#if defined(CONFIG_HAL_CRYPTO)

#define LAST_HASH         (SM3)
#define TEST_DATA_SIZE    (141)

#ifndef MD5_HASH_SIZE
#define MD5_HASH_SIZE     (16)
#endif

#ifndef SHA1_HASH_SIZE
#define SHA1_HASH_SIZE    (20)
#endif

#ifndef SHA256_HASH_SIZE
#define SHA256_HASH_SIZE  (32)
#endif

#ifndef MAX_HASH_SIZE
#define MAX_HASH_SIZE     (64)
#endif

enum {
    HASH_NONE   = 0,
    SHA1        = 1,
    SHA224      = 2,
    SHA256      = 3,
    SHA384      = 4,
    SHA512      = 5,
    MD5         = 6,
    SM3         = 7,
};

static const uint8_t _g_test_data[TEST_DATA_SIZE] = {
   0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
   0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
   0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
   0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
   0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
   0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
   0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
   0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
   0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
   0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
   0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
   0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
   0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
   0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
   0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
   0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
   0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x00, 0x01,
   0x02, 0x03, 0x04, 0x05, 0x13
};

/* openssl calculated result */
static const uint8_t hash_md5[MD5_HASH_SIZE] = {
    0x95, 0x79, 0xa2, 0x46, 0x8e, 0xbc, 0x5b, 0xd6, 0x45, 0x57,
    0xbb, 0x4f, 0xaf, 0xae, 0x5a, 0x05
};

static const int8_t hash_sha1[SHA1_HASH_SIZE] = {
    0x54, 0x1d, 0x6f, 0x6e, 0x46, 0x7e, 0xfe, 0x1d, 0xa8, 0x66,
    0x06, 0x34, 0xb0, 0x21, 0x3d, 0x65, 0xb8, 0xa4, 0x02, 0xca
};

static const uint8_t hash_sha256[SHA256_HASH_SIZE] = {
    0x3b, 0x7f, 0x52, 0xae, 0x5b, 0xe8, 0x09, 0x19, 0x02, 0x1a,
    0x83, 0x8d, 0xcc, 0xc6, 0x01, 0xc3, 0x76, 0x41, 0x22, 0x64,
    0x4b, 0x1c, 0x35, 0xa2, 0x9d, 0xd3, 0xc5, 0x76, 0x36, 0xd7,
    0xda, 0x5f
};

int hal_hash_test(void)
{
    ls_hal_crypt_result ret;
    uint8_t           type;
    void *            hash_ctx = NULL;
    size_t            hash_ctx_size;
    uint8_t           hash[MAX_HASH_SIZE];

    for (type = SHA1; type < LAST_HASH; type++) {
        if (type == SHA1) {
            hash_ctx_size = ls_hal_sha1_get_size();
            if (hash_ctx_size == 0) {
                HAL_TEST_ERR("get ctx size fail(%08x)\n", hash_ctx_size);
                return -1;
            }
            hash_ctx = ls_osa_malloc(hash_ctx_size);
            if (hash_ctx == NULL) {
                HAL_TEST_ERR("malloc(%d) fail\n", (int)hash_ctx_size);
                return -1;
            }
            memset(hash_ctx, 0, hash_ctx_size);

            ret = ls_hal_sha1_init(hash_ctx);
            if (ret != HAL_CRYPT_SUCCESS) {
                if (ret != HAL_CRYPT_NOSUPPORT) {
                    HAL_TEST_ERR("init fail(%08x)", ret);
                    return -1;
                } else {
                    HAL_TEST_INF("[WARN] sha1 not support, continue..\n");
                    ret = 0;
                    continue;
                }
            }

            ret = ls_hal_sha1_update(hash_ctx, _g_test_data, 13);
            if (ret != HAL_CRYPT_SUCCESS) {
                HAL_TEST_ERR("update 1th fail(%08x)", ret);
            }

            ret = ls_hal_sha1_update(hash_ctx, _g_test_data + 13, 63);
            if (ret != HAL_CRYPT_SUCCESS) {
                HAL_TEST_ERR("update 2th fail(%08x)", ret);
            }

            ret = ls_hal_sha1_update(hash_ctx, _g_test_data + 13 + 63, 65);
            if (ret != HAL_CRYPT_SUCCESS) {
                HAL_TEST_ERR("update 3th fail(%08x)", ret);
            }

            ret = ls_hal_sha1_finish(hash_ctx, hash);
            if (ret != HAL_CRYPT_SUCCESS) {
                HAL_TEST_ERR("final fail(%08x)", ret);
            }

            ls_osa_free(hash_ctx);
            hash_ctx = NULL;
            if (memcmp(hash, hash_sha1, SHA1_HASH_SIZE)) {
                hal_dump_data("sha1", hash, SHA1_HASH_SIZE);
                HAL_TEST_ERR("SHA1 test fail!");
            } else {
                HAL_TEST_INF("SHA1 test success!\n");
            }
        } else if (type == SHA256) {
            hash_ctx_size = ls_hal_sha256_get_size();
            if (hash_ctx_size <= 0) {
                HAL_TEST_ERR("get ctx size fail(%08x)\n", ret);
            }
            hash_ctx = ls_osa_malloc(hash_ctx_size);
            if (hash_ctx == NULL) {
                HAL_TEST_ERR("malloc(%d) fail\n", (int)hash_ctx_size);
            }
            memset(hash_ctx, 0, hash_ctx_size);

            ret = ls_hal_sha256_init(hash_ctx);
            if (ret != HAL_CRYPT_SUCCESS) {
                if (ret != HAL_CRYPT_NOSUPPORT) {
                    HAL_TEST_ERR("init fail(%08x)", ret);
                    return -1;
                } else {
                    HAL_TEST_INF("[WARN] sha256 not support, continue..\n");
                    ret = 0;
                    continue;
                }
            }

            ret = ls_hal_sha256_update(hash_ctx, _g_test_data, 13);
            if (ret != HAL_CRYPT_SUCCESS) {
                HAL_TEST_ERR("update 1th fail(%08x)", ret);
            }
            ret = ls_hal_sha256_update(hash_ctx, _g_test_data + 13, 63);
            if (ret != HAL_CRYPT_SUCCESS) {
                HAL_TEST_ERR("update 2th fail(%08x)", ret);
            }
            ret = ls_hal_sha256_update(hash_ctx, _g_test_data + 13 + 63, 65);
            if (ret != HAL_CRYPT_SUCCESS) {
                HAL_TEST_ERR("update 3th fail(%08x)", ret);
            }

            ret = ls_hal_sha256_finish(hash_ctx, hash);
            if (ret != HAL_CRYPT_SUCCESS) {
                HAL_TEST_ERR("final fail(%08x)", ret);
            }

            ls_osa_free(hash_ctx);
            hash_ctx = NULL;

            if (memcmp(hash, hash_sha256, SHA256_HASH_SIZE)) {
                hal_dump_data("sha256", hash, SHA256_HASH_SIZE);
                HAL_TEST_ERR("sha256 test fail!\n");
            } else {
                HAL_TEST_INF("SHA256 test success!\n");
            }
        } else if (type == MD5) {
            hash_ctx_size = ls_hal_md5_get_size();
            if (hash_ctx_size <= 0) {
                HAL_TEST_ERR("get ctx size fail(%08x)\n", ret);
            }
            hash_ctx = ls_osa_malloc(hash_ctx_size);
            if (hash_ctx == NULL) {
                HAL_TEST_ERR("malloc(%d) fail\n", (int)hash_ctx_size);
            }
            memset(hash_ctx, 0, hash_ctx_size);

            ret = ls_hal_md5_init(hash_ctx);
            if (ret != HAL_CRYPT_SUCCESS) {
                if (ret != HAL_CRYPT_NOSUPPORT) {
                    HAL_TEST_ERR("init fail(%08x)", ret);
                    return -1;
                } else {
                    HAL_TEST_INF("[WARN] md5 not support, continue..\n");
                    ret = 0;
                    continue;
                }
            }

            ret = ls_hal_md5_update(hash_ctx, _g_test_data, 13);
            if (ret != HAL_CRYPT_SUCCESS) {
                HAL_TEST_ERR("update 1th fail(%08x)", ret);
            }
            ret = ls_hal_md5_update(hash_ctx, _g_test_data + 13, 63);
            if (ret != HAL_CRYPT_SUCCESS) {
                HAL_TEST_ERR("update 2th fail(%08x)", ret);
            }
            ret = ls_hal_md5_update(hash_ctx, _g_test_data + 13 + 63, 65);
            if (ret != HAL_CRYPT_SUCCESS) {
                HAL_TEST_ERR("update 3th fail(%08x)", ret);
            }

            ret = ls_hal_md5_finish(hash_ctx, hash);
            if (ret != HAL_CRYPT_SUCCESS) {
                HAL_TEST_ERR("final fail(%08x)", ret);
            }

            ls_osa_free(hash_ctx);
            hash_ctx = NULL;
            if (memcmp(hash, hash_md5, MD5_HASH_SIZE)) {
                hal_dump_data("md5", hash, MD5_HASH_SIZE);
                HAL_TEST_ERR("md5 test fail!\n");
            } else {
                HAL_TEST_INF("md5 test success!\n");
            }
        }
    }

    if (hash_ctx) {
        ls_osa_free(hash_ctx);
    }

    if (ret == HAL_CRYPT_SUCCESS) {
        HAL_TEST_INF("=========================> HAL Hash Test Pass.\n\n");
        return 0;
    } else {
        HAL_TEST_ERR("=========================> HAL Hash Test Fail.\n\n");
        return -1;
    }
}

#endif  /* CONFIG_HAL_CRYPTO */

