/**
 * Copyright (C) 2017-2019 Alibaba Group Holding Limited.
 */

#include "ls_hal.h"
#include "hal_test.h"

#if defined(CONFIG_HAL_CRYPTO)

#define RSA_KEY_LEN (128)

static const uint8_t RSA_N[128] = {
    0xa5, 0x6e, 0x4a, 0x0e, 0x70, 0x10, 0x17, 0x58, 0x9a, 0x51, 0x87, 0xdc,
    0x7e, 0xa8, 0x41, 0xd1, 0x56, 0xf2, 0xec, 0x0e, 0x36, 0xad, 0x52, 0xa4,
    0x4d, 0xfe, 0xb1, 0xe6, 0x1f, 0x7a, 0xd9, 0x91, 0xd8, 0xc5, 0x10, 0x56,
    0xff, 0xed, 0xb1, 0x62, 0xb4, 0xc0, 0xf2, 0x83, 0xa1, 0x2a, 0x88, 0xa3,
    0x94, 0xdf, 0xf5, 0x26, 0xab, 0x72, 0x91, 0xcb, 0xb3, 0x07, 0xce, 0xab,
    0xfc, 0xe0, 0xb1, 0xdf, 0xd5, 0xcd, 0x95, 0x08, 0x09, 0x6d, 0x5b, 0x2b,
    0x8b, 0x6d, 0xf5, 0xd6, 0x71, 0xef, 0x63, 0x77, 0xc0, 0x92, 0x1c, 0xb2,
    0x3c, 0x27, 0x0a, 0x70, 0xe2, 0x59, 0x8e, 0x6f, 0xf8, 0x9d, 0x19, 0xf1,
    0x05, 0xac, 0xc2, 0xd3, 0xf0, 0xcb, 0x35, 0xf2, 0x92, 0x80, 0xe1, 0x38,
    0x6b, 0x6f, 0x64, 0xc4, 0xef, 0x22, 0xe1, 0xe1, 0xf2, 0x0d, 0x0c, 0xe8,
    0xcf, 0xfb, 0x22, 0x49, 0xbd, 0x9a, 0x21, 0x37
};
static const uint8_t RSA_E[3]   = { 0x01, 0x00, 0x01 };
static const uint8_t RSA_D[128] = {
    0x33, 0xa5, 0x04, 0x2a, 0x90, 0xb2, 0x7d, 0x4f, 0x54, 0x51, 0xca, 0x9b,
    0xbb, 0xd0, 0xb4, 0x47, 0x71, 0xa1, 0x01, 0xaf, 0x88, 0x43, 0x40, 0xae,
    0xf9, 0x88, 0x5f, 0x2a, 0x4b, 0xbe, 0x92, 0xe8, 0x94, 0xa7, 0x24, 0xac,
    0x3c, 0x56, 0x8c, 0x8f, 0x97, 0x85, 0x3a, 0xd0, 0x7c, 0x02, 0x66, 0xc8,
    0xc6, 0xa3, 0xca, 0x09, 0x29, 0xf1, 0xe8, 0xf1, 0x12, 0x31, 0x88, 0x44,
    0x29, 0xfc, 0x4d, 0x9a, 0xe5, 0x5f, 0xee, 0x89, 0x6a, 0x10, 0xce, 0x70,
    0x7c, 0x3e, 0xd7, 0xe7, 0x34, 0xe4, 0x47, 0x27, 0xa3, 0x95, 0x74, 0x50,
    0x1a, 0x53, 0x26, 0x83, 0x10, 0x9c, 0x2a, 0xba, 0xca, 0xba, 0x28, 0x3c,
    0x31, 0xb4, 0xbd, 0x2f, 0x53, 0xc3, 0xee, 0x37, 0xe3, 0x52, 0xce, 0xe3,
    0x4f, 0x9e, 0x50, 0x3b, 0xd8, 0x0c, 0x06, 0x22, 0xad, 0x79, 0xc6, 0xdc,
    0xee, 0x88, 0x35, 0x47, 0xc6, 0xa3, 0xb3, 0x25
};

static int blinding(void *rng_state, unsigned char *output, size_t len)
{
    memset(output, 0, len);
    output[len-1]=1;
    return 0;
}

static int _hal_encrypt_decrypt(void)
{
    int ret = 0;
    uint8_t src_data[RSA_KEY_LEN];
    uint8_t plaintext[RSA_KEY_LEN];
    uint8_t ciphertext[RSA_KEY_LEN];
    size_t  src_size;
    void    *context = NULL;
    void    *ctx_keypair = NULL;
    size_t  ctx_size;

    ctx_size = ls_hal_rsa_get_ctx_size();

    context = ls_osa_malloc(ctx_size);
    ret = ls_hal_rsa_init(context);
    if (ret != HAL_CRYPT_SUCCESS) {
        HAL_TEST_ERR("rsa: init fail(%08x)\n", ret);
        goto cleanup;
    }

    ctx_keypair = ls_osa_malloc(ctx_size);
    ret = ls_hal_rsa_init(ctx_keypair);
    if (ret != HAL_CRYPT_SUCCESS) {
        HAL_TEST_ERR("rsa: init fail(%08x)\n", ret);
        goto cleanup;
    }

    src_size = RSA_KEY_LEN;
    memset(src_data, 0xa, src_size);
    
    ret = ls_hal_rsa_init_pubkey(context, RSA_KEY_LEN*8,
                                 RSA_N, 128,
                                 RSA_E, 3);
    if (ret) {
        HAL_TEST_ERR("failed(0x%08x)\n", ret);
        goto cleanup;
    }

    ret = ls_hal_rsa_public(context, src_data, ciphertext, RSA_KEY_LEN);
    if (ret != HAL_CRYPT_SUCCESS) {
        HAL_TEST_ERR("rsa: public encrypt fail(%08x)\n", ret);
        goto cleanup;
    }

    ret = ls_hal_rsa_init_keypair(ctx_keypair, RSA_KEY_LEN*8,
                                  RSA_N, 128,
                                  NULL,  0,
                                  RSA_D, 128,
                                  NULL,  0,
                                  NULL,  0,
                                  NULL,  0,
                                  NULL,  0,
                                  NULL,  0);
    if (ret != HAL_CRYPT_SUCCESS) {
        HAL_TEST_ERR("init keypair failed(%08x)\n", ret);
        goto cleanup;
    }

    ret = ls_hal_rsa_private(ctx_keypair, blinding, ciphertext, plaintext, RSA_KEY_LEN);
    if (ret != HAL_CRYPT_SUCCESS) {
        HAL_TEST_ERR("rsa: private decrypt fail(%08x)\n", ret);
        goto cleanup;
    }

    if (memcmp(src_data, plaintext, RSA_KEY_LEN)) {
        HAL_TEST_ERR("RSA encrypt/decrypt test fail!\n");
        hal_dump_data("plaintext", plaintext, RSA_KEY_LEN);
        hal_dump_data("ciphertext", ciphertext, RSA_KEY_LEN);
    } else {
        HAL_TEST_INF("RSA encrypt/decrypt test success\n");
    }

cleanup:
    if (context)
        ls_osa_free(context);

    if (ctx_keypair)
        ls_osa_free(ctx_keypair);

    return ret;
}

int hal_rsa_test(void)
{
    int            ret;
    ret = _hal_encrypt_decrypt();
    if (ret < 0) {
        goto _out;
    }

_out:
    if (0 == ret) {
        HAL_TEST_INF("=============================> HAL RSA Test Pass.\n\n");
    } else {
        HAL_TEST_INF("=============================> HAL RSA Test Fail.\n\n");
    }

    return ret;
}

#endif  /* CONFIG_HAL_CRYPTO */

