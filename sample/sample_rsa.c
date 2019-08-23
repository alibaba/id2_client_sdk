/*
 * Copyright (C) 2015-2017 Alibaba Group Holding Limited
 */

#include "utils.h"
#include "ali_crypto.h"

#define log_err(_f, ...) \
    ls_osa_print("E %s %d: "_f, __FUNCTION__, __LINE__, ##__VA_ARGS__)

#define RSA_KEY_LEN    (128)
static uint8_t RSA_1024_N[128] = {
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

static uint8_t RSA_1024_E[3]   = { 0x01, 0x00, 0x01 };

static uint8_t RSA_1024_D[128] = {
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

uint32_t rsa_example(void)
{
    rsa_padding_t rsa_padding;
    size_t        pub_key_len;
    size_t        key_pair_len;
    uint8_t *     pub_key = NULL;
    uint8_t *     key_pair = NULL;
    uint32_t      n_size   = RSA_KEY_LEN;
    uint32_t      d_size   = RSA_KEY_LEN;
    uint8_t       src_data[RSA_KEY_LEN];
    uint8_t       signature[RSA_KEY_LEN];
    uint8_t       plaintext[RSA_KEY_LEN];
    uint8_t *     ciphertext = plaintext;
    size_t        src_size, dst_size;
    uint32_t      result = 0;
    bool          res_verify;

    result = ali_rsa_get_pubkey_size(RSA_KEY_LEN << 3, &pub_key_len);
    if (result != ALI_CRYPTO_SUCCESS) {
        log_err("get pubkey size fail(%08x)\n", result);
        goto cleanup;
    }

    pub_key = ls_osa_malloc(pub_key_len);
    if (pub_key == NULL) {
        log_err("malloc(%d) fail\n", pub_key_len);
        result = -1;
        goto cleanup;
    }

    memset((uint8_t *)(&rsa_padding), 0, sizeof(rsa_padding_t));
    rsa_padding.type = RSAES_PKCS1_V1_5;

    // init public key with n,e
    result = ali_rsa_init_pubkey(RSA_KEY_LEN << 3, RSA_1024_N, n_size, RSA_1024_E,
                                 3, (rsa_pubkey_t *)pub_key);
    if (result != ALI_CRYPTO_SUCCESS) {
        log_err("init pubkey fail(0x%08x)\n", result);
        goto cleanup;
    }

    // encrypt buf with public key
    src_size = RSA_KEY_LEN - 11;
    memset( src_data, 0xAA, src_size );
    dst_size = RSA_KEY_LEN;

    // NOTE: src_data and ciphertext should not refer to the same buffer !
    result = ali_rsa_public_encrypt((const rsa_pubkey_t *)pub_key, src_data, src_size,
                                    ciphertext, &dst_size, rsa_padding);
    if (result) {
        log_err("rsa public encrypt failed(0x%08x)\n", result);
        goto cleanup;
    }

    result = ali_rsa_get_keypair_size(RSA_KEY_LEN << 3, &key_pair_len);
    if (result != ALI_CRYPTO_SUCCESS) {
        log_err("get keypair size fail(%08x)\n", result);
        goto cleanup;
    }

    key_pair = ls_osa_malloc(key_pair_len);
    if (key_pair == NULL) {
        log_err("malloc(%d) fail\n", key_pair_len);
        result = -1;
        goto cleanup;
    }

    // init key pair with n,e,d
    result = ali_rsa_init_keypair(RSA_KEY_LEN << 3, RSA_1024_N, n_size, RSA_1024_E,
                                  3, RSA_1024_D, d_size, NULL, 0, NULL, 0, NULL, 0,
                                  NULL, 0, NULL, 0, (rsa_keypair_t *)key_pair);
    if (result != ALI_CRYPTO_SUCCESS) {
        log_err("init_key: init keypair fail(%08x)\n", result);
        goto cleanup;
    }

    // decrypt buf with priv key
    result = ali_rsa_private_decrypt((const rsa_keypair_t *)key_pair, ciphertext, RSA_KEY_LEN,
                                     plaintext, &dst_size, rsa_padding);
    if (result) {
        log_err("rsa public decrypt failed(0x%08x)\n", result);
        goto cleanup;
    }

    if (memcmp(ciphertext, src_data, dst_size)) {
        log_err("[ERROR] RSA enc/dec not match!\n");
        result = -1;
        goto cleanup;
    }

    ls_osa_print("====== [RSA] Encrypt/Decrypt       OK\n");

    // Sample RSA Sign/Verify
    dst_size = RSA_KEY_LEN;
    
    memset((uint8_t *)(&rsa_padding), 0, sizeof(rsa_padding_t));
    rsa_padding.type = RSASSA_PKCS1_V1_5;
    rsa_padding.pad.rsassa_v1_5.type = SHA256;
    // for PKCS1_V1_5 condition
    src_size = RSA_KEY_LEN - 11;

    result = ali_rsa_sign(key_pair, src_data, src_size, signature, &dst_size, rsa_padding);
    if (result != ALI_CRYPTO_SUCCESS) {
        log_err("rsa sign fail(%08x)\n");
        goto cleanup;
    }

    result = ali_rsa_verify(pub_key, src_data, src_size, signature, dst_size, rsa_padding, &res_verify);
    if (result != ALI_CRYPTO_SUCCESS) {
        log_err("rsa verify fail(%08x)\n");
        goto cleanup;
    }

    if (res_verify)
        ls_osa_print("====== [RSA] Sign/Verify        OK\n");
    else
        ls_osa_print("====== [RSA] Sign/Verify        FAIL\n");

cleanup:
    if (pub_key) {
        ls_osa_free(pub_key);
        pub_key = NULL;
    }

    if (key_pair) {
        ls_osa_free(key_pair);
        key_pair = NULL;
    }

    return result;
}
