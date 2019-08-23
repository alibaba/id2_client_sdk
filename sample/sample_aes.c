/*
 * Copyright (C) 2015-2017 Alibaba Group Holding Limited
 */

#include "ls_osa.h"
#include "ali_crypto.h"

#define BUF_SIZE (1024)
#define TEST_KEY_SIZE  (32)
#define TEST_DATA_SIZE (141)
#define TEST_ECB_SIZE  (96)
#define TEST_CBC_SIZE  (96)

#define log_err(_f, ...) \
    ls_osa_print("E %s %d: "_f, __FUNCTION__, __LINE__, ##__VA_ARGS__)

static uint8_t   plaintext[BUF_SIZE] = { 0 };
static uint8_t   ciphertext[BUF_SIZE] = { 0 };

static uint8_t _g_aes_key[TEST_KEY_SIZE] = {
   0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
   0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x0f,
   0x0f, 0x0f, 0x0e, 0x0d, 0x0c, 0x0b, 0x0a, 0x09,
   0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01
};

static uint8_t _g_aes_iv[AES_IV_SIZE] = {
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
};

static uint8_t _g_test_data[TEST_DATA_SIZE] = {
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

/*
 * Example of AES process
 */
uint32_t _example_aes_init_process_finish(
                        aes_type_t      type,
                        sym_padding_t   padding,
                        uint32_t        src_size,
                        uint8_t *       iv)
{
    void *    aes_ctx = NULL;
    size_t    aes_ctx_size;
    ali_crypto_result  result = ALI_CRYPTO_SUCCESS;
    size_t    dst_size = BUF_SIZE;
    size_t    dec_len;

    // Step 1: AES Encrypt(src_size)
    result = ali_aes_get_ctx_size(type, &aes_ctx_size);
    if (result != ALI_CRYPTO_SUCCESS) {
        log_err("%s():%d failed! %d\n", __func__, __LINE__, result);
        return result;
    }

    aes_ctx = ls_osa_malloc(aes_ctx_size);
    if (aes_ctx == NULL) {
        log_err("%s():%d failed! %d\n", __func__, __LINE__, result);
        return result;
    }

    result = ali_aes_init(type, true, _g_aes_key, NULL, 16, iv, aes_ctx);
    if (result != ALI_CRYPTO_SUCCESS) {
        log_err("aes init failed(%08x)\n", result);
        goto cleanup;
    }

    // process 32 bytes
    result = ali_aes_process(_g_test_data, ciphertext, 32, aes_ctx);
    if (result != ALI_CRYPTO_SUCCESS) {
        log_err("aes process failed(%08x)\n", result);
    }

    // finish (src_size - 16) bytes
    result = ali_aes_finish(_g_test_data + 32, src_size - 32, ciphertext + 32,
                            &dst_size, padding, aes_ctx);
    if (result != ALI_CRYPTO_SUCCESS) {
        log_err("finish fail(%08x) size(%d)\n", result, dst_size);
    }

    // Step 2: AES Decrypt(src_size)
    // Note: ali_aes_process has already processed N bytes (N=16)
    //       So add N to dst_size for decryption
    dec_len = 32 + dst_size;
    ls_osa_print("src_size(%d), dst_size(%d) dec_size(%d)\n", src_size, dst_size, dec_len);
    
    result = ali_aes_init(type, false, _g_aes_key, NULL, 16, iv, aes_ctx);
    if (result != ALI_CRYPTO_SUCCESS) {
        log_err("aes init failed(%08x)\n", result);
        goto cleanup;
    }

    result = ali_aes_process(ciphertext, plaintext, 48, aes_ctx);
    if (result != ALI_CRYPTO_SUCCESS) {
        log_err("aes process failed(%08x)\n", result);
    }

    result = ali_aes_finish(ciphertext + 48, dec_len - 48, plaintext + 48,
                                &dst_size, padding, aes_ctx);
    if (result != ALI_CRYPTO_SUCCESS) {
        log_err("aes finish failed(0x%08x)\n", result);
        goto cleanup;
    }

    // check dec result
    if (memcmp(plaintext, _g_test_data, src_size)) {
        log_err("[ERROR] aes enc/dec not match!\n", src_size);
        result = -1;
        goto cleanup;
    }

cleanup:
    if (aes_ctx) {
        ls_osa_free(aes_ctx);
        aes_ctx = NULL;
    }

    return result;
}

uint32_t aes_example(void)
{
    uint32_t result;
    uint32_t src_size;

    // AES ECB Sample
    src_size = TEST_ECB_SIZE;
    result = _example_aes_init_process_finish(AES_ECB, SYM_NOPAD, src_size, NULL);
    if (result != ALI_CRYPTO_SUCCESS) {
        ls_osa_print("test failed\n");
        return result;
    }

    ls_osa_print("====== [AES-ECB] init->process->finish           OK\n");

    // AES CBC Sample
    src_size = TEST_CBC_SIZE;
    result = _example_aes_init_process_finish(AES_CBC, SYM_PKCS5_PAD, src_size, _g_aes_iv);
    if (result != ALI_CRYPTO_SUCCESS) {
        ls_osa_print("test failed\n");
        return result;
    }

    ls_osa_print("====== [AES-CBC-PKCS5] init->process->finish     OK\n");

    return result;
}
