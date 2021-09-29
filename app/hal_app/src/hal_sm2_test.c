/*
 * SM4/SMS4 algorithm test programme
 * 2012-4-21
 */

#include "ls_hal.h"
#include "hal_test.h"

#define SM2_KEY_LEN (32)

#define IMPL_ECP_DP_SMP256R1 (13)

static uint8_t data[] = {
    0x65, 0x6E, 0x63, 0x72, 0x79, 0x70, 0x74, 0x69,
    0x6F, 0x6E, 0x20, 0x73, 0x74, 0x61, 0x6E, 0x64,
    0x61, 0x72, 0x64
};

static int curve = IMPL_ECP_DP_SMP256R1;

static uint8_t D[] = {
    0x00, 0x8b, 0xf0, 0x64, 0x82, 0x5c, 0xac, 0xa8,
    0x84, 0x5d, 0xf0, 0xc1, 0x74, 0x7b, 0x7a, 0xa7,
    0xe3, 0xd4, 0xa4, 0x39, 0x00, 0xd7, 0x5d, 0x71,
    0x73, 0xb1, 0x4d, 0x3f, 0xce, 0xbc, 0xc2, 0xde, 0xca
};

static uint8_t X[] = {
    0x00, 0x96, 0xff, 0xa4, 0x02, 0x4b, 0xa8, 0x3d,
    0x39, 0xdc, 0x84, 0x6b, 0x9e, 0x11, 0x24, 0xbd,
    0xa1, 0x0e, 0x33, 0xfd, 0x77, 0x36, 0x1c, 0x16,
    0x03, 0xf7, 0x29, 0x13, 0x5b, 0xb8, 0xf6, 0x44, 0x8a
};

static uint8_t Y[] = {
    0x00, 0xc6, 0x0c, 0x3c, 0x55, 0xf7, 0x37, 0xb5,
    0x16, 0x3c, 0x23, 0x99, 0x24, 0xc3, 0x8f, 0x9b,
    0x60, 0x92, 0x3f, 0xd1, 0x2c, 0xf8, 0xcf, 0x96,
    0x15, 0x20, 0x83, 0x1b, 0x55, 0x01, 0x5b, 0xc7, 0x0a
};

int sm2_public_encrypt(uint8_t *x, size_t x_len,
                       uint8_t *y, size_t y_len,
                       uint8_t *in, size_t in_len,
                       uint8_t *out, size_t *out_len)
{
    int ret;
    uint32_t size;
    void *ctx = NULL;

    if (x == NULL || x_len == 0 ||
        y == NULL || y_len == 0 ||
        in == NULL || in_len == 0 ||
        out == NULL || out_len == NULL) {
        HAL_TEST_ERR("invalid input args\n");
        return -1;
    }

    size = ls_hal_ecc_get_ctx_size();
    ctx = ls_osa_malloc(size);
    if (ctx == NULL) {
        HAL_TEST_ERR("out of mem, %d\n", size);
        return -1;
    }

    ls_hal_ecc_init(ctx);

    ret = ls_hal_ecc_init_pubkey(ctx, curve,
                                 x, x_len, y, y_len);
    if (ret < 0) {
        HAL_TEST_ERR("ecc init fail, 0x%x\n", ret);
        goto _out;
    }

    ret = ls_hal_sm2_encrypt(ctx, in, in_len, out, out_len);
    if (ret < 0) {
        HAL_TEST_ERR("hal sm2 encrypt fail, 0x%x\n", ret);
        goto _out;
    }

    ret = 0;

_out:
    if (ctx != NULL) {
        ls_hal_ecc_cleanup(ctx);
        ls_osa_free(ctx);
    }

    return ret;
}

int sm2_private_decrypt(uint8_t *d, size_t d_len,
                        uint8_t *in, size_t in_len,
                        uint8_t *out, size_t *out_len)
{
    int ret;
    uint32_t size;
    void *ctx = NULL;

    if (d == NULL || d_len == 0 ||
        in == NULL || in_len == 0 ||
        out == NULL || out_len == 0) {
        HAL_TEST_ERR("invalid input args\n");
        return -1;
    }

    size = ls_hal_ecc_get_ctx_size();
    ctx = ls_osa_malloc(size);
    if (ctx == NULL) {
        HAL_TEST_ERR("out of mem, %d\n", size);
        return -1;
    }

    ls_hal_ecc_init(ctx);

    ret = ls_hal_ecc_init_keypair(ctx, curve,
                     d, d_len, d, d_len, d, d_len);
    if (ret < 0) {
        HAL_TEST_ERR("ecc init fail, 0x%x\n", ret);
        goto _out;
    }

    ret = ls_hal_sm2_decrypt(ctx, in, in_len, out, out_len);
    if (ret < 0) {
        HAL_TEST_ERR("hal sm2 decrypt fail, 0x%x\n", ret);
        goto _out;
    }

    ret = 0;

_out:
    if (ctx != NULL) {
        ls_hal_ecc_cleanup(ctx);
        ls_osa_free(ctx);
    }

    return ret;
}

int sm2_private_sign(uint8_t *d, size_t d_len,
                     uint8_t *id, size_t id_len,
                     uint8_t *msg, size_t msg_len,
                     uint8_t *sig, size_t sig_len)
{
    int ret;
    uint32_t size;
    void *ctx = NULL;
    uint8_t hash[32];
    size_t hash_len = 32;

    if (d == NULL || d_len == 0 ||
        id == NULL || id_len == 0 ||
        msg == NULL || msg_len == 0 ||
        sig == NULL || sig_len == 0) {
        HAL_TEST_ERR("invalid input args\n");
        return -1;
    }

    size = ls_hal_ecc_get_ctx_size();
    ctx = ls_osa_malloc(size);
    if (ctx == NULL) {
        HAL_TEST_ERR("out of mem, %d\n", size);
        return -1;
    }

    ls_hal_ecc_init(ctx);

#if 0
    ret = ls_hal_ecc_init_keypair(ctx, curve,
                                  NULL, 0,
                                  NULL, 0,
                                  d, d_len);
#else
    ret = ls_hal_ecc_init_keypair(ctx, curve,
                     X, sizeof(X), Y, sizeof(X), d, d_len);
#endif
    if (ret < 0) {
        HAL_TEST_ERR("ecc init fail, 0x%x\n", ret);
        goto _out;
    }

    ret = ls_hal_sm2_msg_digest(ctx, HAL_TYPE_SM3,
                                id, id_len,
                                msg, msg_len,
                                hash, &hash_len);
    if (ret < 0) {
        HAL_TEST_ERR("hal sm2 msg digest fail, %d\n", ret);
        goto _out;
    }

    ret = ls_hal_sm2_sign(ctx, (const uint8_t *)hash, hash_len, sig, &sig_len);
    if (ret < 0) {
        HAL_TEST_ERR("hal sm2 sign fail, %d\n", ret);
        goto _out;
    }

    if (sig_len != 64) {
        HAL_TEST_ERR("sm2 invalid sign length, %d\n", (int)sig_len);
        ret = -1;
        goto _out;
    }

_out:
    if (ctx != NULL) {
        ls_hal_ecc_cleanup(ctx);
        ls_osa_free(ctx);
    }

    return ret;
}

int sm2_public_verify(uint8_t *x, size_t x_len,
                      uint8_t *y, size_t y_len,
                      uint8_t *id, size_t id_len,
                      uint8_t *msg, size_t msg_len,
                      uint8_t *sig, size_t sig_len)
{
    int ret;
    uint32_t size;
    void *ctx = NULL;
    uint8_t hash[32];
    size_t hash_len = 32;

    if (x == NULL || x_len == 0 ||
        y == NULL || y_len == 0 ||
        id == NULL || id_len == 0 ||
        msg == NULL || msg_len == 0 ||
        sig == NULL || sig_len == 0) {
        HAL_TEST_ERR("invalid input args\n");
        return -1;
    }

    size = ls_hal_ecc_get_ctx_size();
    ctx = ls_osa_malloc(size);
    if (ctx == NULL) {
        HAL_TEST_ERR("out of mem, %d\n", size);
        return -1;
    }

    ls_hal_ecc_init(ctx);

    ret = ls_hal_ecc_init_pubkey(ctx, curve,
                                 x, x_len, y, y_len);
    if (ret < 0) {
        HAL_TEST_ERR("ecc init fail, 0x%x\n", ret);
        goto _out;
    }

    ret = ls_hal_sm2_msg_digest(ctx, HAL_TYPE_SM3,
                 id, id_len, msg, msg_len, hash, &hash_len);
    if (ret < 0) {
        HAL_TEST_ERR("hal sm2 msg digest fail, %d\n", ret);
        goto _out;
    }

    ret = ls_hal_sm2_verify(ctx, hash, hash_len, sig, sig_len);
    if (ret < 0) {
        HAL_TEST_ERR("hal sm2 sign fail, %d\n", ret);
        goto _out;
    }

_out:
    if (ctx != NULL) {
        ls_hal_ecc_cleanup(ctx);
        ls_osa_free(ctx);
    }

    return ret;
}

int hal_sm2_test()
{
    int ret = 0;
    uint8_t enc_data[128];
    uint8_t dec_data[128];
    size_t length = 128;
    char *msg = "Data to be Signed";
    char *id = "1222";
    uint8_t sig_data[128];
    size_t sig_len = 128;

    ret = sm2_public_encrypt(X, sizeof(X), Y, sizeof(Y),
                     data, 19, enc_data, &length);
    if (ret < 0) {
        HAL_TEST_ERR("sm2 public encrypt fail\n");
        goto _out;
    }

    ret = sm2_private_decrypt(D, sizeof(D),
                     enc_data, length, dec_data, &length);
    if (ret < 0) {
        HAL_TEST_ERR("sm2 private decrypt fail\n");
        goto _out;
    }

    if (length != sizeof(data) ||
        memcmp(dec_data, data, length)) {
        HAL_TEST_ERR("--->sm2 encrypt and decrypt fail!!!!!\n");
        goto _out;
    }

    sig_len = 64;
    ret = sm2_private_sign(D, sizeof(Y), (uint8_t *)id, strlen(id),
                           (uint8_t *)msg, strlen(msg), sig_data, sig_len);
    if (ret < 0) {
        HAL_TEST_ERR("sm2 private sign fail\n");
        goto _out;
    }

    sig_len = 64;
    ret = sm2_public_verify(X, sizeof(X), Y, sizeof(Y),
                            (uint8_t *)id, strlen(id),
                            (uint8_t *)msg, strlen(msg),
                            sig_data, sig_len);
    if (ret < 0) {
        HAL_TEST_ERR("sm2 public verify fail\n");
        goto _out;
    }

_out:
    if (0 == ret) {
        HAL_TEST_INF("=============================> HAL SM2 Test Pass.\n\n");
    } else {
        HAL_TEST_INF("=============================> HAL SM2 Test Fail.\n\n");
    }

    return ret;
}
