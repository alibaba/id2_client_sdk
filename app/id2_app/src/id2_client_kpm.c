/*
 * Copyright (C) 2020-2022 Alibaba Group Holding Limited
 */

#include "id2_test.h"
#include "id2_client_kpm.h"

#define ID2_CHALLENGE   "55B83408399FA660F05C82E4F25333DC"
#define ID2_TIMESTAMP   "1512022279204"

#define ID2_KPM_MAX_TST_LEN    128

static uint8_t counter[16] = {
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0x00, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06
};

static void _generate_random_data(uint8_t *data, uint32_t size)
{
    uint32_t i;

    for (i = 0; i < size; i++) {
        data[i] = i % 256;
    }

    return;
}

static int _id2_client_kpm_do_aes_cipher(uint8_t key_idx)
{
    irot_result_t result = 0;
    uint8_t *iv = NULL;
    uint32_t i, iv_len;
    uint32_t tst_len, in_len, out_len;
    uint8_t cipher_suite;
    uint8_t padding_type;
    uint8_t tst_data[ID2_KPM_MAX_TST_LEN];
    uint8_t dec_data[ID2_KPM_MAX_TST_LEN];
    uint8_t enc_data[ID2_KPM_MAX_TST_LEN];

    /* generate test raw data */
    _generate_random_data(tst_data, ID2_KPM_MAX_TST_LEN);

    for (i = 0; i < 4; i++) {     
        ID2_DBG_LOG("id2_client_kpm_do_aes_cipher -- loop_count: %d\n", i); 

        if (i == 0) {
            cipher_suite = LS_KPM_CIPHER_SUITE_AES_ECB;
            padding_type = LS_KPM_SYM_NO_PADDING;
            iv = NULL;
            iv_len = 0;
        } else if (i == 1) {
            cipher_suite = LS_KPM_CIPHER_SUITE_AES_ECB;
            padding_type = LS_KPM_SYM_PADDING_PKCS5;
            iv = NULL;
            iv_len = 0;
        } else if (i == 2) {
            cipher_suite = LS_KPM_CIPHER_SUITE_AES_CBC;
            padding_type = LS_KPM_SYM_NO_PADDING;
            iv = counter;
            iv_len = 16;
        } else if (i == 3) {
            cipher_suite = LS_KPM_CIPHER_SUITE_AES_CBC;
            padding_type = LS_KPM_SYM_PADDING_PKCS5;
            iv = counter;
            iv_len = 16;
        }

        /* set test data length */
        tst_len = 16;

        in_len = tst_len;
        out_len = ID2_KPM_MAX_TST_LEN;
        result = id2_client_kpm_encrypt(key_idx, cipher_suite,
                        padding_type, iv, iv_len, tst_data, in_len, enc_data, &out_len);
        if (result != IROT_SUCCESS) {
            ID2_DBG_LOG("id2_client_kpm_encrypt fail, %d\n", result);
            return result;
        }

        in_len = out_len;
        out_len = ID2_KPM_MAX_TST_LEN;
        result = id2_client_kpm_decrypt(key_idx, cipher_suite,
                            padding_type, iv, iv_len, enc_data, in_len, dec_data, &out_len);
        if (result != IROT_SUCCESS) {
            ID2_DBG_LOG("id2_client_kpm_decrypt fail, %d\n", result);
            return result;
        }

        if (out_len != tst_len) {
            ID2_DBG_LOG("data length is not equal, %d %d\n", out_len, tst_len);
            return IROT_ERROR_GENERIC;
        }

        if (memcmp(dec_data, tst_data, tst_len)) {
            ID2_DBG_LOG("data is not equal, %d %d\n", out_len, tst_len);
            return IROT_ERROR_GENERIC;
        }
    }

    return IROT_SUCCESS;
}

static int _id2_client_kpm_do_sm4_cipher(uint8_t key_idx)
{
    irot_result_t result = 0;
    uint8_t *iv = NULL;
    uint32_t i, iv_len;
    uint32_t tst_len, in_len, out_len;
    uint8_t cipher_suite;
    uint8_t padding_type;
    uint8_t tst_data[ID2_KPM_MAX_TST_LEN];
    uint8_t dec_data[ID2_KPM_MAX_TST_LEN];
    uint8_t enc_data[ID2_KPM_MAX_TST_LEN];

    /* generate test raw data */
    _generate_random_data(tst_data, ID2_KPM_MAX_TST_LEN);

    for (i = 0; i < 4; i++) {     
        ID2_DBG_LOG("id2_client_kpm_do_aes_cipher -- loop_count: %d\n", i); 

        if (i == 0) {
            cipher_suite = LS_KPM_CIPHER_SUITE_SM4_ECB;
            padding_type = LS_KPM_SYM_NO_PADDING;
            iv = NULL;
            iv_len = 0;
        } else if (i == 1) {
            cipher_suite = LS_KPM_CIPHER_SUITE_SM4_ECB;
            padding_type = LS_KPM_SYM_PADDING_PKCS5;
            iv = NULL;
            iv_len = 0;
        } else if (i == 2) {
            cipher_suite = LS_KPM_CIPHER_SUITE_SM4_CBC;
            padding_type = LS_KPM_SYM_NO_PADDING;
            iv = counter;
            iv_len = 16;
        } else if (i == 3) {
            cipher_suite = LS_KPM_CIPHER_SUITE_SM4_CBC;
            padding_type = LS_KPM_SYM_PADDING_PKCS5;
            iv = counter;
            iv_len = 16;
        }

        /* set test data length */
        tst_len = 16;

        in_len = tst_len;
        out_len = ID2_KPM_MAX_TST_LEN;
        result = id2_client_kpm_encrypt(key_idx, cipher_suite,
                        padding_type, iv, iv_len, tst_data, in_len, enc_data, &out_len);
        if (result != IROT_SUCCESS) {
            ID2_DBG_LOG("id2_client_kpm_encrypt fail, %d\n", result);
            return result;
        }

        in_len = out_len;
        out_len = ID2_KPM_MAX_TST_LEN;
        result = id2_client_kpm_decrypt(key_idx, cipher_suite,
                            padding_type, iv, iv_len, enc_data, in_len, dec_data, &out_len);
        if (result != IROT_SUCCESS) {
            ID2_DBG_LOG("id2_client_kpm_decrypt fail, %d\n", result);
            return result;
        }

        if (out_len != tst_len) {
            ID2_DBG_LOG("data length is not equal, %d %d\n", out_len, tst_len);
            return IROT_ERROR_GENERIC;
        }

        if (memcmp(dec_data, tst_data, tst_len)) {
            ID2_DBG_LOG("data is not equal, %d %d\n", out_len, tst_len);
            return IROT_ERROR_GENERIC;
        }
    }

    return IROT_SUCCESS;
}


int id2_client_kpm_unit_test(uint8_t key_idx)
{
    irot_result_t result = 0;
    uint32_t key_type;

    result = id2_client_kpm_get_key_type(key_idx, &key_type);
    if (result != IROT_SUCCESS) {
        ID2_DBG_LOG("id2_client_kpm_get_key_type fail, %d\n", result);
        return result;
    }

    if (key_type == LS_KPM_KEY_TYPE_AES) {
        result = _id2_client_kpm_do_aes_cipher(key_idx);
        if (result != IROT_SUCCESS) {
            ID2_DBG_LOG("_id2_client_kpm_do_aes_cipher fail\n");
            return -1;
        }
    } else if (key_type == LS_KPM_KEY_TYPE_SM4) {
        result = _id2_client_kpm_do_sm4_cipher(key_idx);
        if (result != IROT_SUCCESS) {
            ID2_DBG_LOG("_id2_client_kpm_do_sm4_cipher fail\n");
            return -1;
        }
    } else {
        ID2_DBG_LOG("only support this key type, %d\n", key_type);
        return -1;
    }

    return 0;
}

int id2_client_kpm_test(uint8_t key_idx, uint8_t key_info, char *kpm_data)
{
    int ret = 0;
    bool is_prov = false;
    uint32_t kpm_data_len;
    uint32_t key_type;

    /* index is set to invaid, no need to execute */
    if (key_idx == LS_KPM_KEY_IDX_INVALID) {
        return 0;
    }

    /* import data is invalid, quite directly */
    kpm_data_len = strlen(kpm_data);
    if (kpm_data_len <= 2 * ID2_ID_MIN_LEN) {
        return 0;
    }

    ID2_DBG_LOG("================= ID2 Client KPM Test Start!\n");

    if (key_idx == LS_KPM_KEY_IDX_ID2) {
        ID2_DBG_LOG("This index %s has been reserved for ID2\n");
        ret = -1;
        goto _out;
    }

    ret = id2_client_kpm_get_prov_stat(key_idx, &is_prov);
    if (ret != IROT_SUCCESS) {
        ID2_DBG_LOG("id2_client_kpm_get_prov_stat fail, %d\n", ret);
        ret = -1;
        goto _out;
    }

    if (is_prov == true) {
        ret = id2_client_kpm_delete_key(key_idx);
        if (ret != IROT_SUCCESS) {
            ID2_DBG_LOG("id2_client_delete_key fail, %d\n", ret);
            goto _out;
        }
    }

    /* reset to not prov state */
    is_prov = false;

    ret = id2_client_kpm_import_key(key_idx, (uint8_t *)kpm_data, strlen(kpm_data));
    if (ret != IROT_SUCCESS) {
        ID2_DBG_LOG("id2_client_kpm_import_key fail, %d\n", ret);
        goto _out;
    } else {
        is_prov = true;
    }

    ret = id2_client_kpm_get_key_type(key_idx, &key_type);
    if (ret != IROT_SUCCESS) {
        ID2_DBG_LOG("id2_client_kpm_get_key_type fail, %d\n", ret);
        goto _out;
    } else {
        if (key_type == LS_KPM_KEY_TYPE_AES) {
            ID2_DBG_LOG("key [index = %d] type is AES\n", key_idx);

            if (key_info != LS_KPM_KEY_INFO_AES_128 &&
                key_info != LS_KPM_KEY_INFO_AES_192 &&
                key_info != LS_KPM_KEY_INFO_AES_256) {
                ID2_DBG_LOG("key info %s is not match\n", key_info);
                ret = -1;
                goto _out;
            }
        } else if (key_type == LS_KPM_KEY_TYPE_SM4) {
            ID2_DBG_LOG("key [index = %d] type is SM4\n", key_idx);

            if (key_info != LS_KPM_KEY_INFO_SM4_128) {
                ID2_DBG_LOG("key info %s is not match\n", key_info);
                ret = -1;
                goto _out;
            }
        } else {
            ID2_DBG_LOG("not support this key type, %d\n", key_type);
            ret = -1;
            goto _out;
        }
    }

    ret = id2_client_kpm_unit_test(key_idx);
    if (ret < 0) {
        ID2_DBG_LOG("id2_client_kpm_unit_test fail\n");
        goto _out;
    } 

_out:
    if (is_prov == true) {
        ret = id2_client_kpm_delete_key(key_idx); 
        if (ret != IROT_SUCCESS) {
            ID2_DBG_LOG("id2_client_delete_key fail, %d\n", ret);
        }
    }

    if (ret < 0) {
        ID2_DBG_LOG("================= ID2 Client KPM Test Failed!\n");
    } else {
        ID2_DBG_LOG("================= ID2 Client KPM Test Success!\n");
    }

    return ret;
}

