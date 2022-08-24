/*
 * Copyright (C) 2020-2022 Alibaba Group Holding Limited
 */

#include "id2_config.h"
#include "id2_plat.h"
#include "id2_priv.h"
#include "id2_client.h"
#include "id2_client_kpm.h"
#include "ali_crypto.h"
#include "km.h"

#define LS_KPM_DATA_MAGIC    0x4B
#define LS_KPM_DATA_VERSION  0x01

#define ID2_KM_NAME_MAX_LEN  0x10

#define ID2_KM_NAME_PREFIX   "ID2IntStr_"

#define ID2_BASE64_LEN(len)  ((len + 2) / 3 * 4)

typedef struct _id2_kpm_head_t {
    uint8_t magic;
    uint8_t version;
    uint8_t key_idx;
    uint8_t key_info;
} id2_kpm_head_t;

static void _id2_kpm_get_km_name(uint8_t kidx, char *name, uint32_t *name_len)
{
     memset(name, 0, ID2_KM_NAME_MAX_LEN);

     ls_osa_snprintf(name, ID2_KM_NAME_MAX_LEN, "%s%02x", ID2_KM_NAME_PREFIX, kidx);

     *name_len = (uint32_t)strlen(name);

     return;
}

static irot_result_t _id2_kpm_kcv_validation(uint8_t kidx, uint8_t cipher_suite,
                                  uint8_t padding_type, uint8_t *kcv_data, uint32_t kcv_len)
{
    irot_result_t result = IROT_SUCCESS;
    uint8_t id_buf[ID2_ID_MAX_LEN];
    uint32_t id_len = ID2_ID_MAX_LEN;
    uint8_t *out_buf = NULL;
    uint32_t out_len;

    result = id2_client_get_id(id_buf, &id_len);
    if (result != IROT_SUCCESS) {
        id2_log_error("get id2 id fail, %d\n", result);
        return result;
    }

    out_len = kcv_len;
    out_buf = ls_osa_malloc(out_len);
    if (out_buf == NULL) {
        id2_log_error("out of mem, %d\n", out_len);
        return IROT_ERROR_OUT_OF_MEMORY;
    }

    result = id2_client_kpm_decrypt(kidx, cipher_suite, padding_type,
                                    NULL, 0, kcv_data, kcv_len, out_buf, &out_len);
    if (result != IROT_SUCCESS) {
        id2_log_error("id2 kpm decrypt fail, %d\n", result);
        goto _out;
    }

    if (out_len != id_len) {
        id2_log_error("id length is not equal, %d %d\n", out_len, id_len);
        result = IROT_ERROR_GENERIC;
        goto _out;
    }

    if (memcmp(out_buf, id_buf, id_len)) {
        id2_log_error("id data is not equal\n");
        result = IROT_ERROR_GENERIC;
        goto _out;
     }

    result = IROT_SUCCESS;

_out:
    if (out_buf != NULL) {
        ls_osa_free(out_buf);
    }

    return result;
}

/* symmetric and no padding */
static irot_result_t _id2_kpm_do_cipher(uint8_t kidx, uint8_t cipher_suite,
                                 uint8_t *iv, uint32_t iv_len,
                                 uint8_t *in, uint32_t in_len, uint8_t *out, uint32_t *out_len, bool is_enc)
{
    km_sym_param param;
    uint32_t km_ret;
    uint32_t purpose_type;
    uint32_t name_len;
    size_t tmp_len;
    char name[ID2_KM_NAME_MAX_LEN];

    if (is_enc == true) {
        purpose_type = KM_PURPOSE_ENCRYPT;
    } else {
        purpose_type = KM_PURPOSE_DECRYPT;
    }

    switch(cipher_suite) {
        case LS_KPM_CIPHER_SUITE_AES_ECB: {
            param.key_type = KM_AES;
            param.cipher_param.purpose_type = purpose_type;
            param.cipher_param.block_mode = KM_ECB;
            param.cipher_param.padding_type = KM_NO_PADDING;

            iv = NULL;
            iv_len = 0;

            break;
        }
        case LS_KPM_CIPHER_SUITE_AES_CBC: {
            if (iv == NULL || iv_len == 0) {
                id2_log_error("invalid aes iv params\n");
                return IROT_ERROR_BAD_PARAMETERS;
            }

            param.key_type = KM_AES;
            param.cipher_param.purpose_type = purpose_type;
            param.cipher_param.block_mode = KM_CBC;
            param.cipher_param.padding_type = KM_NO_PADDING;

            break;
        }
        case LS_KPM_CIPHER_SUITE_SM4_ECB: {
            param.key_type = KM_SM4;
            param.cipher_param.purpose_type = purpose_type;
            param.cipher_param.block_mode = KM_ECB;
            param.cipher_param.padding_type = KM_NO_PADDING;

            iv = NULL;
            iv_len = 0;

            break;
        }
        case LS_KPM_CIPHER_SUITE_SM4_CBC: {
            if (iv == NULL || iv_len == 0) {
                id2_log_error("invalid sm4 iv params\n");
                return IROT_ERROR_BAD_PARAMETERS;
            }

            param.key_type = KM_SM4;
            param.cipher_param.purpose_type = purpose_type;
            param.cipher_param.block_mode = KM_CBC;
            param.cipher_param.padding_type = KM_NO_PADDING;
   
            break;
        }
        default:
            id2_log_error("not support this cipher suite, %d\n", cipher_suite);
            return IROT_ERROR_NOT_SUPPORTED;
    }

    /* convert key index to km name */
    _id2_kpm_get_km_name(kidx, name, &name_len);

    tmp_len = *out_len;
    km_ret = km_cipher(name, name_len, &param,
                iv, iv_len, in, in_len, out, &tmp_len);
    if (km_ret != KM_SUCCESS) {
        id2_log_error("km cipher fail, 0x%x\n", km_ret);
        return IROT_ERROR_GENERIC;
    }

    *out_len = tmp_len;

    return IROT_SUCCESS;
}

irot_result_t id2_client_kpm_get_prov_stat(uint8_t key_idx, bool *is_prov)
{
    uint32_t km_ret;
    uint32_t name_len;
    uint32_t state;
    char name[ID2_KM_NAME_MAX_LEN];

    id2_log_debug("[id2_client_kpm_get_prov_stat enter.]\n");

    if (!is_id2_client_inited()) {
        id2_log_error("id2 not inited.\n");
        return IROT_ERROR_GENERIC;
    }

    if (is_prov == NULL) {
        id2_log_error("invalid input arg\n");
        return IROT_ERROR_BAD_PARAMETERS;
    } else {
        *is_prov = false;
    }

    if (key_idx == LS_KPM_KEY_IDX_ID2) {
        id2_log_error("not support id2 key index, %d\n", key_idx);
        return IROT_ERROR_NOT_SUPPORTED;
    }

    _id2_kpm_get_km_name(key_idx, name, &name_len);

    id2_log_debug("km name: %s %d\n", name, name_len);

    km_ret = km_get_prov_state(name, name_len, &state);
    if (km_ret != KM_SUCCESS) {
        id2_log_error("km_get_prov_state, 0x%x\n", km_ret);
        return IROT_ERROR_GENERIC;
    }

    if (state == 1) {
        *is_prov = true;
    }

    id2_log_debug("prov state: %s\n", *is_prov == true ? "true" : "false");

    return IROT_SUCCESS;
}

irot_result_t id2_client_kpm_get_key_type(uint8_t key_idx, uint32_t *key_type)
{
    km_key_type type;
    uint32_t km_ret;
    uint32_t name_len;
    char name[16];

    id2_log_debug("[id2_client_kpm_get_key_type enter.]\n");

    if (!is_id2_client_inited()) {
        id2_log_error("id2 not inited.\n");
        return IROT_ERROR_GENERIC;
    }

    if (key_type == NULL) {
        id2_log_error("invalid input arg\n");
        return IROT_ERROR_BAD_PARAMETERS;
    }

    _id2_kpm_get_km_name(key_idx, name, &name_len);

    km_ret = km_get_key_type(name, name_len, &type);
    if (km_ret != KM_SUCCESS) {
        id2_log_error("km_get_key_type fail, 0x%x\n", km_ret);
        return IROT_ERROR_GENERIC;
    }

    if (type == KM_AES) {
        *key_type = LS_KPM_KEY_TYPE_AES;
    } else if (type == KM_SM4) {
        *key_type = LS_KPM_KEY_TYPE_SM4;
    } else {
        id2_log_error("not support this key type, %d\n", key_type);
        return IROT_ERROR_NOT_SUPPORTED;
    }

    id2_log_debug("key index %d -> key type: %d\n", key_idx, *key_type);

    return IROT_SUCCESS;
}

irot_result_t id2_client_kpm_get_auth_code(uint8_t key_idx, uint8_t key_info,
                  uint8_t mode, char *random, uint8_t *auth_code, uint32_t *auth_code_len)
{
    irot_result_t result = IROT_SUCCESS;
    uint8_t id2_code[ID2_MAX_AUTH_CODE_LEN + 1];
    uint8_t id_buf[ID2_ID_MAX_LEN + 1];
    uint32_t id_len = ID2_ID_MAX_LEN;
    uint32_t id2_code_len = ID2_MAX_AUTH_CODE_LEN;
    uint32_t tmp_code_len;
    uint8_t *tmp_code = NULL;
    id2_kpm_head_t *head = NULL;
    uint32_t offset = 0;
    int ret = 0;

    id2_log_debug("[id2_client_kpm_get_auth_code enter.]\n");

    if (!is_id2_client_inited()) {
        id2_log_error("id2 not inited.\n");
        return IROT_ERROR_GENERIC;
    }

    if (random == NULL || auth_code == NULL || auth_code_len == NULL) {
        id2_log_error("invalid input args\n");
        return IROT_ERROR_BAD_PARAMETERS;
    }

    if (key_idx == LS_KPM_KEY_IDX_ID2) {
        id2_log_error("not support id2 key index, %d\n", key_idx);
        return IROT_ERROR_NOT_SUPPORTED;
    }

    if (key_info != LS_KPM_KEY_INFO_AES_128 &&
        key_info != LS_KPM_KEY_INFO_AES_192 &&
        key_info != LS_KPM_KEY_INFO_AES_256 &&
        key_info != LS_KPM_KEY_INFO_SM4_128) {
        id2_log_error("not support this key info, %d\n", key_info);
        return IROT_ERROR_NOT_SUPPORTED;
    }

    result = id2_client_get_id(id_buf, &id_len);
    if (result != IROT_SUCCESS) {
        id2_log_error("id2_client_get_id fail, %d\n", result);
        return result;
    }

    id2_log_debug("Id2 id: %s %d\n", id_buf, id_len);

    if (mode == LS_ID2_MODE_CHALLENGE) {
        result = id2_client_get_challenge_auth_code(random, NULL, 0, id2_code, &id2_code_len);
        if (result != IROT_SUCCESS) {
            id2_log_error("id2_client_get_challenge_auth_code fail, %d\n", result);
            return result;
        }
    } else if (mode == LS_ID2_MODE_TIMESTAMP) {
        result = id2_client_get_timestamp_auth_code(random, NULL, 0, id2_code, &id2_code_len);
        if (result != IROT_SUCCESS) {
            id2_log_error("id2_client_get_timestamp_auth_code fail, %d\n", result);
            return result;
        }
    } else {
        id2_log_error("not support this mode, %d\n", mode);
        return IROT_ERROR_NOT_SUPPORTED;
    }

    id2_log_debug("Id2 auth code: %s %d\n", id2_code, id2_code_len);

    /* head_info + id2_id + id2_auth_code */
    tmp_code_len = sizeof(id2_kpm_head_t) + 2 + id_len + 2 + id2_code_len;

    if (*auth_code_len < ID2_BASE64_LEN(tmp_code_len)) {
        id2_log_error("short buffer, %d %d\n",
                       *auth_code_len, ID2_BASE64_LEN(tmp_code_len));
        return IROT_ERROR_SHORT_BUFFER;
    }

    tmp_code = ls_osa_malloc(tmp_code_len);
    if (tmp_code == NULL) {
        id2_log_error("out of mem, %d\n", tmp_code_len);
        return IROT_ERROR_OUT_OF_MEMORY;
    } else {
        head = (id2_kpm_head_t *)tmp_code;
        head->magic = LS_KPM_DATA_MAGIC;
        head->version = LS_KPM_DATA_VERSION;
        head->key_idx = key_idx;
        head->key_info = key_info;
    }

    /* id2 id field */
    offset += sizeof(id2_kpm_head_t);
    tmp_code[offset + 0] = (id_len & 0xFF00) >> 8;
    tmp_code[offset + 1] = (id_len & 0x00FF);
    memcpy(tmp_code + offset + 2, id_buf, id_len);

    /* id2 auth code field */
    offset += 2 + id_len;
    tmp_code[offset + 0] = (id2_code_len & 0xFF00) >> 8;
    tmp_code[offset + 1] = (id2_code_len & 0x00FF);
    memcpy(tmp_code + offset + 2, id2_code, id2_code_len);

    if (*auth_code_len < ID2_BASE64_LEN(tmp_code_len)) {
        id2_log_error("short buffer, %d %d\n",
                       *auth_code_len, ID2_BASE64_LEN(tmp_code_len));
        return IROT_ERROR_SHORT_BUFFER;
    } else {
        memset(auth_code, 0, *auth_code_len);
    }

    id2_log_hex_dump("kpm_auth_code", tmp_code, tmp_code_len);

    ret = id2_plat_base64_encode(tmp_code, tmp_code_len, auth_code, auth_code_len);
    if (ret < 0) {
        id2_log_error("id2_plat_base64_encode fail\n");
        result = IROT_ERROR_GENERIC;
        goto _out;
    }

    id2_log_debug("kpm_auth_code: %s %d\n", auth_code, *auth_code_len);

    result = IROT_SUCCESS;

_out:
    if (tmp_code != NULL) {
        ls_osa_free(tmp_code);
    }

    return result;
}

irot_result_t id2_client_kpm_import_key(uint8_t key_idx, uint8_t *data, uint32_t size)
{
    irot_result_t result = IROT_SUCCESS;
    km_keyring_t keyring;
    uint8_t *tmp_data = NULL;
    uint32_t tmp_data_len;
    uint32_t key_len;
    uint32_t kcv_len;
    uint32_t name_len;
    uint8_t *key_data = NULL;
    uint8_t *kcv_data = NULL;
    char name[ID2_KM_NAME_MAX_LEN];
    id2_kpm_head_t *head = NULL;
    uint32_t offset = 0, state = 0;
    uint32_t cipher_suite, padding_type;
    uint32_t km_ret;
    int ret = 0;

    id2_log_debug("[id2_client_kpm_import_key enter.]\n");

    if (!is_id2_client_inited()) {
        id2_log_error("id2 not inited.\n");
        return IROT_ERROR_GENERIC;
    }

    if (data == NULL || size == 0) {
        id2_log_error("invalid input args\n");
        return IROT_ERROR_BAD_PARAMETERS;
    }

    if (key_idx == LS_KPM_KEY_IDX_ID2) {
        id2_log_error("not support id2 key index, %d\n", key_idx);
        return IROT_ERROR_NOT_SUPPORTED;
    }

    /* at least head size + 4 */
    if (size < sizeof(id2_kpm_head_t) + 4) {
        id2_log_error("invalid import data size, %d\n", size);
        return IROT_ERROR_BAD_PARAMETERS;
    }

    /* input data base64 decode */
    tmp_data_len = size;
    tmp_data = ls_osa_malloc(tmp_data_len);
    if (tmp_data == NULL) {
        id2_log_error("out of mem, %d\n", tmp_data_len);
        return IROT_ERROR_OUT_OF_MEMORY;
    } else {
        ret = id2_plat_base64_decode(data, size, tmp_data, &tmp_data_len);
        if (ret < 0) {
            id2_log_error("id2_plat_base64_decode fail\n");
            result = IROT_ERROR_GENERIC;
            goto _out;
        } else {
            size = tmp_data_len;
        }
    }

    /* import data info checking */
    head = (id2_kpm_head_t *)tmp_data;
    if (head->magic != LS_KPM_DATA_MAGIC) {
        id2_log_error("invalid kpm magic, %c\n", head->magic);
        result = IROT_ERROR_GENERIC;
        goto _out;
    }
    if (head->version != LS_KPM_DATA_VERSION) {
        id2_log_error("invalid kpm version, 0x%x\n", head->version);
        result = IROT_ERROR_GENERIC;
        goto _out;
    }
    if (head->key_idx != key_idx) {
        id2_log_error("key index is not match, %d %d\n", head->key_idx, key_idx);
        result = IROT_ERROR_GENERIC;
        goto _out;
    }

    offset += sizeof(id2_kpm_head_t);

    /* key fields length and data */
    key_len = (tmp_data[offset + 0] << 8) + tmp_data[offset + 1];
    if (key_len == 0 ||
        key_len >= size - offset - 2) {
        id2_log_error("invalid key fields length, %d\n", key_len);
        result = IROT_ERROR_GENERIC;
        goto _out;
    } else {
        key_data = tmp_data + offset + 2;
        offset += 2 + key_len;
    }

    id2_log_hex_dump("key_data", key_data, key_len);

    /* kcv fields length and data */
    kcv_len = (tmp_data[offset + 0] << 8) + tmp_data[offset + 1];
    if (kcv_len == 0 ||
        kcv_len != size - offset - 2) {
        id2_log_error("invalid kcv fields length, %d\n", kcv_len);
        result = IROT_ERROR_GENERIC;
        goto _out;
    } else {
        kcv_data = tmp_data + offset + 2;
    }

    id2_log_hex_dump("kcv_data", kcv_data, kcv_len);

    switch(head->key_info) {
        case LS_KPM_KEY_INFO_AES_128: {
            keyring.key_type = KM_AES;
            keyring.key_bit = 128;
            keyring.payload_len = key_len;
            keyring.payload = key_data;

            cipher_suite = LS_KPM_CIPHER_SUITE_AES_ECB;
            padding_type = LS_KPM_SYM_PADDING_PKCS5;

            id2_log_info("import key info: %s\n", "AES_128");

            break;
        }
        case LS_KPM_KEY_INFO_AES_192: {
            keyring.key_type = KM_AES;
            keyring.key_bit = 192;
            keyring.payload_len = key_len;
            keyring.payload = key_data;

            cipher_suite = LS_KPM_CIPHER_SUITE_AES_ECB;
            padding_type = LS_KPM_SYM_PADDING_PKCS5;

            id2_log_info("import key info: %s\n", "AES_192");

            break;
        }
        case LS_KPM_KEY_INFO_AES_256: {
            keyring.key_type = KM_AES;
            keyring.key_bit = 256;
            keyring.payload_len = key_len;
            keyring.payload = key_data;

            cipher_suite = LS_KPM_CIPHER_SUITE_AES_ECB;
            padding_type = LS_KPM_SYM_PADDING_PKCS5;

            id2_log_info("import key info: %s\n", "AES_256");

            break;
        }
        case LS_KPM_KEY_INFO_SM4_128: {
            keyring.key_type = KM_SM4;
            keyring.key_bit = 128;
            keyring.payload_len = key_len;
            keyring.payload = key_data;

            cipher_suite = LS_KPM_CIPHER_SUITE_SM4_ECB;
            padding_type = LS_KPM_SYM_PADDING_PKCS5;

            id2_log_info("import key info: %s\n", "SM4_128");

            break;
        }
        default:
            id2_log_error("not support this key info, %d\n", head->key_info);
            result = IROT_ERROR_NOT_SUPPORTED;
            goto _out;
    }

    /* convert key index to km name */
    _id2_kpm_get_km_name(key_idx, name, &name_len);

    km_ret = km_get_prov_state(name, name_len, &state);
    if (km_ret != KM_SUCCESS) {
        id2_log_error("km get prov state fail, 0x%x\n", km_ret);
        result = IROT_ERROR_GENERIC;
        goto _out;
    } else {
        if (state == 1) {
            id2_log_info("key[index = %d] has been provisioned\n", key_idx);

            result = IROT_ERROR_NOT_SUPPORTED;
            goto _out;
        }
    }

    /* import key fields */
    km_ret = km_import_keyring(name, name_len, &keyring);
    if (km_ret != KM_SUCCESS) {
        id2_log_error("km import keyring fail, 0x%x\n", km_ret);
        result = IROT_ERROR_GENERIC;
        goto _out;
    }

    /* import key validation, delete key if fail */
    result = _id2_kpm_kcv_validation(key_idx,
                      cipher_suite, padding_type, kcv_data, kcv_len);
    if (result != IROT_SUCCESS) {
        id2_log_error("import key validation fail, %d\n", result);

        km_ret = km_delete_key(name, name_len);
        if (km_ret != KM_SUCCESS) {
            id2_log_error("delete km %s fail, 0x%x\n", name);
        }

        goto _out;
    }

    result = IROT_SUCCESS;

_out:
    if (tmp_data != NULL) {
        ls_osa_free(tmp_data);
    }

    return result;
}

irot_result_t id2_client_kpm_delete_key(uint8_t key_idx)
{
    irot_result_t result = IROT_SUCCESS;
    uint32_t name_len;
    char name[ID2_KM_NAME_MAX_LEN];
    uint32_t km_ret;
    bool is_prov = false;

    id2_log_debug("[id2_client_kpm_delete_key enter.]\n");

    if (!is_id2_client_inited()) {
        id2_log_error("id2 not inited.\n");
        return IROT_ERROR_GENERIC;
    }

    if (key_idx == LS_KPM_KEY_IDX_ID2) {
        id2_log_error("not support id2 key index, %d\n", key_idx);
        return IROT_ERROR_NOT_SUPPORTED;
    }

    result = id2_client_kpm_get_prov_stat(key_idx, &is_prov);
    if (result != IROT_SUCCESS) {
        id2_log_error("id2_client_kpm_get_prov_stat fail, %d\n", result);
        return result;
    }

    if (is_prov == false) {
        id2_log_info("key index[%s] is not exist\n", key_idx);
        return IROT_SUCCESS;
    }

    /* convert key index to km name */
    _id2_kpm_get_km_name(key_idx, name, &name_len);

    km_ret = km_delete_key(name, name_len);
    if (km_ret != KM_SUCCESS) {
        id2_log_error("delete key %s fail, 0x%x\n", name);
        return IROT_ERROR_GENERIC;
    }

    return IROT_SUCCESS;
}

irot_result_t id2_client_kpm_export_pub_key(uint8_t key_idx, uint8_t *data, uint32_t *size)
{
    irot_result_t result = IROT_SUCCESS;
    uint8_t *tmp_buf = NULL;
    size_t tmp_len;
    uint32_t key_type;
    uint32_t km_ret;
    uint32_t name_len;
    char name[ID2_KM_NAME_MAX_LEN];
    int ret = 0;

    id2_log_debug("[id2_client_kpm_export_pub_key enter.]\n");

    if (!is_id2_client_inited()) {
        id2_log_error("id2 not inited.\n");
        return IROT_ERROR_GENERIC;
    }

    if (data == NULL || size == NULL) {
        id2_log_error("invalid input args\n");
        return IROT_ERROR_BAD_PARAMETERS;
    }

    result = id2_client_kpm_get_key_type(key_idx, &key_type);
    if (result != IROT_SUCCESS) {
        id2_log_error("id2 kpm get key type fail, %d\n", result);
        return result;
    } else {
        /* only support asym key type */
        if (key_type != LS_KPM_KEY_TYPE_SM2 &&
            key_type != LS_KPM_KEY_TYPE_RSA) {
            id2_log_error("not support this key type, %d\n", key_type);
            return IROT_ERROR_NOT_SUPPORTED;
        }
    }

    tmp_len = *size;
    tmp_buf = ls_osa_malloc(tmp_len);
    if (tmp_buf == NULL) {
        id2_log_error("out of mem, %d\n", tmp_len);
        return IROT_ERROR_OUT_OF_MEMORY;
    }

    /* convert key index to km name */
    _id2_kpm_get_km_name(key_idx, name, &name_len);

    km_ret = km_export_key(name, name_len, KM_KEY_FORMAT_X509, tmp_buf, &tmp_len);
    if (km_ret != KM_SUCCESS) {
        id2_log_error("km export key fail, 0x%x\n", km_ret);
        result = IROT_ERROR_GENERIC;
        goto _out;
    }

    if (*size < ID2_BASE64_LEN(tmp_len)) {
        id2_log_error("short buffer, %d %d\n", *size, ID2_BASE64_LEN(tmp_len));
        result = IROT_ERROR_SHORT_BUFFER;
        goto _out;
    }

    ret = id2_plat_base64_encode(tmp_buf, tmp_len, data, size);
    if (ret < 0) {
        id2_log_error("id2_plat_base64_encode fail\n");
        result = IROT_ERROR_GENERIC;
        goto _out;
    }

    result = IROT_SUCCESS;

_out:
    if (tmp_buf != NULL) {
        ls_osa_free(tmp_buf);
    }

    return result;
}

irot_result_t id2_client_kpm_encrypt(uint8_t key_idx, uint8_t cipher_suite, uint8_t padding_type,
                                     uint8_t *iv, uint32_t iv_len,
                                     uint8_t *in_data, uint32_t in_len, uint8_t *out_data, uint32_t *out_len)
{
    irot_result_t result = IROT_SUCCESS;
    uint32_t tmp_len;
    uint8_t *tmp_data = NULL;
    uint32_t padding, block_size;
    uint32_t key_type;

    id2_log_debug("[id2_client_kpm_encrypt enter.]\n");

    if (!is_id2_client_inited()) {
        id2_log_error("id2 not inited.\n");
        return IROT_ERROR_GENERIC;
    }

    if (in_data == NULL || in_len == 0 ||
        out_data == NULL || out_len == NULL) {
        id2_log_error("invalid input args\n");
        return IROT_ERROR_BAD_PARAMETERS;
    }

    if (key_idx == LS_KPM_KEY_IDX_ID2) {
        id2_log_error("not support id2 key index, %d\n", key_idx);
        return IROT_ERROR_NOT_SUPPORTED;
    }

    result = id2_client_kpm_get_key_type(key_idx, &key_type);
    if (result != IROT_SUCCESS) {
        id2_log_error("id2_client_kpm_get_key_type fail, %d\n", result);
        return result;
    }

    if (cipher_suite == LS_KPM_CIPHER_SUITE_AES_ECB ||
        cipher_suite == LS_KPM_CIPHER_SUITE_AES_CBC) {
        if (key_type != LS_KPM_KEY_TYPE_AES) {
            id2_log_error("key type %d is not match cipher suite %s\n",
                           key_type, "LS_KPM_CIPHER_SUITE_AES_xxx");
            return IROT_ERROR_GENERIC;
        }

        block_size = ID2_AES_BLOCK_SIZE;
    } else if (cipher_suite == LS_KPM_CIPHER_SUITE_SM4_ECB ||
               cipher_suite == LS_KPM_CIPHER_SUITE_SM4_CBC) {
        if (key_type != LS_KPM_KEY_TYPE_SM4) {
            id2_log_error("key type %d is not match cipher suite %s\n",
                           key_type, "LS_KPM_CIPHER_SUITE_SM4_xxx");
            return IROT_ERROR_GENERIC;
        }

        block_size = ID2_SM4_BLOCK_SIZE;
    } else {
        id2_log_error("not support this cipher suite, %d\n", cipher_suite);
        return IROT_ERROR_NOT_SUPPORTED;
    }

    if (key_type == LS_KPM_KEY_TYPE_AES ||
        key_type == LS_KPM_KEY_TYPE_SM4) {

        tmp_len = in_len + block_size;
        tmp_data = ls_osa_malloc(tmp_len);
        if (tmp_data == NULL) {
            id2_log_error("out of mem, %d\n", tmp_len);
            return IROT_ERROR_OUT_OF_MEMORY;
        }

        if (padding_type == LS_KPM_SYM_NO_PADDING) {
            tmp_len = in_len;
            memcpy(tmp_data, in_data, in_len);
        } else if (padding_type == LS_KPM_SYM_PADDING_PKCS5) {
            padding = block_size - in_len % block_size;
            tmp_len = in_len + padding;

            memcpy(tmp_data, in_data, in_len);
            memset(tmp_data + in_len, padding, padding);
        } else {
            id2_log_error("not support this padding type, %d\n", padding_type);
            result = IROT_ERROR_NOT_SUPPORTED;
            goto _out;
        }

        if (*out_len < tmp_len) {
            id2_log_error("short buffer, %d %d\n", *out_len, tmp_len);
            result = IROT_ERROR_SHORT_BUFFER;
            goto _out;
        }

        result = _id2_kpm_do_cipher(key_idx, cipher_suite,
                          iv, iv_len, tmp_data, tmp_len, out_data, out_len, true);
        if (result != IROT_SUCCESS) {
            id2_log_error("id2 kpm do cipher fail, %d\n", result);
            goto _out;
        }
    } else {
        id2_log_error("not support this key type, %d\n", key_type);
        result = IROT_ERROR_NOT_SUPPORTED;
        goto _out;
    }

    result = IROT_SUCCESS;

_out:
    if (tmp_data != NULL) {
        ls_osa_free(tmp_data);
    }

    return result;
}

irot_result_t id2_client_kpm_decrypt(uint8_t key_idx, uint8_t cipher_suite, uint8_t padding_type,
                                     uint8_t *iv, uint32_t iv_len,
                                     uint8_t *in_data, uint32_t in_len, uint8_t *out_data, uint32_t *out_len)
{
    irot_result_t result = IROT_SUCCESS;
    uint32_t tmp_len;
    uint8_t *tmp_data = NULL;
    uint32_t i, padding, block_size;
    uint32_t key_type;

    id2_log_debug("[id2_client_kpm_decrypt enter.]\n");

    if (!is_id2_client_inited()) {
        id2_log_error("id2 not inited.\n");
        return IROT_ERROR_GENERIC;
    }

    if (in_data == NULL || in_len == 0 ||
        out_data == NULL || out_len == NULL) {
        id2_log_error("invalid input args\n");
        return IROT_ERROR_BAD_PARAMETERS;
    }

    if (key_idx == LS_KPM_KEY_IDX_ID2) {
        id2_log_error("not support id2 key index, %d\n", key_idx);
        return IROT_ERROR_NOT_SUPPORTED;
    }

    result = id2_client_kpm_get_key_type(key_idx, &key_type);
    if (result != IROT_SUCCESS) {
        id2_log_error("id2_client_kpm_get_key_type fail, %d\n", result);
        return result;
    }

    if (cipher_suite == LS_KPM_CIPHER_SUITE_AES_ECB ||
        cipher_suite == LS_KPM_CIPHER_SUITE_AES_CBC) {
        if (key_type != LS_KPM_KEY_TYPE_AES) {
            id2_log_error("key type %d is not match cipher suite %s\n",
                           key_type, "LS_KPM_CIPHER_SUITE_AES_xxx");
            return IROT_ERROR_GENERIC;
        }
 
        block_size = ID2_AES_BLOCK_SIZE;
    } else if (cipher_suite == LS_KPM_CIPHER_SUITE_SM4_ECB ||
               cipher_suite == LS_KPM_CIPHER_SUITE_SM4_CBC) {
        if (key_type != LS_KPM_KEY_TYPE_SM4) {
            id2_log_error("key type %d is not match cipher suite %s\n",
                           key_type, "LS_KPM_CIPHER_SUITE_SM4_xxx");
            return IROT_ERROR_GENERIC;
        }

        block_size = ID2_SM4_BLOCK_SIZE;
    } else {
        id2_log_error("not support this cipher suite, %d\n", cipher_suite);
        return IROT_ERROR_NOT_SUPPORTED;
    }

    tmp_len = in_len;
    tmp_data = ls_osa_malloc(tmp_len);
    if (tmp_data == NULL) {
        id2_log_error("out of mem, %d\n", tmp_len);
        return IROT_ERROR_OUT_OF_MEMORY;
    }

    if (key_type == LS_KPM_KEY_TYPE_AES ||
        key_type == LS_KPM_KEY_TYPE_SM4) {
 
       result = _id2_kpm_do_cipher(key_idx, cipher_suite,
                          iv, iv_len, in_data, in_len, tmp_data, &tmp_len, false);
        if (result != IROT_SUCCESS) {
            id2_log_error("id2 kpm do cipher fail, %d\n", result);
            goto _out;
        }

        id2_log_hex_dump("decrypted kcv data", tmp_data, tmp_len);

        if (padding_type == LS_KPM_SYM_PADDING_PKCS5) {
            padding = tmp_data[tmp_len - 1];
            if (padding > block_size) {
                id2_log_error("invalid pkcs5 padding, %d\n", padding);
                result = IROT_ERROR_GENERIC;
                goto _out;
            }

            for (i = padding; i > 0; i--) {
                if (tmp_data[tmp_len - i] != padding) {
                    id2_log_error("id2 kpm pkcs5 unpadding fail.\n");
                    result = IROT_ERROR_GENERIC;
                    goto _out;
                }
            }

            tmp_len = tmp_len - padding;
        } else if (padding_type != LS_KPM_SYM_NO_PADDING) {
            id2_log_error("not support this padding type, %d\n", padding_type);
            result = IROT_ERROR_NOT_SUPPORTED;
            goto _out;
        }
    } else {
        id2_log_error("not support this key type, %d\n", key_type);
        result = IROT_ERROR_NOT_SUPPORTED;
        goto _out;
    }

    if (*out_len < tmp_len) {
        id2_log_error("short buffer, %d %d\n", *out_len, tmp_len);
        result = IROT_ERROR_SHORT_BUFFER;
        goto _out;
    }

    *out_len = tmp_len;
    memcpy(out_data, tmp_data, tmp_len);

    result = IROT_SUCCESS;

_out:
    if (tmp_data != NULL) {
        ls_osa_free(tmp_data);
    }

    return result;
}

irot_result_t id2_client_kpm_sign(uint8_t key_idx, uint8_t *msg, uint32_t msg_len, uint8_t *sign, uint32_t *sign_len)
{
    id2_log_debug("[id2_client_kpm_sign enter.]\n");

    if (!is_id2_client_inited()) {
        id2_log_error("id2 not inited.\n");
        return IROT_ERROR_GENERIC;
    }

    if (msg == NULL || msg_len == 0 ||
        sign == NULL || sign_len == NULL) {
        id2_log_error("invalid input args\n");
        return IROT_ERROR_BAD_PARAMETERS;
    }

    if (key_idx == LS_KPM_KEY_IDX_ID2) {
        id2_log_error("not support id2 key index, %d\n", key_idx);
        return IROT_ERROR_NOT_SUPPORTED;
    }

    id2_log_info("not supported!\n");

    return IROT_ERROR_NOT_SUPPORTED;;
}

irot_result_t id2_client_kpm_verify(uint8_t key_idx, uint8_t *msg, uint32_t msg_len, uint8_t *sign, uint32_t sign_len)
{
    id2_log_debug("[id2_client_kpm_verify enter.]\n");

    if (!is_id2_client_inited()) {
        id2_log_error("id2 not inited.\n");
        return IROT_ERROR_GENERIC;
    }

    if (msg == NULL || msg_len == 0 ||
        sign == NULL || sign_len == 0) {
        id2_log_error("invalid input args\n");
        return IROT_ERROR_BAD_PARAMETERS;
    }

    if (key_idx == LS_KPM_KEY_IDX_ID2) {
        id2_log_error("not support id2 key index, %d\n", key_idx);
        return IROT_ERROR_NOT_SUPPORTED;
    }

    id2_log_info("not supported!\n");

    return IROT_ERROR_NOT_SUPPORTED;;
}

