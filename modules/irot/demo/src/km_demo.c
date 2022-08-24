/*
 * Copyright (C) 2015-2017 Alibaba Group Holding Limited
 */

#include "km.h"
#include "ls_osa.h"
#include "ls_hal_km.h"
#include "ali_crypto.h"

/* ID2 For Debug, which can be got from id2 console */
#define ID2_ID      ""
#define ID2_KEY     ""

#define ID2_MIN_LEN       24
#define MAX_KEY_LEN       32

#define KM_DBG_LOG(_f, _a ...)  \
        ls_osa_print("%s %d: "_f,  __FUNCTION__, __LINE__, ##_a)

#define ID2_ITEM_MAGIC        0xF00A0102
#define ID2_ITEM_MAX_SIZE     128

#define ID2_ITEM_ID_OFFSET    0
#define ID2_ITEM_KEY_OFFSET   512

static uint8_t s_id2[ID2_MIN_LEN + 1]       = {0};
static uint8_t s_id2_key[MAX_KEY_LEN + 1]   = {0};

static uint32_t s_id2_len = 0;
static uint32_t s_key_len = 0;

static uint32_t s_km_init = 0;

typedef struct _id2_item_info_t {
     uint32_t magic;
     uint32_t size;
     uint32_t data[ID2_ITEM_MAX_SIZE];
} id2_item_info_t;

static int _char_to_hex(char c)
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

static int _string_to_hex(char *str, uint32_t str_len, uint8_t *hex, uint32_t hex_len)
{
    size_t i;
    uint8_t h, l;

    if (hex_len * 2 < str_len) {
        return -1;
    }

    for (i = 0; i < str_len; i += 2) {
        h = _char_to_hex(str[i]);
        l = _char_to_hex(str[i + 1]);
        if (h < 0 || l < 0) {
            return -1;
        }

        hex[i >> 1] = (h << 4) | (l & 0x0F);
    }

    return 0;
}

static uint32_t _save_id2_item(uint8_t *data, uint32_t size, uint32_t offset)
{
    id2_item_info_t info;
    int fd = 0;
    uint32_t ret = 0;

    if (data == NULL || size == 0) {
        KM_DBG_LOG("invalid input args\n");
        return KM_ERR_BAD_PARAMS;
    }

    if (size >= ID2_ITEM_MAX_SIZE) {
        KM_DBG_LOG("invalid data size, %d\n", size);
        return KM_ERR_BAD_PARAMS;
    }

    memset(&info, 0, sizeof(id2_item_info_t));
    info.magic = ID2_ITEM_MAGIC;
    info.size = size;
    memcpy(info.data, data, size);

    fd = ls_hal_open_rsvd_part(LS_HAL_READ | LS_HAL_WRITE);
    if (fd < 0) {
        KM_DBG_LOG("open rsvd part fail\n");
        return KM_ERR_GENERIC;
    }

    ret = ls_hal_write_rsvd_part(fd, offset, (uint8_t *)(&info), sizeof(id2_item_info_t));
    if (ret < 0) {
        KM_DBG_LOG("write rsvd part fail\n");
        ret = KM_ERR_GENERIC;
        goto _out;
    }

    ret = KM_SUCCESS;

_out:
    ls_hal_close_rsvd_part(fd);

    return ret;
}

static uint32_t _load_id2_item(id2_item_info_t *info, uint32_t offset)
{
    int fd = 0;
    uint32_t ret = 0;

    if (info == NULL) {
        KM_DBG_LOG("invalid input arg\n");
        return KM_ERR_BAD_PARAMS;
    }

    memset(info, 0, sizeof(id2_item_info_t));

    fd = ls_hal_open_rsvd_part(LS_HAL_READ);
    if (fd < 0) {
        KM_DBG_LOG("open rsvd part fail\n");
        return KM_ERR_GENERIC;
    }

    ret = ls_hal_read_rsvd_part(fd, offset, (uint8_t *)info, sizeof(id2_item_info_t));
    if (ret < 0) {
        KM_DBG_LOG("read rsvd part fail\n");
        ret = KM_ERR_GENERIC;
        goto _out;
    }

    if (info->magic != ID2_ITEM_MAGIC) {
        ret = KM_ERR_ITEM_NOT_FOUND;
        goto _out;
    }
    if (info->size >= ID2_ITEM_MAX_SIZE) {
        KM_DBG_LOG("invalid item size, %d\n", info->size);
        ret = KM_ERR_GENERIC;
        goto _out;
    }

    ret = KM_SUCCESS;

_out:
    ls_hal_close_rsvd_part(fd);

    return ret;

}

static int _aes_ecb_crypt(uint8_t *key, uint32_t key_len,
                uint8_t *in, uint32_t in_len, uint8_t* out, uint32_t* out_len, uint8_t is_enc)
{
    int ret = 0;
    size_t ctx_size;
    ali_crypto_result result;
    void* aes_ctx = NULL;

    result = ali_aes_get_ctx_size(AES_ECB, &ctx_size);
    if (result != ALI_CRYPTO_SUCCESS) {
        KM_DBG_LOG("get aes ecb ctx fail, 0x%x\n", result);
        return -1;
    }

    aes_ctx = ls_osa_malloc(ctx_size);
    if (aes_ctx == NULL) {
        KM_DBG_LOG("out of mem, %d\n", ctx_size);
        return -1;
    }

    result = ali_aes_init(AES_ECB, is_enc, key, NULL, key_len, NULL, aes_ctx);
    if (result != ALI_CRYPTO_SUCCESS) {
        KM_DBG_LOG("aes ecb init fail, %d\n", result);
        ret = -1;
        goto _out;
    }

    result = ali_aes_process(in, out, in_len, aes_ctx);
    if (result != ALI_CRYPTO_SUCCESS){
        KM_DBG_LOG("aes ecb process fail, %d\n", result);
        ret = -1;
        goto _out;
    }

    result = ali_aes_finish(NULL, 0, NULL, NULL, SYM_NOPAD, aes_ctx);
    if (result != ALI_CRYPTO_SUCCESS) {
        KM_DBG_LOG("aes ecb finish fail, %d\n", result);
        ret = -1;
        goto _out;
    }

    *out_len = in_len;

_out:
    ls_osa_free(aes_ctx);

    return ret;
}

static int _sm4_ecb_crypt(uint8_t *key, uint32_t key_len,
                uint8_t *in, uint32_t in_len, uint8_t* out, uint32_t* out_len, uint8_t is_enc)
{
    int ret = 0;
    size_t ctx_size;
    ali_crypto_result result;
    void* sm4_ctx = NULL;

    result = ali_sm4_get_ctx_size(SM4_ECB, &ctx_size);
    if (result != ALI_CRYPTO_SUCCESS) {
        KM_DBG_LOG("get sm4 ecb ctx fail, 0x%x\n", result);
        return -1;
    }

    sm4_ctx = ls_osa_malloc(ctx_size);
    if (sm4_ctx == NULL) {
        KM_DBG_LOG("out of mem, %d\n", ctx_size);
        return -1;
    }

    result = ali_sm4_init(SM4_ECB, is_enc, key, NULL, key_len, NULL, sm4_ctx);
    if (result != ALI_CRYPTO_SUCCESS) {
        KM_DBG_LOG("sm4 ecb init fail, %d\n", result);
        ret = -1;
        goto _out;
    }

    result = ali_sm4_process(in, out, in_len, sm4_ctx);
    if (result != ALI_CRYPTO_SUCCESS){
        KM_DBG_LOG("sm4 ecb process fail, %d\n", result);
        ret = -1;
        goto _out;
    }

    result = ali_sm4_finish(NULL, 0, NULL, NULL, SYM_NOPAD, sm4_ctx);
    if (result != ALI_CRYPTO_SUCCESS) {
        KM_DBG_LOG("sm4 ecb finish fail, %d\n", result);
        ret = -1;
        goto _out;
    }

    *out_len = in_len;

_out:
    ls_osa_free(sm4_ctx);

    return ret;
}

uint32_t km_generate_key(const char* name, uint32_t name_len, km_gen_param_t* arg)
{
    return KM_ERR_NOT_SUPPORTED;
}

uint32_t km_export_key(const char* name, uint32_t name_len,
                       km_format_t format, uint8_t* export_data, size_t* export_data_size)
{
    return KM_ERR_NOT_SUPPORTED;
}

uint32_t km_mac(const char *name, uint32_t name_len, km_sym_param *mac_params,
        uint8_t *iv, uint32_t iv_len, uint8_t *src, size_t src_len,
        uint8_t *mac, uint32_t *mac_len)
{
    return KM_ERR_NOT_SUPPORTED;
}

uint32_t km_delete_key(const char* name, uint32_t name_len)
{
    return KM_ERR_NOT_SUPPORTED;
}

uint32_t km_delete_all()
{
    return KM_ERR_NOT_SUPPORTED;
}

////////////////////////////////////////////////////////////////////////////////

uint32_t km_envelope_begin(void **ctx, const char *name, const uint32_t name_len,
                           uint8_t *iv, uint32_t iv_len,
                           uint8_t *protected_key, uint32_t *protected_key_len, km_purpose_type is_enc)
{
    return KM_ERR_NOT_SUPPORTED;
}

uint32_t km_envelope_update(void* ctx, uint8_t* src, size_t src_len, uint8_t* dest, size_t* dest_len)
{
    return KM_ERR_NOT_SUPPORTED;
}

uint32_t km_envelope_finish(void* ctx, uint8_t* src, size_t src_len, uint8_t* dest, size_t* dest_len)
{
    return KM_ERR_NOT_SUPPORTED;
}

////////////////////////////////////////////////////////////////////////////////

uint32_t km_msg_sign(const char *name, uint32_t name_len,
        km_sign_param *sign_params,
        uint8_t *id, size_t id_len,
        uint8_t *msg, size_t msg_len,
        uint8_t *signature, uint32_t *signature_len)
{
    return KM_ERR_NOT_SUPPORTED;
}

uint32_t km_msg_verify(const char *name, uint32_t name_len,
        km_sign_param *sign_params,
        uint8_t *id, size_t id_len,
        uint8_t *msg, size_t msg_len,
        uint8_t *signature, uint32_t signature_len)
{
    return KM_ERR_NOT_SUPPORTED;
}

uint32_t km_sign(const char* name, uint32_t name_len, km_sign_param* sign_params,
                 uint8_t* digest, uint32_t digest_len, uint8_t* signature, uint32_t* signature_len)
{
    return KM_ERR_NOT_SUPPORTED;
}

uint32_t km_verify(const char* name, uint32_t name_len, km_sign_param* sign_params,
                   const uint8_t* digest, uint32_t digest_len, const uint8_t* signature, uint32_t signature_len)
{
    return KM_ERR_NOT_SUPPORTED;
}

uint32_t km_asym_encrypt(const char* name, uint32_t name_len, km_enc_param* enc_params,
                         uint8_t* src, uint32_t src_len, uint8_t* dest, uint32_t* dest_len)
{
    return KM_ERR_NOT_SUPPORTED;
}

uint32_t km_asym_decrypt(const char* name, uint32_t name_len, km_enc_param* enc_params,
                         uint8_t* src, uint32_t src_len, uint8_t* dest, uint32_t* dest_len)
{
    return KM_ERR_NOT_SUPPORTED;
}

////////////////////////////////////////////////////////////////////////////////

uint32_t km_init()
{
    int ret = 0;
    uint32_t result;
    id2_item_info_t info;

    KM_DBG_LOG("Demo KM Build Time: %s %s\n", __DATE__, __TIME__);
    KM_DBG_LOG("SE, PUF, TEE or Soft KM must be selected for formal product!!!\n\n");

    if (s_km_init == 0) {
        /* load hardcode id2 first */
        s_id2_len = strlen(ID2_ID);
        if (s_id2_len >= ID2_MIN_LEN) {

            /* cache id2 id */
            memcpy(s_id2, ID2_ID, s_id2_len);

            /* cache id2 key */
            s_key_len = strlen(ID2_KEY) >> 1;
            ret = _string_to_hex(ID2_KEY, (uint32_t)strlen(ID2_KEY), s_id2_key, s_key_len);
            if (ret < 0) {
                KM_DBG_LOG("string to hex fail\n");
                return KM_ERR_GENERIC;
            }
        } else {
            /* load id2 id item */
            result = _load_id2_item(&info, ID2_ITEM_ID_OFFSET);
            if (result == KM_SUCCESS) {
                s_id2_len = info.size;
                memcpy(s_id2, info.data, s_id2_len);
            } else if (result != KM_ERR_ITEM_NOT_FOUND) {
                KM_DBG_LOG("load id2 id item fail\n");
                return KM_ERR_GENERIC;
            }

            /* load id2 key item */
            result = _load_id2_item(&info, ID2_ITEM_KEY_OFFSET);
            if (result == KM_SUCCESS) {
                s_key_len = info.size;
                memcpy(s_id2_key, info.data, s_key_len);
            } else if (result != KM_ERR_ITEM_NOT_FOUND) {
                KM_DBG_LOG("load id2 key item fail\n");

                /* reset id2 id and key length */
                s_id2_len = 0;
                s_key_len = 0;

                return KM_ERR_GENERIC;
            }
        }

        s_km_init = 1;
    }

    return KM_SUCCESS;
}

void km_cleanup()
{
    return;
}

uint32_t km_get_irot_type(void)
{
    return KM_IROT_TYPE_DEMO;
}

uint32_t km_cipher(const char* name, uint32_t name_len,
                   km_sym_param* km_params, uint8_t* iv, uint32_t iv_len,
                   uint8_t* src, size_t src_len, uint8_t* dest, size_t* dest_len)
{
    int ret = 0;
    km_key_type key_type = km_params->key_type;
    km_block_mode_type block_mode = km_params->cipher_param.block_mode;
    km_padding_type padding_type = km_params->cipher_param.padding_type;
    km_purpose_type purpose_type = km_params->cipher_param.purpose_type;
    uint8_t is_enc;
    uint32_t output_len;

    if ((block_mode != KM_ECB) || (padding_type != KM_NO_PADDING)) {
        KM_DBG_LOG("invalid mode or padding type, %d %d\n", block_mode, padding_type);
        return KM_ERR_NOT_SUPPORTED;
    }

    is_enc = (purpose_type == KM_PURPOSE_ENCRYPT) ? 1 : 0;

    output_len = *dest_len;
    if (key_type == KM_AES) {
        ret = _aes_ecb_crypt(s_id2_key, s_key_len, src, src_len, dest, &output_len, is_enc);
        if (ret != 0) {
            KM_DBG_LOG("aes ecb crypt fail\n");
            return KM_ERR_GENERIC;
        }
    } else if (key_type == KM_SM4) {
        ret = _sm4_ecb_crypt(s_id2_key, s_key_len, src, src_len, dest, &output_len, is_enc);
        if (ret != 0) {
            KM_DBG_LOG("sm4 ecb crypt fail\n");
            return KM_ERR_GENERIC;
        }
    } else {
        KM_DBG_LOG("not support this type, %d\n", key_type);
        return KM_ERR_NOT_SUPPORTED;
    }

    *dest_len = output_len;

    return KM_SUCCESS;
}

uint32_t km_set_id2(uint8_t* id2, uint32_t len)
{
    uint32_t ret;

    if (len != ID2_MIN_LEN) {
        return KM_ERR_BAD_PARAMS;
    }

    ret = _save_id2_item(id2, len, ID2_ITEM_ID_OFFSET);
    if (ret < 0) {
        KM_DBG_LOG("save id2 item id fail\n");
        return KM_ERR_BAD_PARAMS;
    }

    /* update id2 id cache */
    memcpy(s_id2, id2, len);
    s_id2_len = len;

    return KM_SUCCESS;
}

uint32_t km_import_key(const char* name, uint32_t name_len,
                       km_format_t format, const km_key_data_t* key_data, uint32_t key_data_len)
{
    uint8_t key_type;
    uint8_t* pkey;
    uint32_t key_len;
    uint32_t ret;

    key_type = key_data->type;
    pkey = key_data->sym_key.key;
    key_len = key_data->sym_key.key_bit >> 3;

    if (key_type == KM_AES) {
        if (key_len != 16 &&
            key_len != 24 && key_len != 32) {
            KM_DBG_LOG("invalid aes key length, %d\n", key_len);
            return KM_ERR_BAD_PARAMS;
        }
    } else if (key_type == KM_SM4) {
        if (key_len != 16) {
            KM_DBG_LOG("invalid aes key length, %d\n", key_len);
            return KM_ERR_BAD_PARAMS;
        }
    } else {
        KM_DBG_LOG("not support this key type, %d\n", key_type);
        return KM_ERR_NOT_SUPPORTED;
    }

    ret = _save_id2_item(pkey, key_len, ID2_ITEM_KEY_OFFSET);
    if (ret < 0) {
        KM_DBG_LOG("save id2 item key fail\n");
        return KM_ERR_BAD_PARAMS;
    }

    /* update id2 key cache */
    memcpy(s_id2_key, pkey, key_len);
    s_key_len = key_len;

    return KM_SUCCESS;
}

uint32_t km_get_id2(uint8_t* id2, uint32_t* len)
{
    if (s_id2_len < ID2_MIN_LEN) {
        KM_DBG_LOG("not find id2, s_id2_len = %d\n", s_id2_len);
        return KM_ERR_ITEM_NOT_FOUND;
    } else {
        if (*len < s_id2_len) {
            KM_DBG_LOG("short buffer, %d %d\n", *len, s_id2_len);
            return KM_ERR_SHORT_BUFFER;
        }

        memcpy(id2, s_id2, s_id2_len);
    }

    *len = s_id2_len;

    return KM_SUCCESS;
}

uint32_t km_get_attestation(uint8_t* id, uint32_t* id_len)
{
    int ret;

    if (id == NULL) {
        *id_len = ID2_MIN_LEN;
        return KM_ERR_SHORT_BUFFER;
    }

    ret = ls_hal_get_dev_id(id, id_len);
    if (ret < 0) {
        KM_DBG_LOG("get dev id fail\n");
        return KM_ERR_GENERIC;
    }

    return KM_SUCCESS;
}

uint32_t km_get_id2_state(uint32_t *state)
{
    return KM_ERR_ITEM_NOT_FOUND;
}

uint32_t km_set_id2_state(uint32_t state)
{
    return KM_ERR_ITEM_NOT_FOUND;
}

uint32_t km_generate_key_blob(km_gen_param_t *arg, uint8_t *key_blob, uint32_t *key_blob_len)
{
    return KM_ERR_NOT_SUPPORTED;
}

uint32_t km_import_key_blob(km_format_t format,
                            const km_key_data_t *key_data, uint32_t key_data_len,
                            uint8_t *key_blob, uint32_t *key_blob_len)
{
    return KM_ERR_NOT_SUPPORTED;
}

uint32_t km_blob_export_key(uint8_t *blob, uint32_t key_blob_len, km_format_t format,
                            uint8_t *export_data, size_t *export_data_size)
{
    return KM_ERR_NOT_SUPPORTED;
}

uint32_t km_blob_mac(uint8_t *key_blob, uint32_t key_blob_len, km_sym_param *mac_params,
                     uint8_t *iv, uint32_t iv_len, uint8_t *src, size_t src_len,
                     uint8_t *mac, uint32_t *mac_len)
{
    return KM_ERR_NOT_SUPPORTED;
}

uint32_t km_blob_msg_sign(uint8_t *key_blob, uint32_t key_blob_len,
        km_sign_param *sign_params,
        uint8_t *id, size_t id_len,
        uint8_t *msg, size_t msg_len,
        uint8_t *signature, uint32_t *signature_len)
{
    return KM_ERR_NOT_SUPPORTED;
}

uint32_t km_blob_msg_verify(uint8_t *key_blob, uint32_t key_blob_len,
        km_sign_param *sign_params,
        uint8_t *id, size_t id_len,
        uint8_t *msg, size_t msg_len,
        uint8_t *signature, uint32_t signature_len)
{
    return KM_ERR_NOT_SUPPORTED;
}

uint32_t km_blob_sign(uint8_t *key_blob, uint32_t key_blob_len,
                      km_sign_param *sign_params,
                      uint8_t *digest, uint32_t digest_len,
                      uint8_t *signature, uint32_t *signature_len)
{
    return KM_ERR_NOT_SUPPORTED;
}

uint32_t km_blob_verify(uint8_t *key_blob, uint32_t key_blob_len,
                        km_sign_param *sign_params,
                        const uint8_t *digest, uint32_t digest_len,
                        const uint8_t *signature, uint32_t signature_len)
{
    return KM_ERR_NOT_SUPPORTED;
}

uint32_t km_blob_asym_encrypt(uint8_t *key_blob, uint32_t key_blob_len, km_enc_param *enc_params,
                              uint8_t *src, uint32_t src_len,
                              uint8_t *dest, uint32_t *dest_len)
{
    return KM_ERR_NOT_SUPPORTED;
}

uint32_t km_blob_asym_decrypt(uint8_t *key_blob, uint32_t key_blob_len, km_enc_param *enc_params,
                              uint8_t *src, uint32_t src_len,
                              uint8_t *dest, uint32_t *dest_len)
{
    return KM_ERR_NOT_SUPPORTED;
}

uint32_t km_blob_cipher(uint8_t *key_blob, uint32_t key_blob_len, km_sym_param *cipher_params,
                        uint8_t *iv, uint32_t iv_len, uint8_t *src, size_t src_len,
                        uint8_t *dest, size_t *dest_len)
{
    return KM_ERR_NOT_SUPPORTED;
}

uint32_t km_import_keyring(const char *name, uint32_t name_len,
                       km_keyring_t *keyring)
{
    return KM_ERR_NOT_SUPPORTED;
}

uint32_t km_get_prov_state(const char *name, uint32_t name_len, uint32_t *state)
{
    return KM_ERR_NOT_SUPPORTED;
}

uint32_t km_get_key_type(const char *name, uint32_t name_len, km_key_type *key_type)
{
    return KM_ERR_NOT_SUPPORTED;
}

