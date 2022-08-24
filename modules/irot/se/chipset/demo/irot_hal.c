#include "irot_hal.h"
#include "chip_log.h"
#include "ali_crypto.h"

#define ID2_ID      "00DBBC60A12BC016BA187800"
#define MAX_SYM_KEY_LEN  32 //for soft demo only support symmetric key
#define MAX_KEY_ID  10 //for soft demo support 11 keys
#define ID2_KEY_TYPE HAL_KEY_TYPE_SM4

#if (CONFIG_CHIP_TYPE == CHIP_TYPE_SE_STD_HAL)
typedef struct _key_info_t {
    hal_key_type_t key_type;
    uint32_t key_bit;
    uint8_t key[MAX_SYM_KEY_LEN];
} key_info_t;

uint8_t id2_key[] = {
    0xe8, 0x97, 0x31, 0xa5, 0xa5, 0xd7, 0xf1, 0x2e,
    0x31, 0x6e, 0xbd, 0x7b, 0xb9, 0x11, 0x0f, 0x56
};

//
static key_info_t key_list[MAX_KEY_ID + 1];
static uint32_t key_state[MAX_KEY_ID + 1] = { 0 };

irot_result_t irot_hal_init(void)
{
    //for demo hard code id2_key
    key_list[ID2_CLIENT_KEY_ID].key_type = ID2_KEY_TYPE;
    key_list[ID2_CLIENT_KEY_ID].key_bit = 128;
    memcpy(key_list[ID2_CLIENT_KEY_ID].key, id2_key, 16);
    key_state[ID2_CLIENT_KEY_ID] = 1;

    return IROT_SUCCESS;
}

irot_result_t irot_hal_cleanup(void)
{
    return IROT_SUCCESS;
}

irot_result_t irot_hal_get_id2(uint8_t *id2, uint32_t *len)
{
    uint32_t id2_len = strlen(ID2_ID);
    if (*len < id2_len) {
        *len = id2_len;
        return IROT_ERROR_SHORT_BUFFER;
    }

    *len = id2_len;
    memcpy(id2, ID2_ID, id2_len);
    return IROT_SUCCESS;
}

irot_result_t irot_hal_sym_crypto(key_object *key_obj, uint8_t key_id,
                                  uint8_t *iv, uint32_t iv_len,
                                  uint8_t *in, uint32_t in_len,
                                  uint8_t *out, uint32_t *out_len,
                                  sym_crypto_param_t *crypto_param)
{
    uint8_t *key = NULL;
    bool is_enc = false;
    uint32_t ret = IROT_SUCCESS;
    ali_crypto_result ali_ret = 0;
    size_t ctx_size = 0;
    void *ctx = NULL;
    uint32_t key_len = 0;
    size_t tmp_len;

    if (key_id > MAX_KEY_ID) {
        chip_log_error("invalid key id %d\n", key_id);
        return IROT_ERROR_NOT_SUPPORTED;
    }

    if (crypto_param->key_type != key_list[key_id].key_type) {
        chip_log_error("invalid key type %d : %d\n", crypto_param->key_type, key_list[key_id].key_type);
        return IROT_ERROR_GENERIC;
    }

    key = key_list[key_id].key;
    key_len = (key_list[key_id].key_bit) >> 3;

    if (crypto_param->block_mode != BLOCK_MODE_ECB) {
        chip_log_error("invalid block mode\n");
        return IROT_ERROR_NOT_SUPPORTED;
    }

    if (crypto_param->padding_type != SYM_PADDING_NOPADDING) {
        chip_log_error("invalid padding type\n");
        return IROT_ERROR_NOT_SUPPORTED;
    }

    if (crypto_param->mode == MODE_ENCRYPT) {
        is_enc = true;
    } else if (crypto_param->mode == MODE_DECRYPT) {
        is_enc = false;
    }

    if (crypto_param->key_type == HAL_KEY_TYPE_SM4) {
        ali_ret = ali_sm4_get_ctx_size(SM4_ECB, &ctx_size);
    } else {
        chip_log_error("invalid key type %d\n", crypto_param->key_type);
        return IROT_ERROR_NOT_SUPPORTED;
    }
    if (ali_ret) {
        chip_log_error("ali get ctx size failed 0x%x\n", ali_ret);
        return IROT_ERROR_GENERIC;
    }

    ctx = ls_osa_malloc(ctx_size);
    if (!ctx) {
        chip_log_error("km malloc aes ctx failed\n");
        return IROT_ERROR_OUT_OF_MEMORY;
    }

    memset(ctx, 0, ctx_size);

    tmp_len = *out_len;
    if (crypto_param->key_type == HAL_KEY_TYPE_SM4) {
        ali_ret = ali_sm4_init(SM4_ECB, is_enc, key, NULL, key_len, NULL, ctx);
        if (ali_ret) {
            chip_log_error("sm4 init failed 0x%x\n", ali_ret);
            ret = IROT_ERROR_GENERIC;
            goto clean;
        }

        ali_ret = ali_sm4_finish(in, in_len, out, &tmp_len, SYM_NOPAD, ctx);
        *out_len = tmp_len;
    }
    if (ali_ret) {
        chip_log_error("sm4 finish failed 0x%x\n", ali_ret);
        ret = IROT_ERROR_GENERIC;
    }

clean:
    if (ctx) {
        ls_osa_free(ctx);
        ctx = NULL;
    }

    return ret;
}

irot_result_t irot_hal_get_prov_state(uint8_t key_id, uint32_t *state)
{
    //for demo only support 10 keys
    if (key_id > MAX_KEY_ID || !state) {
        return IROT_ERROR_BAD_PARAMETERS;
    }
    *state = key_state[key_id];

    return IROT_SUCCESS;
}

irot_result_t irot_hal_import_keyring(uint8_t key_id, hal_keyring_t *keyring)
{
    sym_crypto_param_t sym_param;
    irot_result_t ret = 0;
    uint8_t key[MAX_SYM_KEY_LEN];
    uint32_t key_len = MAX_SYM_KEY_LEN;
    uint8_t padding = 0;
    int i = 0;

    //for demo only support 10 keys
    if (key_id > MAX_KEY_ID) {
        return IROT_ERROR_NOT_SUPPORTED;
    }

    if (key_state[key_id] == 1) {
        chip_log_error("key is already exist\n");
        return IROT_ERROR_ACCESS_CONFLICT;
    }

    sym_param.key_type = ID2_KEY_TYPE;
    sym_param.block_mode = BLOCK_MODE_ECB;
    sym_param.padding_type = SYM_PADDING_NOPADDING;
    sym_param.mode = MODE_DECRYPT;

    ret = irot_hal_sym_crypto(NULL, ID2_CLIENT_KEY_ID, NULL, 0,
            keyring->payload, keyring->payload_len, key, &key_len, &sym_param);
    if (ret) {
        chip_log_error("irot hal sym crypto failed %d\n", ret);
        return ret;
    }

    padding = key[key_len - 1];
    if (padding > SM4_BLOCK_SIZE) {
        chip_log_error("wrong padding length %d\n", padding);
        return IROT_ERROR_GENERIC;
    }

    for (i = padding; i > 0; i--) {
        if (key[key_len - i] != padding) {
            chip_log_error("pkcs5 unpadding failed\n");
            return IROT_ERROR_GENERIC;
        }
    }
    key_len -= padding;

    if (keyring->key_bit != (key_len << 3)) {
        chip_log_error("wrong key len %d : %d\n", keyring->key_bit, key_len);
        return IROT_ERROR_GENERIC;
    }
    key_list[key_id].key_type = keyring->key_type;
    key_list[key_id].key_bit = keyring->key_bit;
    memcpy(key_list[key_id].key, key, key_len);
    key_state[key_id] = 1;

    return IROT_SUCCESS;
}

irot_result_t irot_hal_delete_key(uint8_t key_id)
{
    //for demo only support 10 keys
    if (key_id > MAX_KEY_ID) {
        return IROT_ERROR_NOT_SUPPORTED;
    }

    key_state[key_id] = 0;
    memset(&(key_list[key_id]), 0, sizeof(key_info_t));

    return IROT_SUCCESS;
}

irot_result_t irot_hal_get_key_type(uint8_t key_id, hal_key_type_t *key_type)
{
    if (!key_type) {
        return IROT_ERROR_BAD_PARAMETERS;
    }

    if (key_id > MAX_KEY_ID) {
        return IROT_ERROR_NOT_SUPPORTED;
    }

    if (!key_state[key_id]) {
        chip_log_error("key %d does not exist\n", key_id);
        return IROT_ERROR_ITEM_NOT_FOUND;
    }

    *key_type = key_list[key_id].key_type;

    return IROT_SUCCESS;
}

irot_result_t irot_hal_asym_priv_decrypt(key_object *key_obj, uint8_t key_id,
                                         uint8_t *in, uint32_t in_len,
                                         uint8_t *out, uint32_t *out_len,
                                         irot_asym_padding_t padding)
{
    return IROT_ERROR_NOT_SUPPORTED;
}

irot_result_t irot_hal_asym_priv_sign(key_object *key_obj, uint8_t key_id,
                                      uint8_t *msg, uint32_t msg_len,
                                      uint8_t *signature, uint32_t *signature_len,
                                      asym_sign_verify_t type)
{
    return IROT_ERROR_NOT_SUPPORTED;
}
#endif /* CONFIG_CHIP_TYPE == CHIP_TYPE_SE_STD_HAL */
