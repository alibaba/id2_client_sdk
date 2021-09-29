/**
 * Copyright (C) 2019-2021 Alibaba Group Holding Limited.
 */

#include "irot_hal.h"
#include "chip_log.h"
#include "chip_util.h"

#include "ali_crypto.h"

#include "mbedtls/platform.h"
#include "mbedtls/ecdh.h"
#include "mbedtls/ecdsa.h"

#if (CONFIG_CHIP_ECDP_TYPE == CHIP_ECDP_TYPE_SECP192K1)

#if defined(CONFIG_CHIP_DEBUG)
#define CHIP_UID      "0123456789ABCDEF-6789-001234_192"
#define ID2_KEY_Q     "0459A8A3465CFCC450CD4984D6010648E51E3448A1968EC58CE588B9FA702C3040B311909C1793CF540303CB6363A1BBD8"
#define ID2_KEY_D     "B51B17E08938AB9BAAB106711874BA5111AE0BD687E792C8"
#else
#define CHIP_UID      "0123456789ABCDEF-XIDT-ECC_192"
#define ID2_KEY_Q     "0472BD69F3E656354E73A9A6CB021149CE78DDACF907984551F24CF45017645BA87B4A616AB64DB6AAB1D375201FF9A2B0"
#define ID2_KEY_D     "45DE80F1E172D1FCEEFFD9999BB522F1D7385DD5706A1C62"
#endif

#elif (CONFIG_CHIP_ECDP_TYPE == CHIP_ECDP_TYPE_SECP224K1)

#if defined(CONFIG_CHIP_DEBUG)
#define CHIP_UID      "0123456789ABCDEF-6789-001234_224"
#define ID2_KEY_Q     "048FE171E5CE5330BCAD8C7C6BEAA4AF0C44E0660E22423F3E8C1617D7260C5B723AC46D04D4612EC95490B42EE76F0F3AD1984B65E69A518D"
#define ID2_KEY_D     "ECCDA62A04C3691E4E08987E32C6DA9C7823D2BCA53EF162F58438E3"
#else
#define CHIP_UID      "0123456789ABCDEF-XIDT-ECC_224"
#define ID2_KEY_Q     "04E7E4387C220CF54C5E46350896B643C6AF7D5FB2E08E4C257E18BF39B25E2F32529F84E7A4984742D23FDFFBEFB0C2B51178A7CA6E972CE9"
#define ID2_KEY_D     "44D95ECA99B78E516606513684BBDE06D6EAE741C6DFEBFCB1DE705B"
#endif

#elif (CONFIG_CHIP_ECDP_TYPE == CHIP_ECDP_TYPE_SECP256K1)

#if defined(CONFIG_CHIP_DEBUG)
#define CHIP_UID      "0123456789ABCDEF-6789-001234_256"
#define ID2_KEY_Q     "04E441116D9A0835C6018681D57A35A966CF023E93DFAC39055CA2C9B9E27819FC41F4A5A7D3EB82567753EE7DC5A13E5921066A47F5CFDE9C454A67807E885F70"
#define ID2_KEY_D     "33B5B475587967CE6486BC4E655CE18EA2B755586A6E03E0CE821EAC36B646A1"
#else
#define CHIP_UID      "0123456789ABCDEF-XIDT-ECC_256"
#define ID2_KEY_Q     "0402FD9E900DC3F4E4C71D3DB790902CA6CCAF16AFDABD26298ABE856AD16CE56370E3F84CBC0E939B04210C862F467382FB9B9C103FA336500C7DBDE7D8C6CC36"
#define ID2_KEY_D     "D8FED1F6BC4C01B36C750AB8445EB0B7DA4208C14A86B241FF11C5C62FECD178"
#endif

#else
#error "CONFIG_CHIP_ECDP_TYPE is not supported"
#endif

#define ID2_ID_VENDOR        "00000001"

#define ID2_MAX_ID_LEN        48
#define ID2_MAC_KEY_SIZE      32
#define ID2_MAX_CURVE_SIZE    36

#define ID2_IES_HEAD_MAGIC    0x48
#define ID2_IES_HEAD_VERSION  0x01

#define ID2_IES_MODE_NO_BC    0x00   /* backwards compatibility mode is not selected */
#define ID2_IES_MODE_BC       0x01   /* backwards compatibility mode is selected */

#define ID2_IES_MODE_TYPE     ID2_IES_MODE_BC

typedef struct _id2_ies_head_t {
    uint8_t magic;
    uint8_t version;
    uint8_t mode;
    uint8_t rsvd;
} id2_ies_head_t;

typedef struct _hal_id2_info_t {
    uint32_t grp_id;
    uint32_t curve_size;
    uint8_t id2_id[ID2_MAX_ID_LEN + 1];
    uint8_t x[ID2_MAX_CURVE_SIZE];
    uint8_t y[ID2_MAX_CURVE_SIZE];
    uint8_t d[ID2_MAX_CURVE_SIZE];
} hal_id2_info_t;

static hal_id2_info_t *s_id2_info = NULL;

static int _ecp_random(void *p_rng, unsigned char *output, size_t output_len)
{
    uint64_t time_ms;

    (void)p_rng;

    time_ms = ls_osa_get_time_ms() + rand();

    ali_seed((uint8_t *)&time_ms, sizeof(uint8_t *));
    ali_rand_gen(output, output_len);

    return 0;
}

static int _ecies_key_derivation(uint8_t *seed,
                  uint32_t seed_len, uint8_t *key_buf, uint32_t key_len)
{
    int ret = 0;
    uint8_t hash[DIGEST_SHA256_SIZE];
    uint32_t hash_len = DIGEST_SHA256_SIZE;
    uint8_t counter[4] = {0x00, 0x00, 0x00, 0x01};
    uint8_t *msg_buf = NULL;
    uint32_t msg_len;
    uint32_t offset = 0;
    uint32_t i, loop_time;

    if (seed == NULL || seed_len == 0 ||
        key_buf == NULL || key_len == 0) {
        chip_log_error("invalid input args\n");
        return -1;
    }

    loop_time = (key_len  + hash_len - 1) / hash_len;
    if (loop_time > 255) {
        chip_log_error("input data is too large, %d\n", key_len);
        return -1;
    }

    msg_len = seed_len + 4;
    msg_buf = ls_osa_malloc(msg_len);
    if (msg_buf == NULL) {
        chip_log_error("out of mem, %d\n", msg_len);
        return -1;
    } else {
        memcpy(msg_buf, seed, seed_len);
    }

    for (i = 0; i < loop_time; i++) {
        /* update counter */
        memcpy(msg_buf + seed_len, counter, 4);
        counter[3]++;

        ret = chip_hash_digest(msg_buf, msg_len,
                   hash, &hash_len, DIGEST_TYPE_SHA256);
        if (ret < 0) {
            chip_log_error("chip_hash_digest fail\n");
            goto _out;
        }

        if (key_len >= hash_len) {
            memcpy(key_buf + offset, hash, hash_len);
            offset += hash_len;
            key_len -= hash_len;
        } else {
            memcpy(key_buf + offset, hash, key_len);
        }
    }

    ret = 0;

_out:
    if (msg_buf != NULL) {
        ls_osa_free(msg_buf);
    }

    return ret;
}

static int _load_id2_info(uint32_t grp_id, uint32_t curve_size, hal_id2_info_t *id2_info)
{
    int ret = 0;
    uint32_t tmp_len;
    uint32_t id2_len;
    uint8_t tmp_buf[128] = {0};

    if (curve_size == 0 || id2_info == NULL) {
        chip_log_error("invalid input args\n");
        return -1;
    }

    memset(id2_info, 0, sizeof(hal_id2_info_t));
    id2_info->grp_id = grp_id;
    id2_info->curve_size = curve_size;

    id2_len = ID2_MAX_ID_LEN;
    ret = irot_hal_get_id2(id2_info->id2_id, &id2_len);
    if (ret < 0) {
        chip_log_error("irot_hal_get_id2 fail\n");
        return -1;
    }

    chip_log_info("id2 id: %s\n", id2_info->id2_id);

    tmp_len = 128;
    ret = chip_string_to_hex(ID2_KEY_Q, (int)strlen(ID2_KEY_Q), tmp_buf, &tmp_len);
    if (ret < 0) {
        chip_log_error("id2 public key string to hex fail\n");
        return -1;
    } else {
        if (tmp_len != 2 * curve_size + 1) {
            chip_log_error("invalid public key length, %d\n", tmp_len);
            return -1;
        }

        if (tmp_buf[0] != 0x04) {
            chip_log_error("invalid public key compression flag, 0x%x\n", tmp_buf[0]);
            return -1;
        }

        memcpy(id2_info->x, tmp_buf + 1, curve_size);
        memcpy(id2_info->y, tmp_buf + 1 + curve_size, curve_size);
    }

    tmp_len = 128;
    ret = chip_string_to_hex(ID2_KEY_D, (int)strlen(ID2_KEY_D), tmp_buf, &tmp_len);
    if (ret < 0) {
        chip_log_error("id2 private key string to hex fail\n");
        return -1;
    } else {
        if (tmp_len != curve_size) {
            chip_log_error("invalid private key length, %d\n", tmp_len);
            return -1;
        } else {
            memcpy(id2_info->d, tmp_buf, curve_size);
        }
    }

    return 0;
}

static int _ecies_do_encrypt(uint8_t *key_data, uint32_t key_len,
                  uint32_t mode, uint8_t *in_data, uint32_t in_len, uint8_t *out_data)
{
    int ret;
    uint8_t *enc_key;
    uint8_t *mac_key;
    uint32_t i, out_len;

    if (key_data == NULL || key_len == 0 ||
        in_data == NULL || in_len == 0 || out_data == NULL) {
        chip_log_error("invalid input args\n");
        return -1;
    }

    if (mode == ID2_IES_MODE_NO_BC) {
        mac_key = key_data;
        enc_key = key_data + ID2_MAC_KEY_SIZE;
    } else if (mode == ID2_IES_MODE_BC) {
        enc_key = key_data;
        mac_key = key_data + in_len;
    } else {
        chip_log_error("not support this mode, %d\n", mode);
        return -1;
    }

    /* XOR Encryption */
    for (i = 0; i < in_len; i++) {
         out_data[i] = in_data[i] ^ enc_key[i];
    }

    out_len = DIGEST_SHA256_SIZE;
    ret = chip_hmac_digest(
               mac_key, ID2_MAC_KEY_SIZE,
               out_data, in_len, out_data + in_len, &out_len, DIGEST_TYPE_SHA256);
    if (ret < 0) {
        chip_log_error("chip_hmac_digest fail\n");
        return -1;
    }

    return 0;
}

static int _ecies_do_decrypt(uint8_t *key_data, uint32_t key_len,
                  uint32_t mode, uint8_t *in_data, uint32_t in_len, uint8_t *out_data)
{
    int ret;
    uint8_t *enc_key;
    uint8_t *mac_key;
    uint8_t digest[DIGEST_SHA256_SIZE];
    uint32_t i, out_len;

    if (key_data == NULL || key_len == 0 ||
        in_data == NULL || in_len == 0 || out_data == NULL) {
        chip_log_error("invalid input args\n");
        return -1;
    }

    if (mode == ID2_IES_MODE_NO_BC) {
        mac_key = key_data;
        enc_key = key_data + ID2_MAC_KEY_SIZE;
    } else if (mode == ID2_IES_MODE_BC) {
        enc_key = key_data;
        mac_key = key_data + in_len - ID2_MAC_KEY_SIZE;
    } else {
        chip_log_error("not support this mode, %d\n", mode);
        return -1;
    }

    if (in_len <= DIGEST_SHA256_SIZE) {
        chip_log_error("invalid input data length, %d\n", in_len);
        return -1;
    }

    out_len = DIGEST_SHA256_SIZE;
    ret = chip_hmac_digest(mac_key, ID2_MAC_KEY_SIZE,
               in_data, in_len - DIGEST_SHA256_SIZE, digest, &out_len, DIGEST_TYPE_SHA256);
    if (ret < 0) {
        chip_log_error("chip_hmac_digest fail\n");
        return -1;
    } else {
        if (memcmp(digest, in_data + in_len -DIGEST_SHA256_SIZE, DIGEST_SHA256_SIZE)) {
            chip_log_error("check ecies digest fail\n");
            return -1;
        }
    }

    /* XOR Decryption */
    for (i = 0; i < in_len - DIGEST_SHA256_SIZE; i++) {
         out_data[i] = in_data[i] ^ enc_key[i];
    }

    return 0;
}

int irot_hal_init(void)
{
    int ret;
    uint32_t grp_id = 0;
    uint32_t curve_size = 0;

#if (CONFIG_CHIP_ECDP_TYPE == CHIP_ECDP_TYPE_SECP192K1)
    grp_id = MBEDTLS_ECP_DP_SECP192K1;
    curve_size = 24;
#elif (CONFIG_CHIP_ECDP_TYPE == CHIP_ECDP_TYPE_SECP224K1)
    grp_id = MBEDTLS_ECP_DP_SECP224K1;
    curve_size = 28;
#elif (CONFIG_CHIP_ECDP_TYPE == CHIP_ECDP_TYPE_SECP256K1)
    grp_id = MBEDTLS_ECP_DP_SECP256K1;
    curve_size = 32;
#endif

    if (s_id2_info == NULL) {
        s_id2_info = ls_osa_malloc(sizeof(hal_id2_info_t));
        if (s_id2_info == NULL) {
            chip_log_error("out of mem, %d\n", (int)sizeof(hal_id2_info_t));
            return -1;
        }
    }

    ret = _load_id2_info(grp_id, curve_size, s_id2_info);
    if (ret < 0) {
        chip_log_error("load id2 info fail\n");
        return -1;
    }

    return 0;
}

void irot_hal_cleanup(void)
{
    if (s_id2_info != NULL) {
        memset(s_id2_info, 0, sizeof(hal_id2_info_t));
        ls_osa_free(s_id2_info);
        s_id2_info = NULL;
    }

    return;
}

int irot_hal_get_uid(uint8_t *id_buf, uint32_t *id_len)
{
    if (id_buf == NULL || id_len == NULL) {
        chip_log_error("invalid input args\n");
        return -1;
    }

    if (*id_len < strlen(CHIP_UID)) {
        chip_log_error("short buffer, %d %d\n", *id_len, (int)strlen(CHIP_UID));
        return -1;
    }

    *id_len = (uint32_t)strlen(CHIP_UID);
    memcpy(id_buf, CHIP_UID, *id_len);

    return 0;
}

int irot_hal_get_id2(uint8_t *id_buf, uint32_t *id_len)
{
    uint32_t uid_len;
    const char* stable = "0123456789ABCDEF";

    if (id_buf == NULL || id_len == NULL) {
        chip_log_error("invalid input args\n");
        return -1;
    }

    uid_len = ID2_ID_VERS_LEN + ID2_ID_VEND_LEN  +
              ID2_ID_RSVD_LEN + ID2_ID_SLEN_LEN + (int)strlen(CHIP_UID);
    if (*id_len < uid_len) {
        chip_log_error("short buffer, %d %d\n", *id_len, uid_len);
        return -1;
    } else {
        *id_len = uid_len;
    }

    uid_len = (int)strlen(CHIP_UID);

    memcpy(id_buf, ID2_ID_VERSION, ID2_ID_VERS_LEN);
    id_buf += ID2_ID_VERS_LEN;

    memcpy(id_buf, ID2_ID_VENDOR, ID2_ID_VEND_LEN);
    id_buf += ID2_ID_VEND_LEN;

    memcpy(id_buf, ID2_ID_RESERVE, ID2_ID_RSVD_LEN);
    id_buf += ID2_ID_RSVD_LEN;

    uid_len = (int)strlen(CHIP_UID);
    id_buf[0] = stable[(uid_len & 0xF0) >> 4];
    id_buf[1] = stable[(uid_len & 0x0F)];
    id_buf += ID2_ID_SLEN_LEN;

    memcpy(id_buf, CHIP_UID, uid_len);

    return 0;
}

int irot_hal_id2_sign(
         uint8_t *msg, uint32_t msg_len, uint8_t *sign, uint32_t *sign_len)
{
    int ret;
    mbedtls_ecp_group grp;
    mbedtls_mpi d, r, s;
    uint32_t grp_id;
    uint32_t hash_len;
    uint32_t curve_size;
    uint8_t hash[DIGEST_SHA256_SIZE];

    if (msg == NULL || msg_len == 0 ||
        sign == NULL || sign_len == NULL) {
        chip_log_error("invalid input args\n");
        return -1;
    }

    mbedtls_ecp_group_init(&grp);
    mbedtls_mpi_init(&d);
    mbedtls_mpi_init(&r);
    mbedtls_mpi_init(&s);

    hash_len = DIGEST_SHA256_SIZE;
    ret = chip_hash_digest(msg, msg_len,
               hash, &hash_len, DIGEST_TYPE_SHA256);
    if (ret < 0) {
        chip_log_error("chip_hash_digest fail\n");
        return -1;
    }

    if (s_id2_info == NULL) {
        chip_log_error("id2 info has not been loaded\n");
        ret = -1;
        goto _out;
    } else {
        grp_id = s_id2_info->grp_id;
        curve_size = s_id2_info->curve_size;

        ret = mbedtls_mpi_read_binary(&d, s_id2_info->d, curve_size);
        if (ret < 0) {
            chip_log_error("mpi read id2 key D fail\n");
            goto _out;
        }

        ret = mbedtls_ecp_group_load(&grp, grp_id);
        if (ret < 0) {
            chip_log_error("load ecp group %d fail\n", grp_id);
            goto _out;
        }
    }

    ret = mbedtls_ecdsa_sign(&grp, &r, &s, &d, hash, DIGEST_SHA256_SIZE, _ecp_random, NULL);
    if (ret < 0) {
        chip_log_error("mbedtls_ecdsa_sign fail, -0x%x\n", -ret);
        goto _out;
    }

    if (*sign_len < 2 * curve_size) {
         chip_log_error("short buffer, %d %d\n", *sign_len, 2 * curve_size);
         ret = -1;
         goto _out;
    } else {
         *sign_len = 2 * curve_size;
    }

    mbedtls_mpi_write_binary(&r, sign, curve_size);
    mbedtls_mpi_write_binary(&s, sign + curve_size, curve_size);

    ret = 0;

_out:
    mbedtls_ecp_group_free(&grp);
    mbedtls_mpi_free(&d);
    mbedtls_mpi_free(&r);
    mbedtls_mpi_free(&s);

    return ret;
}

int irot_hal_id2_verify(
         uint8_t *msg, uint32_t msg_len, uint8_t *sign, uint32_t sign_len)
{
    int ret;
    mbedtls_ecp_group grp;
    mbedtls_ecp_point Q;
    mbedtls_mpi r, s;
    uint32_t grp_id;
    uint32_t hash_len;
    uint32_t curve_size;
    uint8_t hash[DIGEST_SHA256_SIZE];

    if (msg == NULL || msg_len == 0 ||
        sign == NULL || sign_len == 0) {
        chip_log_error("invalid input args\n");
        return -1;
    }

    mbedtls_ecp_group_init(&grp);
    mbedtls_ecp_point_init(&Q);
    mbedtls_mpi_init(&r);
    mbedtls_mpi_init(&s);

    hash_len = DIGEST_SHA256_SIZE;
    ret = chip_hash_digest(msg, msg_len,
               hash, &hash_len, DIGEST_TYPE_SHA256);
    if (ret < 0) {
        chip_log_error("chip_hash_digest fail\n");
        return -1;
    }

    if (s_id2_info == NULL) {
        chip_log_error("id2 info has not been loaded\n");
        ret = -1;
        goto _out;
    } else {
        grp_id = s_id2_info->grp_id;
        curve_size = s_id2_info->curve_size;

        ret = mbedtls_mpi_read_binary(&Q.X, s_id2_info->x, curve_size);
        if (ret < 0) {
            chip_log_error("mpi read id2 key QX fail\n");
            goto _out;
        }

        ret = mbedtls_mpi_read_binary(&Q.Y, s_id2_info->y, curve_size);
        if (ret < 0) {
            chip_log_error("mpi read id2 key QX fail\n");
            goto _out;
        }

        mbedtls_mpi_lset(&Q.Z, 1);
    }

    if (sign_len != curve_size * 2) {
        chip_log_error("invalid sign length, %d %d\n", sign_len, curve_size * 2);
        ret = -1;
        goto _out;
    } else {
        ret = mbedtls_mpi_read_binary(&r, sign, curve_size);
        if (ret < 0) {
            chip_log_error("mpi read sign R fail\n");
            goto _out;
        }

        ret = mbedtls_mpi_read_binary(&s, sign + curve_size, curve_size);
        if (ret < 0) {
            chip_log_error("mpi read sign S fail\n");
            goto _out;
        }
    }

    ret = mbedtls_ecp_group_load(&grp, grp_id);
    if (ret < 0) {
        chip_log_error("load ecp group %d fail\n", grp_id);
        goto _out;
    }

    ret = mbedtls_ecdsa_verify(&grp, hash, DIGEST_SHA256_SIZE, &Q, &r, &s);
    if (ret < 0) {
        chip_log_error("mbedtls_ecdsa_verify fail, -0x%x\n", -ret);
        goto _out;
    }

    ret = 0;

_out:
    mbedtls_ecp_group_free(&grp);
    mbedtls_ecp_point_free(&Q);
    mbedtls_mpi_free(&r);
    mbedtls_mpi_free(&s);

    return ret;
}

int irot_hal_id2_encrypt(
         uint8_t *in_data, uint32_t in_len, uint8_t *out_data, uint32_t *out_len)
{
    int ret = 0;
    mbedtls_ecp_group grp;
    mbedtls_ecp_point tmp_q, id2_q;
    mbedtls_mpi tmp_d, z;
    uint8_t sh_key[ID2_MAX_CURVE_SIZE];
    uint8_t *key_buf = NULL;
    uint32_t grp_id;
    uint32_t exp_size;
    uint32_t curve_size;
    uint32_t key_buf_len;
    id2_ies_head_t head;

    if (in_data == NULL || in_len == 0 ||
        out_data == NULL || out_len == NULL) {
        chip_log_error("invalid input args\n");
        return -1;
    }

    mbedtls_ecp_group_init(&grp);
    mbedtls_ecp_point_init(&tmp_q);
    mbedtls_ecp_point_init(&id2_q);
    mbedtls_mpi_init(&tmp_d);
    mbedtls_mpi_init(&z);

    if (s_id2_info == NULL) {
        chip_log_error("id2 info has not been loaded\n");
        ret = -1;
        goto _out;
    } else {
        grp_id = s_id2_info->grp_id;
        curve_size = s_id2_info->curve_size;

        ret = mbedtls_mpi_read_binary(&id2_q.X, s_id2_info->x, curve_size);
        if (ret < 0) {
            chip_log_error("mpi read id2 QX fail\n");
            goto _out;
        }

        ret = mbedtls_mpi_read_binary(&id2_q.Y, s_id2_info->y, curve_size);
        if (ret < 0) {
            chip_log_error("mpi read id2 QY fail\n");
            goto _out;
        }

        mbedtls_mpi_lset(&id2_q.Z, 1);
    }

    ret = mbedtls_ecp_group_load(&grp, grp_id);
    if (ret < 0) {
        chip_log_error("load ecp group %d fail\n", grp_id);
        goto _out;
    }

    ret = mbedtls_ecdh_gen_public(&grp, &tmp_d, &tmp_q, _ecp_random, NULL);
    if (ret != 0) {
        chip_log_error("mbedtls_ecdh_gen_public fail, -0x%x\n", -ret);
        goto _out;
    }

    ret = mbedtls_ecdh_compute_shared(&grp, &z, &id2_q, &tmp_d, _ecp_random, NULL);
    if (ret != 0) {
        chip_log_error("mbedtls_ecdh_compute_shared fail, -0x%x\n", -ret);
        goto _out;
    } else {
        mbedtls_mpi_write_binary(&z, sh_key, curve_size);
    }

    key_buf_len = in_len + DIGEST_SHA256_SIZE;
    key_buf = ls_osa_malloc(key_buf_len);
    if (key_buf == NULL) {
        chip_log_error("out of mem, %d\n", key_buf_len);
        ret = -1;
        goto _out;
    }

    ret = _ecies_key_derivation(sh_key, curve_size, key_buf, key_buf_len);
    if (ret < 0) {
        chip_log_error("_ecies_key_derivation fail\n");
        goto _out;
    }

    /* Head + PubKey + CipherData + MacData */
    exp_size = sizeof(id2_ies_head_t) +
                   2 * curve_size + 1 + in_len + DIGEST_SHA256_SIZE;
    if (*out_len < exp_size) {
        chip_log_error("short buffer, %d %d\n", *out_len, exp_size);
        ret = -1;
        goto _out;
    } else {
        *out_len = exp_size;
    }

    /* Init Cipher Head Info */
    memset(&head, 0, sizeof(id2_ies_head_t));
    head.magic = ID2_IES_HEAD_MAGIC;
    head.version = ID2_IES_HEAD_VERSION;
    head.mode = ID2_IES_MODE_TYPE;

    memcpy(out_data, &head, sizeof(id2_ies_head_t));
    out_data += sizeof(id2_ies_head_t);

    /* ECC Public Key Binary Data */
    out_data[0] = 0x04;
    mbedtls_mpi_write_binary(&tmp_q.X, out_data + 1, curve_size);
    mbedtls_mpi_write_binary(&tmp_q.Y, out_data + 1 + curve_size, curve_size);
    out_data += 1 + 2 * curve_size;

    ret = _ecies_do_encrypt(key_buf, key_buf_len,
                    head.mode, in_data, in_len, out_data);
    if (ret < 0) {
        chip_log_error("_ecies_do_encrypt fail\n");
        goto _out;
    }

    ret = 0;

_out:
    if (key_buf != NULL) {
        ls_osa_free(key_buf);
    }

    mbedtls_ecp_group_free(&grp);
    mbedtls_ecp_point_free(&id2_q);
    mbedtls_ecp_point_free(&tmp_q);
    mbedtls_mpi_free(&tmp_d);
    mbedtls_mpi_free(&z);

    return ret;
}

int irot_hal_id2_decrypt(
         uint8_t *in_data, uint32_t in_len, uint8_t *out_data, uint32_t *out_len)
{
    int ret = 0;
    mbedtls_ecp_group grp;
    mbedtls_ecp_point tmp_q;
    mbedtls_mpi id2_d, z;
    id2_ies_head_t *head = NULL;
    uint8_t sh_key[ID2_MAX_CURVE_SIZE];
    uint8_t *key_buf = NULL;
    uint32_t grp_id;
    uint32_t curve_size;
    uint32_t key_buf_len;

    if (in_data == NULL || in_len == 0 ||
        out_data == NULL || out_len == NULL) {
        chip_log_error("invalid input args\n");
        return -1;
    }

    mbedtls_ecp_group_init(&grp);
    mbedtls_ecp_point_init(&tmp_q);
    mbedtls_mpi_init(&id2_d);
    mbedtls_mpi_init(&z);

    if (s_id2_info == NULL) {
        chip_log_error("id2 info has not been loaded\n");
        ret = -1;
        goto _out;
    } else {
        grp_id = s_id2_info->grp_id;
        curve_size = s_id2_info->curve_size;

        ret = mbedtls_mpi_read_binary(&id2_d, s_id2_info->d, curve_size);
        if (ret < 0) {
            chip_log_error("mpi read id2 D fail\n");
            goto _out;
        }
    }

    ret = mbedtls_ecp_group_load(&grp, grp_id);
    if (ret < 0) {
        chip_log_error("load ecp group %d fail\n", grp_id);
        goto _out;
    }

    if (in_len < sizeof(id2_ies_head_t ) + 1 + 2 * curve_size + DIGEST_SHA256_SIZE) {
        chip_log_error("invalid input length, %d %d\n",
        in_len, sizeof(id2_ies_head_t ) + 1 + 2 * curve_size + DIGEST_SHA256_SIZE);
        ret = -1;
        goto _out;
    } else {
        head = (id2_ies_head_t *)in_data;
        if (head->magic != ID2_IES_HEAD_MAGIC) {
            chip_log_error("invalid ies head magic, %c\n", head->magic);
            ret = -1;
            goto _out;
        }

        if (head->version != ID2_IES_HEAD_VERSION) {
            chip_log_error("invalid ies head version, 0x%x\n", head->version);
            ret = -1;
            goto _out;
        }

        chip_log_debug("id2 ecies key mode, 0x%02x\n", head->mode);

        /* jump over id2 crypt head */
        in_data += sizeof(id2_ies_head_t);
        in_len -= sizeof(id2_ies_head_t);

        if (in_data[0] != 0x04) {
            chip_log_error("invalid key compress flag, 0x%x\n", in_data[0]);
            ret = -1;
            goto _out;
        }

        ret = mbedtls_mpi_read_binary(&tmp_q.X, in_data + 1, curve_size);
        if (ret < 0) {
            chip_log_error("mpi read tmp QX fail\n");
            goto _out;
        }

        ret = mbedtls_mpi_read_binary(&tmp_q.Y, in_data + 1 + curve_size, curve_size);
        if (ret < 0) {
            chip_log_error("mpi read tmp QY fail\n");
            goto _out;
        }

        mbedtls_mpi_lset(&tmp_q.Z, 1);

        /* jump over  EC Q bin data */
        in_data += 1 + 2 * curve_size;
        in_len = in_len - 1 - 2 * curve_size;
    }

    ret = mbedtls_ecdh_compute_shared(&grp, &z, &tmp_q, &id2_d, _ecp_random, NULL);
    if (ret != 0) {
        chip_log_error("mbedtls_ecdh_compute_shared fail, -0x%x\n", -ret);
        goto _out;
    } else {
        mbedtls_mpi_write_binary(&z, sh_key, curve_size);
    }

    key_buf_len = in_len - DIGEST_SHA256_SIZE + ID2_MAC_KEY_SIZE;
    key_buf = ls_osa_malloc(key_buf_len);
    if (key_buf == NULL) {
        chip_log_error("out of mem, %d\n", key_buf_len);
        ret = -1;
        goto _out;
    }

    ret = _ecies_key_derivation(sh_key, curve_size, key_buf, key_buf_len);
    if (ret < 0) {
        chip_log_error("_ecies_key_derivation fail\n");
        goto _out;
    }

    if (*out_len < in_len - DIGEST_SHA256_SIZE) {
        chip_log_error("short buffer, %d %d\n", *out_len, in_len - DIGEST_SHA256_SIZE);
        ret = -1;
        goto _out;
    } else {
        *out_len = in_len - DIGEST_SHA256_SIZE;
    }

    ret = _ecies_do_decrypt(key_buf, key_buf_len,
                    head->mode, in_data, in_len, out_data);
    if (ret < 0) {
        chip_log_error("_ecies_do_decrypt fail\n");
        goto _out;
    }

    chip_dump_buf("out_data", out_data, *out_len);

    ret = 0;

_out:
    if (key_buf != NULL) {
        ls_osa_free(key_buf);
    }

    mbedtls_ecp_group_free(&grp);
    mbedtls_ecp_point_free(&tmp_q);
    mbedtls_mpi_free(&id2_d);
    mbedtls_mpi_free(&z);

    return ret;
}

