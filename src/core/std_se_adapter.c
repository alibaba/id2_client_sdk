/*
 * Copyright (C) 2018 Alibaba Group Holding Limited
 */


#include <stdio.h>
#include <string.h>
#include "config.h"
#include "irot_hal.h"
#include "se_driver.h"
#include "util/util.h"
#include "log/log.h"

#if (ID2_SECURE_TYPE_CONFIG == ID2_SECURE_TYPE_STD_SE)

#define SE_ID2_LENGTH                       12

////////////////////////////////////////////////////////////////////////////////
//依据: <<ID2安全应用指令规范v1.0>>
////////////////////////////////////////////////////////////////////////////////

#define CLA_VALUE  0x80

typedef enum
{
    SE_DIGEST_TYPE_SHA1                     = 0x00,
    SE_DIGEST_TYPE_SHA224                   = 0x01,
    SE_DIGEST_TYPE_SHA256                   = 0x02,
    SE_DIGEST_TYPE_SHA384                   = 0x03,
    SE_DIGEST_TYPE_SHA512                   = 0x04,
    SE_DIGEST_TYPE_SM3                      = 0x05,
} digest_t;

////////////////////////////////////////////////////////////////////////////////

typedef enum
{
    MODE_SYMM_ENCRYPT                       = 0x51,
    MODE_SYMM_DECRYPT                       = 0x52,
    MODE_SYMM_COMPUTE_MAC                   = 0x53,
    MODE_SYMM_VERIFY_MAC                    = 0x54,
} sym_mode_t;


typedef enum
{
    TYPE_SYMM_DES_CBC_NOPADDING             = 0x00,
    TYPE_SYMM_DES_ECB_NOPADDING             = 0x01,
    TYPE_SYMM_AES_CBC_NOPADDING             = 0x02,
    TYPE_SYMM_AES_ECB_NOPADDING             = 0x03,
    TYPE_SYMM_DES_CBC_ISO9797_M1            = 0x04,
    TYPE_SYMM_DES_CBC_ISO9797_M2            = 0x05,
    TYPE_SYMM_AES_CBC_ISO9797_M1            = 0x06,
    TYPE_SYMM_AES_CBC_ISO9797_M2            = 0x07,

    TYPE_SYMM_SM4_CBC_NOPADDING             = 0x10,
    TYPE_SYMM_SM4_ECB_NOPADDING             = 0x11,
    TYPE_SYMM_SM7_CBC_NOPADDING             = 0x12,
    TYPE_SYMM_SM7_ECB_NOPADDING             = 0x13,
    TYPE_SYMM_SM4_CBC_ISO9797_M1            = 0x14,
    TYPE_SYMM_SM4_CBC_ISO9797_M2            = 0x15,
    TYPE_SYMM_SM7_CBC_ISO9797_M1            = 0x16,
    TYPE_SYMM_SM7_CBC_ISO9797_M2            = 0x17,

} sym_cipher_t;

////////////////////////////////////////////////////////////////////////////////

typedef enum
{
    MODE_ASYMM_ENCRYPT                      = 0x51,
    MODE_ASYMM_DECRYPT                      = 0x52,
    MODE_ASYMM_SIGN                         = 0x53,
    MODE_ASYMM_VERIFY                       = 0x54,
} asym_mode_t;

typedef enum
{
    TYPE_ASYMM_RSA_NOPADDING                = 0x00,
    TYPE_ASYMM_RSA_PKCS1                    = 0x01,
    TYPE_ASYMM_RSA_SHA1_PKCS1               = 0x01,
    TYPE_ASYMM_RSA_SHA256_PKCS1             = 0x02,
    TYPE_ASYMM_RSA_SHA384_PKCS1             = 0x03,
    TYPE_ASYMM_RSA_SHA512_PKCS1             = 0x04,
    TYPE_ASYMM_SM2_SM3                      = 0x05,
    TYPE_ASYMM_ECDSA                        = 0x06,
} asym_cipher_t;


enum
{
    INDEX_CLA                               = 0x00,
    INDEX_INS                               = 0x01,
    INDEX_P1                                = 0x02,
    INDEX_P2                                = 0x03,
    INDEX_LC                                = 0x04,
    INDEX_DATA                              = 0x05,
};

enum
{
    INS_GET_ID                              = 0xF8,
    INS_SYMMTRIC_ENCRYPT                    = 0xF6,
    INS_ASYMMTRIC_ENCRYPT                   = 0xF4,
    INS_GET_CHALLENGE                       = 0x84,
    INS_COMPUTE_DIGEST                      = 0xF0,
    INS_GET_RESPONSE                        = 0xC0,
};

#define CMD_APDU_HEAD_LENGTH                0x05
#define RSP_APDU_SW_LENGTH                  0x02

#define MAX_CMD_APDU_LENGTH                 (CMD_APDU_HEAD_LENGTH + 255 + 1)
#define MAX_RSP_APDU_LENGTH                 (0x100 + RSP_APDU_SW_LENGTH)

#define P2_NOT_LAST_BLOCK                   0x00
#define P2_LAST_BLOCK                       0x01
#define BLOCK_DATA_LENGTH                   0xF0
#define RSA_BLOCK_LENGTH                    0x80

const static uint8_t ID2_APPLET_AID[] = {0xA0, 0x00, 0x00, 0x00, 0x41, 0x6C, 0x69, 0x59, 0x75, 0x6E, 0x2E, 0x49, 0x44, 0x32};

static irot_result_t open_session(void** handle)
{
    irot_result_t ret;
    id2_log_debug("=> SE open session\n");
    ret = se_open_session(handle);
    id2_log_debug("<= SE open session, (ret = %d).\n", ret);
    if (ret != IROT_SUCCESS)
    {
        id2_log_error("ERROR: SE open session.\n");
    }
    return ret;
}

static irot_result_t close_session(void* handle)
{
    irot_result_t ret;
    id2_log_debug("=> SE close session.\n");
    ret = se_close_session(handle);
    id2_log_debug("<= SE close session, (ret = %d).\n", ret);
    if (ret != IROT_SUCCESS)
    {
        id2_log_error("ERROR: SE close session.\n");
    }

    return ret;
}

static irot_result_t apdu_transmit_wrap(void* handle, uint8_t* cmd_buf, uint32_t cmd_len, uint8_t* rsp_buf, uint32_t* rsp_len)
{
    irot_result_t ret;
    uint32_t counter = 0;

    //backup the buffer length
    uint32_t buf_len = *rsp_len;
    do
    {
        //ensure exit the loop
        counter++;
        if (counter >= 3)
        {
            ret = IROT_ERROR_GENERIC;
            break;
        }

        id2_log_debug("================================================================================\n");
        id2_log_hex_data("Command APDU:", cmd_buf, cmd_len);

        //reset the buffer length
        *rsp_len = buf_len;

        //call driver send the APDU command
        id2_log_debug("=> SE transmit.\n");
        ret = se_transmit(handle, cmd_buf, cmd_len, rsp_buf, rsp_len);
        id2_log_debug("<= SE transmit, (ret = %d, rsp_len = %d).\n", ret, *rsp_len);
        if (ret != IROT_SUCCESS)
        {
            id2_log_error("ERROR: SE transmit.\n");
            break;
        }
        id2_log_hex_data("Response APDU:", rsp_buf, *rsp_len);
        id2_log_debug("================================================================================\n");

        //length error
        if ((*rsp_len < RSP_APDU_SW_LENGTH) || (*rsp_len > MAX_RSP_APDU_LENGTH))
        {
            id2_log_error("ERROR: response apdu length.\n");
            ret = IROT_ERROR_GENERIC;
            break;
        }
        //CASE: T=0 protocol return 0x61
        if ((*rsp_len == 0x02) && (rsp_buf[*rsp_len - 2] == 0x61))
        {
            id2_log_debug("response apdu with 0x61.\n");
            cmd_buf[INDEX_CLA] = 0x00;
            cmd_buf[INDEX_INS] = INS_GET_RESPONSE;
            cmd_buf[INDEX_P1] = 0x00;
            cmd_buf[INDEX_P2] = 0x00;
            cmd_buf[INDEX_LC] = rsp_buf[*rsp_len - 1];
            cmd_len = CMD_APDU_HEAD_LENGTH;
            continue;
        }
        //CASE: T=0 protocol return 0x6C
        else if ((*rsp_len == 0x02) && (rsp_buf[*rsp_len - 2] == 0x6C))
        {
            id2_log_debug("response apdu with 0x6C.\n");
            cmd_buf[INDEX_LC] = rsp_buf[*rsp_len - 1];
            cmd_len = CMD_APDU_HEAD_LENGTH;
            continue;
        }
        //return 0x9000 OK
        else if ((rsp_buf[*rsp_len - 2] == 0x90) && (rsp_buf[*rsp_len - 1] == 0x00))
        {
            *rsp_len -= 0x02;
            break;
        }
        //other error
        else
        {
            id2_log_error("ERROR: response apdu data error.\n");
            ret = IROT_ERROR_GENERIC;
            break;
        }
    }
    while (1);

    return ret;
}

static irot_result_t select_application(void* handle, uint8_t* cmd_buf, uint8_t* rsp_buf, uint32_t* rsp_len)
{
    irot_result_t ret;

    //select command
    cmd_buf[INDEX_CLA] = 0x00;
    cmd_buf[INDEX_INS] = 0xA4;
    cmd_buf[INDEX_P1] = 0x04;
    cmd_buf[INDEX_P2] = 0x00;
    cmd_buf[INDEX_LC] = sizeof(ID2_APPLET_AID);
    memcpy(cmd_buf + INDEX_DATA, ID2_APPLET_AID, sizeof(ID2_APPLET_AID));
    ret = apdu_transmit_wrap(handle, cmd_buf, CMD_APDU_HEAD_LENGTH + sizeof(ID2_APPLET_AID), rsp_buf, rsp_len);

    return ret;
}

irot_result_t irot_hal_init()
{
    return IROT_SUCCESS;
}

irot_result_t irot_hal_get_id2(uint8_t* id, uint32_t* len)
{
    irot_result_t ret;
    irot_result_t close_ret;
    void* handle = NULL;
    uint8_t cmd_buf[MAX_CMD_APDU_LENGTH];
    uint8_t rsp_buf[MAX_RSP_APDU_LENGTH];
    uint32_t rsp_len = sizeof(rsp_buf);

    // open session
    ret = open_session(&handle);
    if (ret != IROT_SUCCESS)
    {
        goto EXIT;
    }

    // select application
#if ID2_SEND_SELECT_COMMAND
    ret = select_application(handle, cmd_buf, rsp_buf, &rsp_len);
    if (ret != IROT_SUCCESS)
    {
        goto EXIT;
    }
#endif
    // get ID
    memset(cmd_buf, 0x00, CMD_APDU_HEAD_LENGTH);
    cmd_buf[INDEX_CLA] = CLA_VALUE;
    cmd_buf[INDEX_INS] = INS_GET_ID;
    cmd_buf[INDEX_LC] = 0x00;
    rsp_len = sizeof(rsp_buf);
    ret = apdu_transmit_wrap(handle, cmd_buf, CMD_APDU_HEAD_LENGTH, rsp_buf, &rsp_len);
    if (ret != IROT_SUCCESS)
    {
        goto EXIT;
    }
    // 3 bytes head
    if (rsp_len != (0x03 + SE_ID2_LENGTH))
    {
        ret = IROT_ERROR_GENERIC;
        goto EXIT;
    }
    // ID2 data
    if (rsp_buf[2] != SE_ID2_LENGTH)
    {
        ret = IROT_ERROR_GENERIC;
        goto EXIT;
    }
    rsp_len -= 0x03;
    if (rsp_len > *len)
    {
        ret = IROT_ERROR_GENERIC;
        goto EXIT;
    }
    else
    {
        // | 2 TAG | 1 len |
        memcpy(id, rsp_buf + 3, rsp_len);
        *len = rsp_len;
    }

EXIT:
    // close session
    close_ret = close_session(handle);

    return ret == IROT_SUCCESS ? close_ret : ret;
}

irot_result_t irot_hal_sym_crypto(key_object* key_obj, uint8_t key_id,
                                  const uint8_t* iv, uint32_t iv_len,
                                  const uint8_t* in, uint32_t in_len,
                                  uint8_t* out, uint32_t* out_len,
                                  sym_crypto_param_t* crypto_param
                                 )
{
    irot_result_t ret;
    irot_result_t close_ret;
    void* handle = NULL;
    uint8_t cmd_buf[MAX_CMD_APDU_LENGTH];
    uint8_t rsp_buf[MAX_RSP_APDU_LENGTH];
    uint32_t rsp_len = sizeof(rsp_buf);
    uint8_t block_num = 0;
    uint32_t copy_len = 0;
    uint32_t offset;

    uint8_t cipher_type = crypto_param->cipher_type;
    //uint8_t block_mode = crypto_param->block_mode;
    //uint8_t padding_type = crypto_param->padding_type;
    uint8_t mode = crypto_param->mode;

    uint32_t out_buf_len = *out_len;
    uint32_t out_offset = 0;

    //open session
    ret = open_session(&handle);
    if (ret != IROT_SUCCESS)
    {
        goto EXIT;
    }

    // select application
#if ID2_SEND_SELECT_COMMAND
    ret = select_application(handle, cmd_buf, rsp_buf, &rsp_len);
    if (ret != IROT_SUCCESS)
    {
        goto EXIT;
    }
#endif
    memset(cmd_buf, 0x00, CMD_APDU_HEAD_LENGTH);
    //send data in loop, may be more than 1 block
    while (in_len > 0)
    {
        cmd_buf[INDEX_CLA] = CLA_VALUE;
        cmd_buf[INDEX_INS] = INS_SYMMTRIC_ENCRYPT;

        //fill P1,P2
        offset = INDEX_P1;
        cmd_buf[offset++] = block_num;
        cmd_buf[offset++] = P2_LAST_BLOCK;

        //skip LC
        offset++;

        //extra 5 bytes in the first block
        if (block_num == 0x00)
        {
            cmd_buf[offset++] = mode == MODE_ENCRYPT ? MODE_SYMM_ENCRYPT : MODE_SYMM_DECRYPT;
            cmd_buf[offset++] = cipher_type == CIPHER_TYPE_3DES ? TYPE_SYMM_DES_ECB_NOPADDING : TYPE_SYMM_AES_ECB_NOPADDING;
            cmd_buf[offset++] = key_id;

            //data total length
            cmd_buf[offset++] = (uint8_t)((in_len >> 8) & 0xFF);
            cmd_buf[offset++] = (uint8_t)(in_len & 0xFF);
        }

        copy_len = (in_len > BLOCK_DATA_LENGTH) ? BLOCK_DATA_LENGTH : in_len;
        //data
        memcpy(&cmd_buf[offset], in, copy_len);
        in += copy_len;
        in_len -= copy_len;
        offset += copy_len;

        //the length of LC
        cmd_buf[INDEX_LC] = (offset - CMD_APDU_HEAD_LENGTH);

        rsp_len = sizeof(rsp_buf);
        ret = apdu_transmit_wrap(handle, cmd_buf, offset, rsp_buf, &rsp_len);
        if (ret != IROT_SUCCESS)
        {
            goto EXIT;
        }
        //fill output data
        if (rsp_len > out_buf_len)
        {
            ret = IROT_ERROR_GENERIC;
            goto EXIT;
        }
        else
        {
            memcpy(out + out_offset, rsp_buf, rsp_len);
            out_offset += rsp_len;
            out_buf_len -= rsp_len;
        }
        block_num += 1;
    }
    *out_len = out_offset;
EXIT:
    // close session
    close_ret = close_session(handle);

    return ret == IROT_SUCCESS ? close_ret : ret;
}

# if(ID2_CRYPTO_TYPE_CONFIG == ID2_CRYPTO_TYPE_RSA)
static irot_result_t asymmetric_crypto(uint8_t mode, uint8_t cipher_type, uint8_t key_id, const uint8_t* in_data, uint32_t in_len, uint8_t* out_buf, uint32_t* out_len)
{
    irot_result_t ret;
    irot_result_t close_ret;
    void* handle = NULL;
    uint8_t cmd_buf[MAX_CMD_APDU_LENGTH];
    uint8_t rsp_buf[MAX_RSP_APDU_LENGTH];
    uint32_t rsp_len = sizeof(rsp_buf);
    uint8_t block_num = 0;
    uint32_t copy_len = 0;
    uint32_t offset;

    uint32_t out_buf_len = *out_len;
    uint32_t out_offset = 0;


    //open session
    ret = open_session(&handle);
    if (ret != IROT_SUCCESS)
    {
        goto EXIT;
    }

    //select application
#if ID2_SEND_SELECT_COMMAND
    ret = select_application(handle, cmd_buf, rsp_buf, &rsp_len);
    if (ret != IROT_SUCCESS)
    {
        goto EXIT;
    }
#endif
    memset(cmd_buf, 0x00, CMD_APDU_HEAD_LENGTH);
    //send data in loop, may be more than 1 block
    while (in_len > 0)
    {
        cmd_buf[INDEX_CLA] = CLA_VALUE;
        cmd_buf[INDEX_INS] = INS_ASYMMTRIC_ENCRYPT;

        //fill P1,P2
        offset = INDEX_P1;
        cmd_buf[offset++] = block_num;
        cmd_buf[offset++] = (in_len <= RSA_BLOCK_LENGTH) ? P2_LAST_BLOCK : P2_NOT_LAST_BLOCK;

        //skip LC
        offset++;

        //include extra 5 bytes in the first block
        if (block_num == 0x00)
        {
            cmd_buf[offset++] = mode;
            cmd_buf[offset++] = cipher_type;
            cmd_buf[offset++] = key_id;

            //total length
            cmd_buf[offset++] = (uint8_t)((in_len >> 8) & 0xFF);
            cmd_buf[offset++] = (uint8_t)(in_len & 0xFF);
        }

        copy_len = (in_len > RSA_BLOCK_LENGTH) ? RSA_BLOCK_LENGTH : in_len;
        //data
        memcpy(&cmd_buf[offset], in_data, copy_len);
        in_data += copy_len;
        in_len -= copy_len;
        offset += copy_len;

        //the length of LC
        cmd_buf[INDEX_LC] = (offset - CMD_APDU_HEAD_LENGTH);

        rsp_len = sizeof(rsp_buf);
        ret = apdu_transmit_wrap(handle, cmd_buf, offset, rsp_buf, &rsp_len);
        if (ret != IROT_SUCCESS)
        {
            goto EXIT;
        }
        //fill output data
        if (rsp_len > out_buf_len)
        {
            ret = IROT_ERROR_GENERIC;
            goto EXIT;
        }
        else
        {
            memcpy(out_buf + out_offset, rsp_buf, rsp_len);
            out_offset += rsp_len;
            out_buf_len -= rsp_len;
        }
        block_num += 1;
    }
    *out_len = out_offset;
EXIT:
    // close session
    close_ret = close_session(handle);

    return ret == IROT_SUCCESS ? close_ret : ret;
}

irot_result_t irot_hal_asym_priv_sign(key_object* key_obj, uint8_t key_id, const uint8_t* in, uint32_t in_len,
                                      uint8_t* sign, uint32_t* sign_len, asym_sign_verify_t type)
{
    irot_result_t ret;
    uint8_t mode;
    uint8_t cipher_type;

    mode = MODE_ASYMM_SIGN;
    switch (type)
    {
    case ASYM_TYPE_RSA_SHA1_PKCS1:
        {
            cipher_type = TYPE_ASYMM_RSA_SHA1_PKCS1;
        }
        break;
    case ASYM_TYPE_RSA_SHA256_PKCS1:
        {
            cipher_type = TYPE_ASYMM_RSA_SHA256_PKCS1;
        }
        break;
    default:
        {
            return IROT_ERROR_BAD_PARAMETERS;
        }
        break;
    }

    ret = asymmetric_crypto(mode, cipher_type, key_id, in, in_len, sign, sign_len);

    return ret;
}

irot_result_t irot_hal_asym_priv_decrypt(key_object* key_obj, uint8_t key_id,
        const uint8_t* in, uint32_t in_len,
        uint8_t* out, uint32_t* out_len,
        irot_asym_padding_t padding)
{
    irot_result_t ret;
    uint8_t mode;
    uint8_t cipher_type;

    mode = MODE_ASYMM_DECRYPT;
    if (padding != ASYM_PADDING_PKCS1)
    {
        return IROT_ERROR_BAD_PARAMETERS;
    }
    cipher_type = TYPE_ASYMM_RSA_PKCS1;
    ret = asymmetric_crypto(mode, cipher_type, key_id, in, in_len, out, out_len);
    return ret;
}
#endif

#if (ID2_HASH_MODE_CONFIG == ID2_HASH_ALG_IN_HAL)

irot_result_t irot_hal_hash_sum(const uint8_t* in, uint32_t in_len,
                                uint8_t* out, uint32_t* out_len, hash_t type)
{
    irot_result_t ret;
    irot_result_t close_ret;
    void* handle = NULL;
    uint8_t cmd_buf[MAX_CMD_APDU_LENGTH];
    uint8_t rsp_buf[MAX_RSP_APDU_LENGTH];
    uint32_t rsp_len = sizeof(rsp_buf);
    uint32_t block_num = 0;
    uint32_t copy_len = 0;
    uint32_t offset;
    uint8_t hash_type;

    switch (type)
    {
    case HASH_TYPE_SHA1:
        {
            hash_type = SE_DIGEST_TYPE_SHA1;
        }
        break;
    case HASH_TYPE_SHA256:
        {
            hash_type = SE_DIGEST_TYPE_SHA256;
        }
        break;
    default:
        {
            return IROT_ERROR_BAD_PARAMETERS;
        }
        break;
    }

    //open session
    ret = open_session(&handle);
    if (ret != IROT_SUCCESS)
    {
        goto EXIT;
    }
    //select application
#if ID2_SEND_SELECT_COMMAND
    ret = select_application(handle, cmd_buf, rsp_buf, &rsp_len);
    if (ret != IROT_SUCCESS)
    {
        goto EXIT;
    }
#endif
    memset(cmd_buf, 0x00, CMD_APDU_HEAD_LENGTH);
    cmd_buf[INDEX_CLA] = CLA_VALUE;
    cmd_buf[INDEX_INS] = INS_COMPUTE_DIGEST;

    //send data in loop, may be more than 1 block
    while (in_len > 0)
    {
        offset = INDEX_P1;

        //fill P1,P2
        cmd_buf[offset++] = (uint8_t)block_num;
        cmd_buf[offset++] = (in_len <= BLOCK_DATA_LENGTH) ? P2_LAST_BLOCK : P2_NOT_LAST_BLOCK;

        //skip LC
        offset++;

        //include extra 1 byte in the first block
        if (block_num == 0x00)
        {
            cmd_buf[offset++] = hash_type;
        }

        //data length
        copy_len = (in_len > BLOCK_DATA_LENGTH) ? BLOCK_DATA_LENGTH : in_len;

        //data
        memcpy(&cmd_buf[offset], in, copy_len);
        in += copy_len;
        in_len -= copy_len;
        offset += copy_len;

        //the length of LC
        cmd_buf[INDEX_LC] = (offset - CMD_APDU_HEAD_LENGTH);

        rsp_len = sizeof(rsp_buf);
        ret = apdu_transmit_wrap(handle, cmd_buf, offset, rsp_buf, &rsp_len);
        if (ret != IROT_SUCCESS)
        {
            goto EXIT;
        }

        //nothing for output if not the last block
        if ((cmd_buf[INDEX_P2] != P2_LAST_BLOCK) && (rsp_len > 0))
        {
            ret = IROT_ERROR_GENERIC;
            goto EXIT;
        }

        //output the hash when the last block
        if (cmd_buf[INDEX_P2] == P2_LAST_BLOCK)
        {
            if (rsp_len > *out_len)
            {
                ret = IROT_ERROR_GENERIC;
                goto EXIT;
            }
            else
            {
                memcpy(out, rsp_buf, rsp_len);
                *out_len = rsp_len;
            }
        }
        block_num += 1;
        //block number error
        if (block_num >= 0x100)
        {
            ret = IROT_ERROR_GENERIC;
            goto EXIT;
        }
    }
EXIT:
    //close session
    close_ret = close_session(handle);

    return ret == IROT_SUCCESS ? close_ret : ret;
}
#endif

#endif
