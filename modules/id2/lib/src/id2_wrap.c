/*
 * Copyright (C) 2020-2022 Alibaba Group Holding Limited
 */

#include "id2_plat.h"
#include "id2_priv.h"
#include "id2_client.h"
#include "ali_crypto.h"

#define ID2_OTP_MAX_RETRY_TIME    2

/* ssl record and msg head length */
#define ID2_SSL_HDR_LEN           5
#define ID2_SSL_HS_HDR_LEN        4

/* supported ssl version */
#define ID2_SSL_MAJOR_VERSION_3   3
#define ID2_SSL_MINOR_VERSION_3   3

/* in_buf and out_buf length */
#define ID2_SSL_BUFFER_LEN        1024

#define ID2_SSL_KEY_GROUP_ID2     0x10001000
#define ID2_SSL_VER_NUM_INFO      0x00010200    /* v1.2.0 */

/* ciphersuites */
#define TLS_ID2_WITH_AES_128_CBC_SHA256    0xD003
#define TLS_ID2_WITH_AES_256_CBC_SHA256    0xD004

#define TLS_ID2_SSL_COMPRESS_NULL    0

/* ssl message types */
#define TLS_ID2_SSL_MSG_ALERT        21
#define TLS_ID2_SSL_MSG_HANDSHAKE    22

/* ssl handshake types */
#define TLS_ID2_SSL_HS_CLIENT_HELLO           1
#define TLS_ID2_SSL_HS_SERVER_HELLO           2
#define TLS_ID2_SSL_HS_HELLO_VERIFY_REQUEST   3

/* ssl extension id definitions */
#define TLS_ID2_EXT_AUTH_EXTRA       0x2000
#define TLS_ID2_EXT_KEY_ID           0x2001
#define TLS_ID2_EXT_AUTH_CODE        0x2002
#define TLS_ID2_EXT_KEY_OTP_DATA     0x2011
#define TLS_ID2_EXT_EXTENDED_VERSION 0x2020

static uint32_t id2_otp_time = 0;

typedef struct _otp_ssl_context {
    char *product_key;
    char *product_secret;
    uint32_t timeout;

    int major_ver; /*!< equal to  MBEDTLS_SSL_MAJOR_VERSION_3 */
    int minor_ver; /*!< either 0 (SSL3) or 1 (TLS1.0)    */

    int fd; /*net handle*/

    /*
     * Record layer (incoming data)
     */
    unsigned char *in_buf;  /*!< input buffer                     */
    unsigned char *in_hdr;  /*!< start of record header           */
    unsigned char *in_len;  /*!< two-bytes message length field   */
    unsigned char *in_msg;  /*!< message contents (in_iv+ivlen)   */
    unsigned char *in_offt; /*!< read offset in application data  */

    int in_msgtype;   /*!< record header: message type      */
    size_t in_msglen; /*!< record header: message length    */
    size_t in_left;   /*!< amount of data read so far       */

    /*
     * Record layer (outgoing data)
     */
    unsigned char *out_buf; /*!< output buffer                    */
    unsigned char *out_hdr; /*!< start of record header           */
    unsigned char *out_len; /*!< two-bytes message length field   */
    unsigned char *out_msg; /*!< message contents (out_iv+ivlen)  */

    int out_msgtype;   /*!< record header: message type      */
    size_t out_msglen; /*!< record header: message length    */
    size_t out_left;   /*!< amount of data not yet written   */
} otp_ssl_context;

static void _id2_print_error(int type)
{
    if (type == 160) {
        id2_log_info("ID2 - id2 generic error\n");
    } else if (type == 161) {
        id2_log_info("ID2 - id2 no quota\n");
    } else if (type == 162) {
        id2_log_info("ID2 - id2 is not exist\n");
    } else if (type == 163) {
        id2_log_info("ID2 - id2 authcode is invaid\n");
    } else if (type == 164) {
        id2_log_info("ID2 - id2 has not been activated\n");
    } else if (type == 165) {
        id2_log_info("ID2 - the the timestamp used in authcode is expired\n");
    } else if (type == 166) {
        id2_log_info("ID2 - id2 challenge is invalid\n");
    } else if (type == 167) {
        id2_log_info("ID2 - not support this operation\n");
    } else if (type == 168) {
        id2_log_info("ID2 - id2 has been suspended\n");
    } else if (type == 169) {
        id2_log_info("ID2 - id2 has been discarded\n");
    } else if (type == 170) {
        id2_log_info("ID2 - permission denied, id2 has been binded to other product key\n");
    } else if (type == 171) {
        id2_log_info("ID2 - product key is invalid\n");
    } else if (type == 172) {
        id2_log_info("ID2 - Product key is not exist\n");
    } else if (type == 173) {
        id2_log_info("ID2 - id2 server is busy\n");
    } else if (type == 174) {
        id2_log_info("ID2 - the device fingerprint is invalid\n");
    } else if (type == 175) {
        id2_log_info("ID2 - the device fingerprint is duplicated\n");
    } else if (type == 176) {
        id2_log_info("ID2 - id2 server random is invalid\n");
    } else if (type == 177) {
        id2_log_info("ID2 - hash type used in authcode generated is invalid\n");
    } else if (type == 178) {
        id2_log_info("ID2 - id2 key type is invalid\n");
    }
}

static irot_result_t _id2_otp_init(otp_ssl_context *ssl, char *host, char *port,
                                   char *product_key, char *product_secret, uint32_t timeout)
{
    irot_result_t result = IROT_SUCCESS;

    /* reset ssl context */
    memset(ssl, 0, sizeof(otp_ssl_context));
    
    ssl->in_buf = ls_osa_calloc(1, ID2_SSL_BUFFER_LEN);
    ssl->out_buf = ls_osa_calloc(1, ID2_SSL_BUFFER_LEN);
    if (ssl->in_buf == NULL || ssl->out_buf == NULL) {
        id2_log_error("out of mem, %d\n", ID2_SSL_BUFFER_LEN);
        ls_osa_free(ssl->in_buf);
        return IROT_ERROR_OUT_OF_MEMORY;
    }

    /* init in and out pointer */
    ssl->out_hdr = ssl->out_buf + 8;
    ssl->out_len = ssl->out_buf + 11;
    ssl->out_msg = ssl->out_buf + 13;

    ssl->in_hdr = ssl->in_buf + 8;
    ssl->in_len = ssl->in_buf + 11;
    ssl->in_msg = ssl->in_buf + 13;
    
    ssl->major_ver = ID2_SSL_MAJOR_VERSION_3;
    ssl->minor_ver = ID2_SSL_MINOR_VERSION_3;

    ssl->product_key = product_key;
    ssl->product_secret = product_secret;
    ssl->timeout = timeout;

    ssl->fd = ls_osa_net_connect(host, port, LS_NET_TYPE_TCP);
    if (ssl->fd < 0) {
        id2_log_error("ls_osa_net_connect fail, host = %s\n", host);
        result = IROT_ERROR_GENERIC;
        goto _out;
    }

_out:
    if (result != IROT_SUCCESS) {
        if (ssl->in_buf != NULL) {
            ls_osa_free(ssl->in_buf);
        }
        if (ssl->out_buf != NULL) {
            ls_osa_free(ssl->out_buf);
        }
    }

    return result;
}

static void _id2_otp_cleanup(otp_ssl_context *ssl)
{
    if (ssl == NULL) {
        id2_log_error("ssl context is null\n");
        return;
    }

    if (ssl->in_buf != NULL) {
        ls_osa_free(ssl->in_buf);
    }
    if (ssl->out_buf != NULL) {
        ls_osa_free(ssl->out_buf);
    }
    if (ssl->fd > 0) {
        ls_osa_net_disconnect(ssl->fd);
    }

    memset(ssl, 0, sizeof(otp_ssl_context));

    return;
}

static int _ssl_generate_random(uint8_t *output, uint32_t output_len)
{
    uint64_t time_ms;

    time_ms = ls_osa_get_time_ms();

    ali_seed((uint8_t *)&time_ms, sizeof(uint8_t *));
    ali_rand_gen(output, output_len);

    return 0;
}

static int _ssl_fetch_input(otp_ssl_context *ssl, uint8_t *buf, uint32_t nb_want)
{
    int ret_orig;
    uint32_t total = 0;
    int ret;

    while (total < nb_want) {
        ret = ls_osa_net_recv(ssl->fd,
                 buf + total, nb_want - total, ssl->timeout, &ret_orig);
        if (ret < 0) {
            /* encounter EINTR */
            if (ret_orig == -1) {
                continue;
            } else if (ret_orig == -2) {
                id2_log_error("network receive data timeout\n");
            } else {
                id2_log_error("network receive data fail\n");
            }
            return -1;
        }

        total += ret;
    }

    id2_log_hex_dump("fetch input record", buf, total);

    return 0;
}

static int _ssl_read_record(otp_ssl_context *ssl) 
{
    int ret = 0;

    /* read ssl record head info */
    ret = _ssl_fetch_input(ssl, ssl->in_hdr, ID2_SSL_HDR_LEN);
    if (ret < 0) {
        id2_log_error("ssl fetch input fail\n");
        return -1;
    }

    ssl->in_msgtype =  ssl->in_hdr[0];
    ssl->in_msglen = ( ssl->in_len[0] << 8 ) | ssl->in_len[1];

    if (ssl->in_msgtype != TLS_ID2_SSL_MSG_HANDSHAKE &&
        ssl->in_msgtype != TLS_ID2_SSL_MSG_ALERT) {
        id2_log_error("unknown record type, %d", ssl->in_msgtype);
        return -1;
    }

    if (ssl->in_msglen > ID2_SSL_BUFFER_LEN - (ssl->in_msg - ssl->in_buf)) {
        id2_log_error("bad message length, %d\n", ssl->in_msglen);
        return -1;
    }

    /* read hanshake message */
    ret = _ssl_fetch_input(ssl, ssl->in_msg, ssl->in_msglen);
    if (ret < 0) {
        id2_log_error("ssl fetch input fail\n");
        return -1;
    }

    return 0;
}

static int _ssl_write_record(otp_ssl_context *ssl)
{
    int ret;
    size_t len = ssl->out_msglen;
    unsigned char *buf;
    int ret_orig = 0;

    id2_log_debug("=> write record\n");

    if (ssl->out_msgtype == TLS_ID2_SSL_MSG_HANDSHAKE) {
        ssl->out_msg[1] = (unsigned char)((len - 4) >> 16);
        ssl->out_msg[2] = (unsigned char)((len - 4) >> 8);
        ssl->out_msg[3] = (unsigned char)((len - 4));
    }

    /* set hdr */
    {
        ssl->out_hdr[0] = (unsigned char)ssl->out_msgtype;
        ssl->out_hdr[1] = ssl->major_ver;
        ssl->out_hdr[2] = ssl->minor_ver;

        ssl->out_len[0] = (unsigned char)(len >> 8);
        ssl->out_len[1] = (unsigned char)(len);

        ssl->out_left = ID2_SSL_HDR_LEN + ssl->out_msglen;

        id2_log_debug(
            "output record: msgtype = %d, "
            "version = [%d:%d], msglen = %d\n",
            ssl->out_hdr[0], ssl->out_hdr[1], ssl->out_hdr[2],
            (ssl->out_len[0] << 8) | ssl->out_len[1]);
    }

    id2_log_hex_dump("output record sent to network",
                      ssl->out_hdr, ID2_SSL_HDR_LEN + ssl->out_msglen);

    /* total output message length */
    len = ID2_SSL_HDR_LEN + ssl->out_msglen;

    while (ssl->out_left > 0) {
        id2_log_debug("message length: %d, out_left: %d\n", len, ssl->out_left);
 
       /* update send buf pointer */
        buf = ssl->out_hdr + len - ssl->out_left;

        ret = ls_osa_net_send(ssl->fd, buf, ssl->out_left, &ret_orig);
        if (ret <= 0) {
            id2_log_error("net_send = %d, ret_orig = %d\n", ret, ret_orig);
            return -1;
        }

        ssl->out_left -= ret;
    }

    id2_log_debug("<= write record\n");

    return 0;
}

static int _ssl_write_auth_extra_ext(otp_ssl_context *ssl, unsigned char *buf, size_t *olen)
{
    unsigned char *p = buf;
    unsigned char *auth_extra = buf + ID2_SSL_HS_HDR_LEN;
    uint32_t auth_extra_len = strlen(ssl->product_key);

    /* extension tag */
    *p++ = (unsigned char)((TLS_ID2_EXT_AUTH_EXTRA >> 8) & 0xFF);
    *p++ = (unsigned char)((TLS_ID2_EXT_AUTH_EXTRA) & 0xFF);

    /* extension length */
    *p++ = (unsigned char)((auth_extra_len >> 8) & 0xFF);
    *p++ = (unsigned char)((auth_extra_len) & 0xFF);

    /* extension data */
    memcpy(auth_extra, ssl->product_key, auth_extra_len);

    id2_log_hex_dump("client hello, auth_extra", buf, auth_extra_len);

    *olen = 4 + auth_extra_len;

    return 0;
}

/*
 * struct {
 *     uint32_t key_group;
 *     opaque key_id<0..2^8-1>;
 * } Key_ID_Extension;
 */
static int _ssl_write_key_id_ext(otp_ssl_context *ssl, unsigned char *buf, size_t *olen)
{
    unsigned char *p = buf;
    uint32_t key_group;
    unsigned char *key_id = buf + 4;
    uint32_t key_id_len;

    /* extension tag */
    *p++ = (unsigned char)((TLS_ID2_EXT_KEY_ID >> 8) & 0xFF);
    *p++ = (unsigned char)((TLS_ID2_EXT_KEY_ID) & 0xFF);

    key_group = ID2_SSL_KEY_GROUP_ID2;

    key_id[0] = (unsigned char)((key_group) & 0xFF);
    key_id[1] = (unsigned char)((key_group >>  8) & 0xFF);
    key_id[2] = (unsigned char)((key_group >> 16) & 0xFF);
    key_id[3] = (unsigned char)((key_group >> 24) & 0xFF);

    key_id_len = 4 + ID2_ID_MIN_LEN;

    /* extension data */
    memset(key_id + 4, 'F', ID2_ID_MIN_LEN);

    /* extension length */
    *p++ = (unsigned char)((key_id_len >> 8) & 0xFF);
    *p++ = (unsigned char)((key_id_len) & 0xFF);

    id2_log_hex_dump("client hello, key_id", buf, key_id_len);

    *olen = 4 + key_id_len;

    return 0;
}

static int _ssl_write_auth_code_ext(otp_ssl_context *ssl, unsigned char *buf, size_t *olen) 
{
    int ret = 0;
    unsigned char *p = buf;
    unsigned char *auth_code = buf + 4;
    uint32_t auth_code_len = ssl->out_buf + ID2_SSL_BUFFER_LEN - auth_code;

    /* extension tag */
    *p++ = (unsigned char)((TLS_ID2_EXT_AUTH_CODE >> 8) & 0xFF);
    *p++ = (unsigned char)((TLS_ID2_EXT_AUTH_CODE) & 0xFF);

    /* extension data */
    ret = id2_client_get_otp_auth_code(
                     (const uint8_t *)ssl->product_secret,
                     strlen(ssl->product_secret), auth_code, &auth_code_len);
    if (ret != IROT_SUCCESS) {
        id2_log_error("id2_client_get_otp_auth_code fail, %d\n", ret);
        return -1;
    }

    /* extension length */
    *p++ = (unsigned char)((auth_code_len >> 8) & 0xFF);
    *p++ = (unsigned char)((auth_code_len) & 0xFF);

    id2_log_hex_dump("client hello, auth_code", buf, auth_code_len);

    *olen = 4 + auth_code_len;

    return 0;
}

static int _ssl_write_extended_version_ext(otp_ssl_context *ssl, unsigned char *buf, size_t *olen)
{
    unsigned char *p = buf;
    uint32_t len = 4;

    *p++ = (unsigned char)((TLS_ID2_EXT_EXTENDED_VERSION >> 8) & 0xFF);
    *p++ = (unsigned char)((TLS_ID2_EXT_EXTENDED_VERSION) & 0xFF);

    *p++ = (unsigned char)((len >> 8) & 0xFF);
    *p++ = (unsigned char)((len) & 0xFF);

    *p++ = (unsigned char)((ID2_SSL_VER_NUM_INFO) & 0xFF);
    *p++ = (unsigned char)((ID2_SSL_VER_NUM_INFO >>  8) & 0xFF);
    *p++ = (unsigned char)((ID2_SSL_VER_NUM_INFO >> 16) & 0xFF);
    *p++ = (unsigned char)((ID2_SSL_VER_NUM_INFO >> 24) & 0xFF);

    id2_log_hex_dump("client hello, extended version", buf, len);

    *olen = 4 + len;
   
    return 0;
}

static int _ssl_parse_hello_verify_ext(
                otp_ssl_context *ssl, unsigned char *buf, size_t len)
{
    const unsigned char *ext = buf;
    unsigned int ext_id;
    unsigned int ext_size;
    int ret = 0;

    /* expect otp data extension existed */
    if (len < 4) {
        id2_log_error("no extension data for hello verify\n");
        return -1;
    }

    ext_id = (ext[0] << 8) | ext[1];
    ext_size = (ext[2] << 8) | ext[3];

    if (ext_size + 4 > len) {
        id2_log_error("extension length does not match message size, %d %d\n",
                       ext_size + 4, (int)len);
        return - 1;
    }

    switch(ext_id) {
        case TLS_ID2_EXT_KEY_OTP_DATA: {
            id2_log_hex_dump("otp_data extension", ext + 4, ext_size);

            ret = id2_client_load_otp_data(ext + 4, ext_size);
            if (ret != IROT_SUCCESS) {
                id2_log_error("id2_client_load_otp_data fail, %d\n", ret);
                return -1;
            }

            break;
        }

        default:
           id2_log_error("unkown extension found: 0x%04x\n", ext_id);
           return -1;
    }

    return 0;
}

static irot_result_t _id2_otp_send_client_hello(otp_ssl_context *ssl)
{
    size_t n, olen, ext_len = 0;
    unsigned char *buf;
    unsigned char *p;
    int ret = 0;

    id2_log_debug("=> write client hello\n");

    /*
    *     0  .   0   handshake type
    *     1  .   3   handshake length
    *     4  .   5   highest version supported
    *     6  .   9   current UNIX time
    *    10  .  37   random bytes
    */
    buf = ssl->out_msg;
    p = buf + 4;

    /* set supported version */
    {
        *p++ = ssl->major_ver;
        *p++ = ssl->minor_ver;
    }

    id2_log_debug("client hello, max version: [%d:%d]\n", buf[4], buf[5]);

    /* generate current UNIX time and random bytes */
    _ssl_generate_random(p, 32);
    p += 32;

    id2_log_hex_dump("client hello, random bytes ", buf + 6, 32);

    /*
    *    38  .  38   session id length
    *    39  . 39+n  session id
    *   39+n . 39+n  DTLS only: cookie length (1 byte)
    *   40+n .  ..   DTSL only: cookie
    *   ..   . ..    ciphersuitelist length (2 bytes)
    *   ..   . ..    ciphersuitelist
    *   ..   . ..    compression methods length (1 byte)
    *   ..   . ..    compression methods
    *   ..   . ..    extensions length (2 bytes)
    *   ..   . ..    extensions
    */

    /* session id and length */
    n = 0;
    *p++ = (unsigned char)n;

    id2_log_debug("client hello, session id len.: %d\n", n);

    /* set ciphersuitelist and length */
    n = 2 + 2;
    *p++ = (unsigned char)(n >> 8) & 0xFF;
    *p++ = (unsigned char)(n);

    /* fixed two ciphersuites */
    *p++ = (unsigned char)(TLS_ID2_WITH_AES_256_CBC_SHA256 >> 8);
    *p++ = (unsigned char)(TLS_ID2_WITH_AES_256_CBC_SHA256);
    *p++ = (unsigned char)(TLS_ID2_WITH_AES_128_CBC_SHA256 >> 8);
    *p++ = (unsigned char)(TLS_ID2_WITH_AES_128_CBC_SHA256);


    id2_log_debug("client hello, add ciphersuite: %04x\n", TLS_ID2_WITH_AES_256_CBC_SHA256);
    id2_log_debug("client hello, add ciphersuite: %04x\n", TLS_ID2_WITH_AES_128_CBC_SHA256);

    *p++ = 1;
    *p++ = TLS_ID2_SSL_COMPRESS_NULL;

    /* set extensions and length */
    ret = _ssl_write_auth_extra_ext(ssl, p + 2 + ext_len, &olen);
    if (ret != 0) {
        id2_log_error("write auth extra extension fail\n");
        return IROT_ERROR_GENERIC;
    } else {
        ext_len += olen;
    }

    ret = _ssl_write_key_id_ext(ssl, p + 2 + ext_len, &olen);
    if (ret != 0) {
        id2_log_error("write key id extension fail\n");
        return IROT_ERROR_GENERIC;
    } else {
        ext_len += olen;
    }

    ret = _ssl_write_auth_code_ext(ssl, p + 2 + ext_len, &olen);
    if (ret != 0) {
        id2_log_error("write auth code extension fail\n");
        return IROT_ERROR_GENERIC;
    } else {
        ext_len += olen;
    }

    ret = _ssl_write_extended_version_ext(ssl, p + 2 + ext_len, &olen);
    if (ret != 0) {
        id2_log_error("write extended version extension fail\n");
        return IROT_ERROR_GENERIC;
    } else {
        ext_len += olen;
    }

    id2_log_debug("client hello, total extension length: %d\n", ext_len);

    *p++ = (unsigned char)((ext_len >> 8) & 0xFF);
    *p++ = (unsigned char)((ext_len) & 0xFF);
    p += ext_len;

    ssl->out_msglen = p - buf;
    ssl->out_msgtype = TLS_ID2_SSL_MSG_HANDSHAKE;
    ssl->out_msg[0] = TLS_ID2_SSL_HS_CLIENT_HELLO;

    /* add message hdr and send to network */
    ret = _ssl_write_record(ssl);
    if (ret != 0) {
        id2_log_error("ssl write record fail\n");
        return IROT_ERROR_GENERIC;
    }

    id2_log_debug("<= write client hello\n");

    return IROT_SUCCESS;
}

static irot_result_t _id2_otp_parse_hello_verify_request(otp_ssl_context *ssl)
{
    const unsigned char *p = ssl->in_msg + 4;
    int major_ver, minor_ver;
    unsigned char *buf;
    unsigned int ext_len;
    int ret;

    id2_log_debug("=> parse hello verify request\n");

    /*
     * struct {
     *   ProtocolVersion server_version;
     *   opaque cookie<0..2^8-1>;
     *   Extension extension<0..2^16-1>;
     * } HelloVerifyRequest;
     */

    /* get and check server version */
    major_ver = *p++;
    minor_ver = *p++;
    if (major_ver > ssl->major_ver || minor_ver > ssl->minor_ver) {
        id2_log_error("bad server version [%d.%d]\n", major_ver, minor_ver);
        return IROT_ERROR_GENERIC;
    }

    buf = (unsigned char *)p;
    ext_len = ssl->in_msg + ssl->in_msglen - p;

    ret = _ssl_parse_hello_verify_ext(ssl, buf, ext_len);
    if (ret != 0) {
        id2_log_error("parse hello verify request extension fail\n");
        return IROT_ERROR_GENERIC;
    }

    id2_log_debug("<= parse hello verify request\n");

    return IROT_SUCCESS;
}

static irot_result_t _id2_otp_parse_server_hello(otp_ssl_context *ssl)
{
    unsigned char *buf;
    int ret;

    id2_log_debug("=> parse server hello\n");

    ret = _ssl_read_record(ssl);
    if (ret != 0) {
        id2_log_error("ssl read record fail\n");
        return IROT_ERROR_GENERIC;
    }

    if (ssl->in_msgtype == TLS_ID2_SSL_MSG_HANDSHAKE) {
        if (ssl->in_msglen < ID2_SSL_HS_HDR_LEN) {
            id2_log_error("handshake message too short, %d\n", ssl->in_msglen);
            return IROT_ERROR_GENERIC;
        }
    } else if (ssl->in_msgtype == TLS_ID2_SSL_MSG_ALERT) {
        id2_log_info( "got an alert message, type: [%d:%d]\n",
                      ssl->in_msg[0], ssl->in_msg[1]);

        _id2_print_error(ssl->in_msg[1]);

        return IROT_ERROR_GENERIC;
    }

    buf = ssl->in_msg;

    if (buf[0] != TLS_ID2_SSL_HS_HELLO_VERIFY_REQUEST) {
        id2_log_error("unexpected ssl handshake type, %d\n", buf[0]);
        return IROT_ERROR_GENERIC;
    }

    return _id2_otp_parse_hello_verify_request(ssl);
}

static irot_result_t _id2_proc_otp_request(char *host, char *port,
                          char *product_key, char *product_secret, uint32_t timeout)
{
    irot_result_t result = IROT_SUCCESS;
    otp_ssl_context ctx;
    bool is_prov = false;

    result = _id2_otp_init(&ctx, host, port, product_key, product_secret, timeout);
    if (result != IROT_SUCCESS) {
        id2_log_error("id2 otp init fail, %d\n", result);
        return result;
    }

   result =  _id2_otp_send_client_hello(&ctx);
    if (result != IROT_SUCCESS) {
        id2_log_error("id2 send client hello fail, %d\n", result);
        goto _out;
    }

    result = _id2_otp_parse_server_hello(&ctx);
    if (result != IROT_SUCCESS) {
        id2_log_error("id2 parse server hello fail, %d\n", result);
        goto _out;
    }

    /* get prov stat to check if success */
    result = id2_client_get_prov_stat(&is_prov);
    if (result != IROT_SUCCESS) {
        id2_log_error("id2 client get prov stat fail, %d\n", result);
        goto _out;
    } else {
        if (is_prov != true) {
            id2_log_info("no id2 has been provisioned\n");
            result = IROT_ERROR_ITEM_NOT_FOUND;
            goto _out;
        }
    }

_out:
    _id2_otp_cleanup(&ctx);

    return result;
}

irot_result_t id2_client_wrap_do_provisioning(const char *host, uint32_t port,
                  const char *product_key, const char *product_secret, uint32_t timeout_ms) 
{
    irot_result_t result = IROT_SUCCESS;
    char host_str[128] = {0};
    char port_str[16] = {0};
    uint32_t len = 0;
    uint32_t retry = 0;
    bool is_prov = false;

    if (!is_id2_client_inited()) {
        id2_log_error("id2 not inited.\n");
        return IROT_ERROR_GENERIC;
    }

    if (host == NULL || product_key == NULL || product_secret == NULL) {
        id2_log_error("invalid input args\n");
        return IROT_ERROR_BAD_PARAMETERS;
    }

    /* set minimum timeout to 2 seconds */
    if (timeout_ms < 2000) {
        timeout_ms = 2000;
    }

    ls_osa_snprintf(host_str, 128, "%s.%s", product_key, host);
    ls_osa_snprintf(port_str, 16, "%u", (int)port);

    len = (int)strlen(host);
    if (len > 128) {
        id2_log_error("invalid host name length, %d\n", len);
        return IROT_ERROR_GENERIC;
    }

    len = (int)strlen(product_key);
    if (len > 128) {
        id2_log_error("invalid product key length, %d\n", len);
        return IROT_ERROR_GENERIC;
    }

    len = (int)strlen(product_secret);
    if (len > 128) {
        id2_log_error("invalid product secret length, %d\n", len);
        return IROT_ERROR_GENERIC;
    }

    result = id2_client_get_prov_stat(&is_prov);
    if (result != IROT_SUCCESS) {
        id2_log_error("id2 client get prov stat fail, %d\n", result);
        return result;
    } else {
        if (is_prov == true) {
            ls_osa_print("id2 has been provisioned\n");
            return IROT_SUCCESS;
        } else {
            ls_osa_print("id2 has not been provisioned, need to do provisioning!\n");

            /*
             * limit the max otp time in a prrocess,
             * which is used to avoid id2 otp wasting by mistake
             */
            if (id2_otp_time++ >= 4) {
                id2_log_error("id2 provisioning (time:%d) exceed the allowed times!\n",
                              (int)id2_otp_time);
                return IROT_ERROR_EXCESS_DATA;
            }
        }
    }

#if defined(ON_DAILY)
    ls_osa_snprintf(host_str, 128, "%s", host);
#else
    ls_osa_snprintf(host_str, 128, "%s.%s", product_key, host);
#endif

    ls_osa_snprintf(port_str, 16, "%u", (int)port);

    id2_log_info("host: %s\n", host_str);
    id2_log_info("port: %s\n", port_str);

    do {
        result = _id2_proc_otp_request(host_str, port_str,
                           (char *)product_key, (char *)product_secret, timeout_ms);
        if (result != IROT_SUCCESS) {
    
            /* reduce the influence of network and cloud server abnormal */
            if (retry++ >= ID2_OTP_MAX_RETRY_TIME) {
                break;
            } else {
                id2_log_info("execute id2 provisioning request - retry count: %d\n\n", retry);
                ls_osa_msleep(retry * 200);
            }
        }
    } while(result != IROT_SUCCESS);

    if (result != IROT_SUCCESS) {
        id2_log_error("id2 process otp request fail, %d\n", result);
        return result;
    }

    return IROT_SUCCESS;
}

