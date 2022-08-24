/*
 * Copyright (C) 2015-2018 Alibaba Group Holding Limited
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/time.h>

#if defined(PLATFORM_ANDROID) || defined(PLATFORM_LINUX_LE)
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <signal.h>
#endif

#include "itls/config.h"
#include "itls/debug.h"
#include "itls/ssl.h"
#include "itls/net_sockets.h"
#include "itls/hal_itls.h"

#if defined(MBEDTLS_AES_ALT)
#include "ali_crypto.h"
#endif

#if __GNUC__ >= 4
    #define BIND_GLOBAL   __attribute__ ((visibility ("default")))
    #define BIND_LOCAL    __attribute__ ((visibility ("hidden")))
#else
    #define BIND_GLOBAL
    #define BIND_LOCAL
#endif

#define ITLS_VER_MAJOR    2
#define ITLS_VER_MINOR    0
#define ITLS_VER_BLDNR    0

#define TLS_PARAM_MAGIC       (0x54321213)
#define SEND_TIMEOUT_SECONDS  (10)
#define RECV_TIMEOUT_SECONDS  (20)

typedef struct _tls_param_t {
    uint32_t magic;           /* itls param magic */
    mbedtls_ssl_context ssl;  /* itls control context */
    mbedtls_net_context fd;   /* itls network context */
    mbedtls_ssl_config conf;  /* itls configuration context */
} tls_param_t;

static int debug_threshold = 1;

#if defined(PLATFORM_ANDROID) || defined(PLATFORM_LINUX_LE)
static int net_prepare(void)
{
#if ( defined(_WIN32) || defined(_WIN32_WCE) ) && !defined(EFIX64) && \
   !defined(EFI32)
    WSADATA wsaData;
    static int wsa_init_done = 0;

    if (wsa_init_done == 0) {
        if (WSAStartup(MAKEWORD(2, 0), &wsaData) != 0) {
            return (MBEDTLS_ERR_NET_SOCKET_FAILED);
        }

        wsa_init_done = 1;
    }
#else
#if !defined(EFIX64) && !defined(EFI32)
    signal(SIGPIPE, SIG_IGN);
#endif
#endif
    return (0);
}

static int mbedtls_net_connect_timeout(mbedtls_net_context *ctx,
              const char *host, const char *port, int proto, int timeout)
{
    int ret;
    struct addrinfo hints, *addr_list, *cur;
    struct timeval sendtimeout;

    if ((ret = net_prepare()) != 0) {
        return (ret);
    }

    /* Do name resolution with both IPv6 and IPv4 */
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = proto == MBEDTLS_NET_PROTO_UDP ? SOCK_DGRAM : SOCK_STREAM;
    hints.ai_protocol = proto == MBEDTLS_NET_PROTO_UDP ? IPPROTO_UDP : IPPROTO_TCP;

    if (getaddrinfo(host, port, &hints, &addr_list) != 0) {
        return (MBEDTLS_ERR_NET_UNKNOWN_HOST);
    }

    /* Try the sockaddrs until a connection succeeds */
    ret = MBEDTLS_ERR_NET_UNKNOWN_HOST;
    for (cur = addr_list; cur != NULL; cur = cur->ai_next) {
        ctx->fd = (int) socket(cur->ai_family, cur->ai_socktype,
                               cur->ai_protocol);
        if (ctx->fd < 0) {
            ret = MBEDTLS_ERR_NET_SOCKET_FAILED;
            continue;
        }

        sendtimeout.tv_sec = timeout;
        sendtimeout.tv_usec = 0;

        if (0 != setsockopt(ctx->fd, SOL_SOCKET, SO_SNDTIMEO, &sendtimeout, sizeof(sendtimeout))) {
            SSL_DBG_LOG("setsockopt fail errno, %d\n", errno);
            close(ctx->fd);
            ret = MBEDTLS_ERR_NET_CONNECT_FAILED;
            break;
        }

        SSL_DBG_LOG("setsockopt SO_SNDTIMEO timeout: %d\n", (int)sendtimeout.tv_sec);

        if (connect(ctx->fd, cur->ai_addr, cur->ai_addrlen) == 0) {
            ret = 0;
            break;
        }

        close(ctx->fd);
        ret = MBEDTLS_ERR_NET_CONNECT_FAILED;
    }

    freeaddrinfo(addr_list);

    return (ret);
}
#endif

static int _tls_random(void *p_rng, unsigned char *output, size_t output_len)
{
    uint64_t time_ms;

    (void)p_rng;

    time_ms = ls_osa_get_time_ms();

#if defined(MBEDTLS_AES_ALT)
    ali_seed((uint8_t *)&time_ms, sizeof(uint8_t *));
    ali_rand_gen(output, output_len);
#else
    srandom((unsigned int)time_ms);
    while(output_len > 0) {
        output[output_len - 1] = random() & 0xFF;
        output_len--;
    }
#endif

    return 0;
}

static void _tls_debug( void *ctx, int level,
                      const char *file, int line, const char *str )
{
    ((void) ctx);
    ((void) level);

    SSL_DBG_LOG("%s:%04d: %s", file, line, str);
}

BIND_GLOBAL
void hal_itls_get_version(char version[16])
{
    memset(version, 0, 16);
    ls_osa_snprintf(version, 16, "%d.%d.%d",
        ITLS_VER_MAJOR, ITLS_VER_MINOR, ITLS_VER_BLDNR);
}

BIND_GLOBAL
void hal_itls_set_debug_level(uint32_t debug_level)
{
    debug_threshold = (int)debug_level;

    SSL_DBG_LOG("set itls debug level to %d\n", debug_threshold);
    mbedtls_debug_set_threshold(debug_threshold);
}

BIND_GLOBAL
uintptr_t hal_itls_establish(
                   const char *host,
                   uint32_t port,
                   const char *product_key,
                   const char *product_secret)
{
    return hal_itls_establish_timeout(host, port,
                    product_key, product_secret, SEND_TIMEOUT_SECONDS);
}

BIND_GLOBAL
uintptr_t hal_itls_establish_timeout(
                   const char *host,
                   uint32_t port,
                   const char *product_key,
                   const char *product_secret,
                   uint32_t timeout)
{
    int ret = 0;
    char port_str[16];
    tls_param_t *param = NULL;

    SSL_DBG_LOG("iTLS Library, Version: %d.%d.%d\n",
                ITLS_VER_MAJOR, ITLS_VER_MINOR, ITLS_VER_BLDNR);
    SSL_DBG_LOG("iTLS Library, Build Time: %s %s\n", __DATE__, __TIME__);

    if (host == NULL || product_key == NULL || product_secret == NULL) {
        SSL_DBG_LOG("invalid input args\n");
        return 0;
    }

    if (timeout == 0) {
        SSL_DBG_LOG("invalid timeout seconds, %d\n", timeout);
        return 0;
    }

    memset(port_str, 0, 16);
    sprintf(port_str, "%u", (int)port);

    param = ls_osa_calloc(1, sizeof(tls_param_t));
    if (param == NULL) {
        SSL_DBG_LOG("ls_osa_calloc(%d) fail\n", (int)sizeof(tls_param_t));
        goto _out;
    }

    /*
     * 0. Initialize the RNG and the session data
     */
    mbedtls_net_init(&param->fd);
    mbedtls_ssl_init(&param->ssl);
    mbedtls_ssl_config_init(&param->conf);

    /*
     * 1. Start the connection
     */
    SSL_DBG_LOG("  . Connecting to tcp/%s/%s...\n", host, port_str);
#if !defined(PLATFORM_ANDROID) && !defined(PLATFORM_LINUX_LE)
    if ((ret = mbedtls_net_connect(&param->fd,
                       host, port_str, MBEDTLS_NET_PROTO_TCP)) != 0) {
        SSL_DBG_LOG(" failed! mbedtls_net_connect returned %d\n", ret);
        goto _out;
    }
#else
    if ((ret = mbedtls_net_connect_timeout(&param->fd, host,
                       port_str, MBEDTLS_NET_PROTO_TCP, timeout)) != 0) {
        SSL_DBG_LOG(" failed! mbedtls_net_connect_timeout returned %d\n", ret);
        goto _out;
    }
#endif
    SSL_DBG_LOG("ok\n");

    /*
     * 2. Setup stuff
     */
    SSL_DBG_LOG("  . Setting up the SSL/TLS structure...\n");
    if ((ret = mbedtls_ssl_config_defaults(&param->conf,
                    MBEDTLS_SSL_IS_CLIENT,
                    MBEDTLS_SSL_TRANSPORT_STREAM,
                    MBEDTLS_SSL_PRESET_DEFAULT)) != 0) {
        SSL_DBG_LOG("failed! mbedtls_ssl_config_defaults returned %d\n", ret);
        goto _out;
    }
    SSL_DBG_LOG(" ok\n");

    mbedtls_ssl_conf_rng(&param->conf, _tls_random, NULL );
    mbedtls_ssl_conf_dbg(&param->conf, _tls_debug, NULL );

    /* set socket recv timeout */
    mbedtls_ssl_conf_read_timeout(&param->conf, RECV_TIMEOUT_SECONDS * 1000);

    /* extra data for authentication */
    if ((ret = mbedtls_ssl_conf_auth_extra(
                   &param->conf, product_key, strlen(product_key))) != 0) {
        SSL_DBG_LOG("failed! mbedtls_ssl_conf_auth_extra returned %d\n", ret);
        goto _out;
    }

    /* token for one-time provisioning */
    if ((ret = mbedtls_ssl_conf_auth_token(
                    &param->conf, product_secret, strlen(product_secret))) != 0) {
        SSL_DBG_LOG("failed! mbedtls_ssl_conf_auth_token returned %d\n", ret);
        goto _out;
    }

#if defined(MBEDTLS_SSL_MAX_FRAGMENT_LENGTH)
    if ((ret = mbedtls_ssl_conf_max_frag_len(&param->conf, MBEDTLS_SSL_MAX_FRAG_LEN_1024)) != 0) {
        SSL_DBG_LOG("failed! mbedtls_ssl_conf_max_frag_len returned %d\n", ret);
        goto _out;
    }
#endif

    if ((ret = mbedtls_ssl_setup(&param->ssl, &param->conf)) != 0) {
        SSL_DBG_LOG("failed! mbedtls_ssl_setup returned %d\n", ret);
        goto _out;
    }

    mbedtls_ssl_set_bio(&param->ssl, &param->fd, mbedtls_net_send,
                         mbedtls_net_recv, mbedtls_net_recv_timeout);

    /*
     * 3. Handshake
     */
    SSL_DBG_LOG("  . Performing the SSL/TLS handshake...\n");
    while ((ret = mbedtls_ssl_handshake(&param->ssl)) != 0) {
        if (ret != MBEDTLS_ERR_SSL_WANT_READ && ret != MBEDTLS_ERR_SSL_WANT_WRITE) {
            SSL_DBG_LOG(" failed\n  ! mbedtls_ssl_handshake returned -0x%04x\n", -ret);
            goto _out;
        }
    }
    SSL_DBG_LOG(" ok\n");

    param->magic = TLS_PARAM_MAGIC;
    ret = 0;

_out:
    if (ret != 0) {
        mbedtls_net_free(&param->fd);
        mbedtls_ssl_free(&param->ssl);
        mbedtls_ssl_config_free(&param->conf);

        ls_osa_free(param);
        param = NULL;
    }

    return (uintptr_t)param;
}

BIND_GLOBAL
uint32_t hal_itls_get_alert_type(void)
{
    return mbedtls_ssl_get_message_alert_type();
}

BIND_GLOBAL
int32_t hal_itls_destroy(uintptr_t handle)
{
    tls_param_t *param = (tls_param_t *)handle;

    SSL_DBG_LOG("itls disconnect\n");

    if (handle == (uintptr_t)NULL) {
        SSL_DBG_LOG("handle is NULL\n");
        return 0;
    }

    if (param->magic != TLS_PARAM_MAGIC) {
        SSL_DBG_LOG("bad handle magic, 0x%x\n", param->magic);
        return 0;
    }

    mbedtls_ssl_close_notify(&param->ssl);
    mbedtls_net_free(&param->fd);
    mbedtls_ssl_free(&param->ssl);
    mbedtls_ssl_config_free(&param->conf);

    memset(param, 0, sizeof(tls_param_t));
    ls_osa_free(param);

    return 0;
}

BIND_GLOBAL
int32_t hal_itls_write(uintptr_t handle, const char *buf, int len, int timeout_ms)
{
    int ret = -1;
    uint32_t total_len = 0;
    tls_param_t *param = (tls_param_t *)handle;

    if (handle == (uintptr_t)NULL || buf == NULL || len == 0) {
        SSL_DBG_LOG("invalid input args\n");
        return -1;
    }

    if (param->magic != TLS_PARAM_MAGIC) {
        SSL_DBG_LOG("bad handle magic, 0x%x\n", param->magic);
        return -1;
    }

    (void)timeout_ms;

    while (total_len < len) {
        ret = mbedtls_ssl_write(&(param->ssl), (uint8_t *)buf + total_len, len - total_len);
        if (ret > 0) {
            total_len += ret;
            continue;
        } else if (ret == 0) {
            SSL_DBG_LOG("itls write timeout\n");
            return 0;
        } else {
            SSL_DBG_LOG("itls write error, code = %d", ret);
            return -1;
        }
    }

    return total_len;
}

BIND_GLOBAL
int32_t hal_itls_read(uintptr_t handle, char *buf, int len, int timeout_ms)
{
    int ret = -1;
    uint32_t read_len = 0;
    static int net_status = 0;
    tls_param_t *param = (tls_param_t *)handle;

    if (handle == (uintptr_t)NULL || buf == NULL || len == 0) {
        SSL_DBG_LOG("invalid input args\n");
        return -1;
    }

    if (param->magic != TLS_PARAM_MAGIC) {
        SSL_DBG_LOG("bad handle magic, 0x%x\n", param->magic);
        return -1;
    }

    /* set minimum timeout */
    if (timeout_ms < 2000) {
        timeout_ms = 2000;
    }

    mbedtls_ssl_conf_read_timeout(&(param->conf), timeout_ms);
    while (read_len < len) {
        ret = mbedtls_ssl_read(&(param->ssl), (uint8_t *)buf + read_len, len - read_len);
        if (ret > 0) {
            read_len += ret;
            net_status = 0;
        } else if (ret == 0) {
            /* if ret is 0, indicate the connection is closed during last call */
            return read_len;
        } else {
            if (MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY == ret) {
                SSL_DBG_LOG("itls recv peer close notify\n");
                net_status = -2; /* connection is closed */
                break;
            } else if ((MBEDTLS_ERR_SSL_TIMEOUT == ret)
                       || (MBEDTLS_ERR_SSL_CONN_EOF == ret)
                       || (MBEDTLS_ERR_SSL_NON_FATAL == ret)) {
                /* read already complete */
                /* if call mbedtls_ssl_read again, it will return 0 (means EOF) */
                return read_len;
            } else {
#ifdef CSP_LINUXHOST
                if (MBEDTLS_ERR_SSL_WANT_READ == ret && errno == EINTR) {
                    continue;
                }
#endif
                SSL_DBG_LOG("itls recv error: code = %d\n", ret);
                return -2; /* connection error */
            }
        }
    }

    return (read_len > 0) ? read_len : net_status;
}

