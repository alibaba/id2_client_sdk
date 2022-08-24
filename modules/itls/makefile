include ../../make.rules
include ../../make.settings

CFLAGS  += -I../../include
CFLAGS  += -I../../include/osa
CFLAGS  += -I../../include/id2
CFLAGS  += -I../../include/itls
CFLAGS  += -I../../include/crypto

ifeq ($(CONFIG_LS_ID2_DEBUG), N)
CFLAGS  += -DCONFIG_SSL_DEBUG_NO
endif

CFLAGS  += -DCONFIG_SSL_DTLS_NO

SRCS := src/platform.c
SRCS += src/debug.c
SRCS += src/timing.c
SRCS += src/cipher.c
SRCS += src/cipher_wrap.c
SRCS += src/md.c
SRCS += src/md_wrap.c
SRCS += src/sha1.c
SRCS += src/sha256.c
SRCS += src/ssl_cli.c
SRCS += src/ssl_tls.c
SRCS += src/ssl_ciphersuites.c
SRCS += src/mbedtls_auth.c
SRCS += src/net_sockets.c
SRCS += src/mbedtls_alt.c

ifeq ($(BUILD_SYS), __LINUX__)
SRCS += src/hal_itls.c
else ifeq ($(BUILD_SYS), __ANDROID__)
SRCS += src/hal_itls.c
endif

OBJS := $(patsubst %.cxx,%.o,$(patsubst %.c,%.o,$(SRCS)))

OUT := libitls.a

$(OUT): $(OBJS)
	$(AR) -r $(OUT) $(OBJS)
%.o: %.c
	$(CC) -c $(CFLAGS) $< -o $*.o

clean:
	rm -f $(OBJS) .elf $(OUT)
