include ../../make.rules

CFLAGS += -I../../include/osa
CFLAGS += -I../../include/hal
CFLAGS += -I../../include/crypto
CFLAGS += -I./inc

CFLAGS += -DCONFIG_DBG_CRYPT=0
CFLAGS += -DCONFIG_RSA_ENCRYPT
CFLAGS += -DCONFIG_RSA_DECRYPT
CFLAGS += -DCONFIG_RSA_SIGN
CFLAGS += -DCONFIG_RSA_VERIFY
CFLAGS += -DRSA_PADDING_PKCS1_V15
CFLAGS += -DRSA_PADDING_PKCS1_V21

SRCS := src/api_init.c
SRCS += src/api_aes.c
SRCS += src/api_sm4.c
SRCS += src/api_hash.c
SRCS += src/api_hmac.c
SRCS += src/api_rsa.c
SRCS += src/api_sm2.c
SRCS += src/api_ecc.c
SRCS += src/api_rand.c
SRCS += src/api_pkwrite.c
SRCS += src/api_pkparse.c
SRCS += src/pkparse.c
SRCS += src/asn1write.c
SRCS += src/asn1parse.c
SRCS += src/oid.c

OBJS := $(patsubst %.cxx,%.o,$(patsubst %.c,%.o,$(SRCS)))

OUT := libicrypt.a

all: $(OUT) $(OBJS)

$(OUT): $(OBJS)
	$(AR) -r $(OUT) $(OBJS)

%.o: %.c
	@echo $(CC) $(CFLAGS) $<
	$(CC) -c $(CFLAGS) $(CRYPTO_CFLAGS) $< -o $*.o

clean:
	rm -f $(OBJS) $(OUT)
