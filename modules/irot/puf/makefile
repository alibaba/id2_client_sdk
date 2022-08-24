include ../../../make.rules
include ../../../make.settings

CHIP_NAME := demo

CFLAGS  += -I../../../include/osa
CFLAGS  += -I../../../include/irot
CFLAGS  += -I../../../include/irot/puf
CFLAGS  += -I../../../include/crypto

CFLAGS  += -I./inc

ifeq ($(CONFIG_LS_ID2_DEBUG), Y)
CFLAGS  += -DCONFIG_CHIP_DEBUG
endif

ifeq ($(CONFIG_LS_ID2_KEY_TYPE), ECC)
CFLAGS  += -DCONFIG_CHIP_KEY_TYPE=CHIP_KEY_TYPE_ECC

ifeq ($(CONFIG_LS_ID2_ECDP_TYPE), K-163)
CFLAGS  += -DCONFIG_CHIP_ECDP_TYPE=CHIP_ECDP_TYPE_SECT163K1
else ifeq ($(CONFIG_LS_ID2_ECDP_TYPE), K-233)
CFLAGS  += -DCONFIG_CHIP_ECDP_TYPE=CHIP_ECDP_TYPE_SECT233K1
else ifeq ($(CONFIG_LS_ID2_ECDP_TYPE), K-283)
CFLAGS  += -DCONFIG_CHIP_ECDP_TYPE=CHIP_ECDP_TYPE_SECT283K1
else ifeq ($(CONFIG_LS_ID2_ECDP_TYPE), K-192)
CFLAGS  += -DCONFIG_CHIP_ECDP_TYPE=CHIP_ECDP_TYPE_SECP192K1
else ifeq ($(CONFIG_LS_ID2_ECDP_TYPE), K-224)
CFLAGS  += -DCONFIG_CHIP_ECDP_TYPE=CHIP_ECDP_TYPE_SECP224K1
else ifeq ($(CONFIG_LS_ID2_ECDP_TYPE), K-256)
CFLAGS  += -DCONFIG_CHIP_ECDP_TYPE=CHIP_ECDP_TYPE_SECP256K1
endif

else
CFLAGS  += -DCONFIG_CHIP_KEY_TYPE=CHIP_KEY_TYPE_NON
endif

SRCS    := src/km_to_irot.c
SRCS    += src/chip_util.c
SRCS    += chipset/$(CHIP_NAME)/irot_hal_ecc.c

ifeq ($(CHIP_NAME), demo)
CFLAGS  += -I./chipset/demo/mbedtls/include

SRCS    += chipset/demo/mbedtls/src/ecp.c
SRCS    += chipset/demo/mbedtls/src/ecp_curves.c
SRCS    += chipset/demo/mbedtls/src/ecdh.c
SRCS    += chipset/demo/mbedtls/src/ecdsa.c
SRCS    += chipset/demo/mbedtls/src/bignum.c
SRCS    += chipset/demo/mbedtls/src/platform_util.c
SRCS    += chipset/demo/mbedtls/src/asn1parse.c
SRCS    += chipset/demo/mbedtls/src/asn1write.c
endif

OBJS := $(patsubst %.cxx,%.o,$(patsubst %.c,%.o,$(SRCS)))

OUT := ../libkm.a

$(OUT): $(OBJS)
	$(AR) -r $(OUT) $(OBJS)
%.o: %.c
	$(CC) -c $(CFLAGS) $< -o $*.o

clean:
	rm -f $(OBJS) .elf $(OUT)
