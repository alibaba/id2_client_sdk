include ../../../make.rules
include ../../../make.settings

CFLAGS  += -I./inc
CFLAGS  += -I../../../include/osa
CFLAGS  += -I../../../include/id2
CFLAGS  += -I../../../include/irot
CFLAGS  += -I../../../include/crypto

ifeq ($(CONFIG_LS_ID2_DEBUG), Y)
CFLAGS  += -DCONFIG_ID2_DEBUG
endif

ifeq ($(CONFIG_LS_ID2_OTP), Y)
CFLAGS  += -DCONFIG_ID2_OTP
endif

ifeq ($(CONFIG_LS_ID2_KEY_TYPE), 3DES)
CFLAGS  += -DCONFIG_ID2_KEY_TYPE=ID2_KEY_TYPE_3DES
else ifeq ($(CONFIG_LS_ID2_KEY_TYPE), AES)
CFLAGS  += -DCONFIG_ID2_KEY_TYPE=ID2_KEY_TYPE_AES
else ifeq ($(CONFIG_LS_ID2_KEY_TYPE), RSA)
CFLAGS  += -DCONFIG_ID2_KEY_TYPE=ID2_KEY_TYPE_RSA
else ifeq ($(CONFIG_LS_ID2_KEY_TYPE), ECC)
CFLAGS  += -DCONFIG_ID2_KEY_TYPE=ID2_KEY_TYPE_ECC
else ifeq ($(CONFIG_LS_ID2_KEY_TYPE), SM1)
CFLAGS  += -DCONFIG_ID2_KEY_TYPE=ID2_KEY_TYPE_SM1
else ifeq ($(CONFIG_LS_ID2_KEY_TYPE), SM2)
CFLAGS  += -DCONFIG_ID2_KEY_TYPE=ID2_KEY_TYPE_SM2
else ifeq ($(CONFIG_LS_ID2_KEY_TYPE), SM4)
CFLAGS  += -DCONFIG_ID2_KEY_TYPE=ID2_KEY_TYPE_SM4
else
CFLAGS  += -DCONFIG_ID2_KEY_TYPE=ID2_KEY_TYPE_NON
endif

SRCS += src/id2_client.c
SRCS += src/id2_dpm.c
SRCS += src/id2_kpm.c
SRCS += src/id2_otp.c
SRCS += src/id2_wrap.c
SRCS += src/id2_plat.c
SRCS += src/id2_util.c

OBJS := $(patsubst %.cxx,%.o,$(patsubst %.c,%.o,$(SRCS)))

OUT := ../libid2.a

$(OUT): $(OBJS)
	$(AR) -r $(OUT) $(OBJS)
%.o: %.c
	$(CC) -c $(CFLAGS) $< -o $*.o

clean:
	rm -f $(OBJS) .elf $(OUT)
