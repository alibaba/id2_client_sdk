include ../../make.rules
include ../../make.settings

ifeq ($(CONFIG_LS_ID2_ROT_TYPE), MDU)

CFLAGS  += -I./inc
CFLAGS  += -I../../include/osa
CFLAGS  += -I../../include/id2

CFLAGS  += -DCONFIG_ID2_MDU

ifeq ($(CONFIG_LS_ID2_DEBUG), Y)
CFLAGS  += -DCONFIG_ID2_DEBUG
endif

SRCS += module/core/id2_client.c
SRCS += module/atcmd/mdu_id2_quec.c
SRCS += module/driver/template/mdu_driver.c

else  #CONFIG_LS_ID2_ROT_TYPE

CFLAGS  += -I./inc
CFLAGS  += -I../../include/osa
CFLAGS  += -I../../include/id2
CFLAGS  += -I../../include/irot
CFLAGS  += -I../../include/crypto

ifeq ($(CONFIG_LS_ID2_DEBUG), Y)
CFLAGS  += -DCONFIG_ID2_DEBUG
endif

ifeq ($(CONFIG_LS_ID2_OTP), Y)
CFLAGS  += -DCONFIG_ID2_OTP
endif

ifeq ($(CONFIG_LS_ID2_KEY_TYPE), 3DES)
CFLAGS  += -DCONFIG_ID2_KEY_TYPE=ID2_KEY_TYPE_3DES
else ifeq ($(CONFIG_LS_ID2_KEY_TYPE), RSA)
CFLAGS  += -DCONFIG_ID2_KEY_TYPE=ID2_KEY_TYPE_RSA
else ifeq ($(CONFIG_LS_ID2_KEY_TYPE), AES)
endif

SRCS += src/core/id2_client.c
SRCS += src/core/otp.c
SRCS += src/plat/id2_plat.c
SRCS += src/utils/id2_util.c

endif #CONFIG_LS_ID2_ROT_TYPE

OBJS := $(patsubst %.cxx,%.o,$(patsubst %.c,%.o,$(SRCS)))

OUT := libid2.a

$(OUT): $(OBJS)
	$(AR) rc $(OUT) $(OBJS)
	$(RANLIB) $(OUT)
%.o: %.c
	$(CC) -c $(CFLAGS) $< -o $*.o

clean:
	rm -f $(OBJS) .elf $(OUT)
