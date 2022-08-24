include ../../../make.rules
include ../../../make.settings

CHIP_NAME := template
#CHIP_NAME := demo

CFLAGS  += -I../../../include/osa
CFLAGS  += -I../../../include/irot
CFLAGS  += -I../../../include/irot/se
CFLAGS  += -I../../../include/crypto

CFLAGS  += -I./inc
CFLAGS  += -I./chipset/$(CHIP_NAME)

ifeq ($(CONFIG_LS_ID2_KEY_TYPE), 3DES)
CFLAGS  += -DCONFIG_CHIP_KEY_TYPE=CHIP_KEY_TYPE_3DES
else ifeq ($(CONFIG_LS_ID2_KEY_TYPE), RSA)
CFLAGS  += -DCONFIG_CHIP_KEY_TYPE=CHIP_KEY_TYPE_RSA
else ifeq ($(CONFIG_LS_ID2_KEY_TYPE), AES)
CFLAGS  += -DCONFIG_CHIP_KEY_TYPE=CHIP_KEY_TYPE_AES
else ifeq ($(CONFIG_LS_ID2_KEY_TYPE), SM1)
CFLAGS  += -DCONFIG_CHIP_KEY_TYPE=CHIP_KEY_TYPE_SM1
else ifeq ($(CONFIG_LS_ID2_KEY_TYPE), SM2)
CFLAGS  += -DCONFIG_CHIP_KEY_TYPE=CHIP_KEY_TYPE_SM2
else ifeq ($(CONFIG_LS_ID2_KEY_TYPE), SM4)
CFLAGS  += -DCONFIG_CHIP_KEY_TYPE=CHIP_KEY_TYPE_SM4
else
CFLAGS  += -DCONFIG_CHIP_KEY_TYPE=CHIP_KEY_TYPE_NON
endif

SRCS    := src/core/km_to_irot.c
SRCS    += src/log/chip_log.c

ifeq ($(CHIP_NAME), template)
CFLAGS += -DCONFIG_CHIP_TYPE=CHIP_TYPE_SE_STD_CMD
SRCS    += src/core/std_se_adapter.c
SRCS    += chipset/template/se_driver/se_driver.c
else ifeq ($(CHIP_NAME), demo)
CFLAGS += -DCONFIG_CHIP_TYPE=CHIP_TYPE_SE_STD_HAL
CFLAGS  += -I$(TOP)/include/icrypto
SRCS    += chipset/demo/irot_hal.c
endif

OBJS := $(patsubst %.cxx,%.o,$(patsubst %.c,%.o,$(SRCS)))

OUT := ../libkm.a

$(OUT): $(OBJS)
	$(AR) -r $(OUT) $(OBJS)
%.o: %.c
	$(CC) -c $(CFLAGS) $< -o $*.o

clean:
	rm -f $(OBJS) .elf $(OUT)
