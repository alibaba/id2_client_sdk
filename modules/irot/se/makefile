include ../../../make.rules
include ../../../make.settings

CHIP_NAME := template

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
endif

SRCS    := src/core/km_to_irot.c
SRCS    += src/core/mtk_se_adapter.c
SRCS    += src/core/std_se_adapter.c
SRCS    += src/log/chip_log.c

SRCS    += chipset/$(CHIP_NAME)/se_driver/se_driver.c

OBJS := $(patsubst %.cxx,%.o,$(patsubst %.c,%.o,$(SRCS)))

OUT := ../libkm.a

$(OUT): $(OBJS)
	$(AR) rc $(OUT) $(OBJS)
	$(RANLIB) $(OUT)
%.o: %.c
	$(CC) -c $(CFLAGS) $< -o $*.o

clean:
	rm -f $(OBJS) .elf $(OUT)
