include ../../../make.rules

CHIP_NAME := template

CFLAGS  += -I../../../include/osa
CFLAGS  += -I../../../include/irot
CFLAGS  += -I../../../include/irot/se
CFLAGS  += -I../../../include/crypto

CFLAGS  += -I./inc
CFLAGS  += -I./chipset/$(CHIP_NAME)

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
