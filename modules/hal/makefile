include ../../make.rules

CFLAGS  += -I../../include/osa
CFLAGS  += -I../../include/hal
CFLAGS  += -I./crypto/demo/inc

ifeq ($(BUILD_SYS), __LINUX__)
CFLAGS  += -D__DEMO__
else ifeq ($(BUILD_SYS), __ANDROID__)
CFLAGS  += -D__DEMO__
endif

SRCS    := km/demo/ls_hal_km.c
SRCS    += sst/demo/ls_hal_sst.c
SRCS    += crypto/demo/src/ls_hal_aes.c
SRCS    += crypto/demo/src/ls_hal_sm4.c
SRCS    += crypto/demo/src/ls_hal_hash.c
SRCS    += crypto/demo/src/ls_hal_rand.c
SRCS    += crypto/demo/src/ls_hal_rsa.c
SRCS    += crypto/demo/src/ls_hal_sm2.c
SRCS    += crypto/demo/src/ls_hal_ecc.c
SRCS    += crypto/demo/src/aes.c
SRCS    += crypto/demo/src/sm4.c
SRCS    += crypto/demo/src/md5.c
SRCS    += crypto/demo/src/sha1.c
SRCS    += crypto/demo/src/sha256.c
SRCS    += crypto/demo/src/bignum.c
SRCS    += crypto/demo/src/rsa.c
SRCS    += crypto/demo/src/sm2.c
SRCS    += crypto/demo/src/sm3.c
SRCS    += crypto/demo/src/ecp.c
SRCS    += crypto/demo/src/ecp_curves.c

OBJS := $(patsubst %.cxx,%.o,$(patsubst %.c,%.o,$(SRCS)))

OUT := libls_hal.a

$(OUT): $(OBJS)
	$(AR) -r $(OUT) $(OBJS)
%.o: %.c
	$(CC) -c $(CFLAGS) $< -o $*.o

clean:
	rm -f $(OBJS) .elf $(OUT)
