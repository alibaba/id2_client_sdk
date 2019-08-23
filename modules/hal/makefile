include ../../make.rules

CFLAGS  += -I../../include/osa
CFLAGS  += -I../../include/hal
CFLAGS  += -I./demo/inc

SRCS    := demo/src/ls_hal_aes.c
SRCS    += demo/src/ls_hal_hash.c
SRCS    += demo/src/ls_hal_rand.c
SRCS    += demo/src/ls_hal_rsa.c
SRCS    += demo/src/aes.c
SRCS    += demo/src/md5.c
SRCS    += demo/src/sha1.c
SRCS    += demo/src/sha256.c
SRCS    += demo/src/bignum.c
SRCS    += demo/src/rsa.c

OBJS := $(patsubst %.cxx,%.o,$(patsubst %.c,%.o,$(SRCS)))

OUT := libls_hal.a

$(OUT): $(OBJS)
	$(AR) rc $(OUT) $(OBJS)
	$(RANLIB) $(OUT)
%.o: %.c
	$(CC) -c $(CFLAGS) $< -o $*.o

clean:
	rm -f $(OBJS) .elf $(OUT)
