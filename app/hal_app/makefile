
include ../../make.rules

CFLAGS  += -I./inc
CFLAGS  += -I../../include/osa
CFLAGS  += -I../../include/hal

CFLAGS  += -DCONFIG_HAL_CRYPTO

LDFLAGS += -pie

SRCS    := app_entry.c
SRCS    += src/hal_test.c
SRCS    += src/hal_aes_test.c
SRCS    += src/hal_sm2_test.c
SRCS    += src/hal_rsa_test.c
SRCS    += src/hal_hash_test.c
SRCS    += src/hal_rand_test.c

OBJS    := $(patsubst %.cxx,%.o,$(patsubst %.c,%.o,$(SRCS)))

LIBS    += ../../out/libs/libls_hal.a
LIBS    += ../../out/libs/libls_osa.a

OUT     := hal_app

$(OUT): $(OBJS) $(LIBS)
	$(CC) $(LDFLAGS) $^ -o $@
%.o: %.c
	$(CC) -c $(CFLAGS) $< -o $*.o

.PHONY: clean
clean:
	rm -rf $(OBJS) $(OUT)

