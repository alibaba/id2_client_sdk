include ../../make.rules
include ../../make.settings

CFLAGS  += -I../../include
CFLAGS  += -I../../include/osa
CFLAGS  += -I../../include/itls
CFLAGS  += -I../../include/crypto

#CFLAGS += -DON_DAILY

LDFLAGS += -pie

SRCS    := app_entry.c
SRCS    += src/itls_client.c
SRCS    += src/idtls_client.c

OBJS    := $(patsubst %.cxx,%.o,$(patsubst %.c,%.o,$(SRCS)))

ifeq ($(CONFIG_LS_ID2_ROT_TYPE), MDU)
LIBS    := ../../out/libs/libitls.a
LIBS    += ../../out/libs/libid2_stub.a
LIBS    += ../../out/libs/libicrypt.a
LIBS    += ../../out/libs/libls_hal.a
LIBS    += ../../out/libs/libls_osa.a
else
LIBS    := ../../out/libs/libitls.a
LIBS    += ../../out/libs/libid2.a
LIBS    += ../../out/libs/libkm.a
LIBS    += ../../out/libs/libicrypt.a
LIBS    += ../../out/libs/libls_hal.a
LIBS    += ../../out/libs/libls_osa.a
endif

OUT     := itls_app

$(OUT): $(OBJS) $(LIBS)
	$(CC) $(LDFLAGS) $^ -o $@
%.o: %.c
	$(CC) -c $(CFLAGS) $< -o $*.o

.PHONY: clean
clean:
	rm -rf $(OBJS) $(OUT)

