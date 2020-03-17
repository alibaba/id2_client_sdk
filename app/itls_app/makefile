include ../../make.rules
include ../../make.settings

CFLAGS  += -I../../include
CFLAGS  += -I../../include/osa
CFLAGS  += -I../../include/itls
CFLAGS  += -I../../include/crypto

SRCS    := app_entry.c
SRCS    += src/itls_client.c
SRCS    += src/idtls_client.c

OBJS    := $(patsubst %.cxx,%.o,$(patsubst %.c,%.o,$(SRCS)))

LIBS    := ../../out/libs/libitls.a
LIBS    += ../../out/libs/libid2.a
LIBS    += ../../out/libs/libkm.a
LIBS    += ../../out/libs/libicrypt.a
LIBS    += ../../out/libs/libls_hal.a
LIBS    += ../../out/libs/libls_osa.a

OUT     := itls_app

$(OUT): $(OBJS) $(LIBS)
	$(CC) $(LDFLAGS) $^ -o $@
%.o: %.c
	$(CC) -c $(CFLAGS) $< -o $*.o

.PHONY: clean
clean:
	rm -rf $(OBJS) $(OUT)

