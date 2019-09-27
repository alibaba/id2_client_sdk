include ../../make.rules
include ../../make.settings

CFLAGS  += -I./inc
CFLAGS  += -I../../include/osa
CFLAGS  += -I../../include/id2

SRCS    := app_entry.c
SRCS    += src/cJSON.c
SRCS    += src/id2_client_mesg.c
SRCS    += src/id2_client_test.c

OBJS    := $(patsubst %.cxx,%.o,$(patsubst %.c,%.o,$(SRCS)))

ifeq ($(CONFIG_ID2_MDU), y)
LIBS    := ../../out/libs/libid2.a
LIBS    += ../../out/libs/libls_osa.a
else
LIBS    := ../../out/libs/libid2.a
LIBS    += ../../out/libs/libkm.a
LIBS    += ../../out/libs/libicrypt.a
LIBS    += ../../out/libs/libls_hal.a
LIBS    += ../../out/libs/libls_osa.a
endif

OUT     := id2_app

$(OUT): $(OBJS) $(LIBS)
	$(CC) $(LDFLAGS) $^ -o $@
%.o: %.c
	$(CC) -c $(CFLAGS) $< -o $*.o

.PHONY: clean
clean:
	rm -rf $(OBJS) $(OUT)

