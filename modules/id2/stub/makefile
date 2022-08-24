include ../../../make.rules
include ../../../make.settings

CFLAGS  += -I./inc
CFLAGS  += -I../../../include/osa
CFLAGS  += -I../../../include/id2

ifeq ($(CONFIG_LS_ID2_DEBUG), Y)
CFLAGS  += -DCONFIG_ID2_DEBUG
endif

SRCS += src/id2_client.c
SRCS += src/id2_dpm.c
SRCS += src/id2_kpm.c

OBJS := $(patsubst %.cxx,%.o,$(patsubst %.c,%.o,$(SRCS)))

OUT := ../libid2_stub.a

$(OUT): $(OBJS)
	$(AR) -r $(OUT) $(OBJS)
%.o: %.c
	$(CC) -c $(CFLAGS) $< -o $*.o

clean:
	rm -f $(OBJS) .elf $(OUT)
