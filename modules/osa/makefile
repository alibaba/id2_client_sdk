include ../../make.rules

OS_NAME := demo

CFLAGS  += -I../../include/osa

ifeq ($(BUILD_SYS), __LINUX__)
CFLAGS  += -D__DEMO__
else ifeq ($(BUILD_SYS), __ANDROID__)
CFLAGS  += -D__DEMO__
CFLAGS  += -DCONFIG_LS_OS_ANDROID
endif

SRCS    := $(OS_NAME)/src/ls_osa.c

OBJS := $(patsubst %.cxx,%.o,$(patsubst %.c,%.o,$(SRCS)))

OUT := libls_osa.a

$(OUT): $(OBJS)
	$(AR) -r $(OUT) $(OBJS)
%.o: %.c
	$(CC) -c $(CFLAGS) $< -o $*.o

clean:
	rm -f $(OBJS) .elf $(OUT)
