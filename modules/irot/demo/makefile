include ../../../make.rules

CFLAGS  += -I../../../include/osa
CFLAGS  += -I../../../include/irot
CFLAGS  += -I../../../include/crypto

SRCS    := src/km_demo.c

OBJS := $(patsubst %.cxx,%.o,$(patsubst %.c,%.o,$(SRCS)))

OUT := ../libkm.a

$(OUT): $(OBJS)
	$(AR) rc $(OUT) $(OBJS)
	$(RANLIB) $(OUT)
%.o: %.c
	$(CC) -c $(CFLAGS) $< -o $*.o

clean:
	rm -f $(OBJS) .elf $(OUT)
