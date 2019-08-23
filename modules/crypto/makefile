include ../../make.rules

CFLAGS += -I../../include/osa
CFLAGS += -I../../include/hal
CFLAGS += -I../../include/crypto

SRCS := src/api_aes.c
SRCS += src/api_hash.c
SRCS += src/api_hmac.c
SRCS += src/api_init.c
SRCS += src/api_rand.c
SRCS += src/api_rsa.c

OBJS := $(patsubst %.cxx,%.o,$(patsubst %.c,%.o,$(SRCS)))

OUT := libicrypt.a

all: $(OUT) $(OBJS)

$(OUT): $(OBJS)
	$(AR) rc $(OUT) $(OBJS)

%.o: %.c
	@echo $(CC) $(CFLAGS) $<
	$(CC) -c $(CFLAGS) $(CRYPTO_CFLAGS) $< -o $*.o

clean:
	rm -f $(OBJS) $(OUT)
