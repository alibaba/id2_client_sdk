CC ?= gcc
AR ?= ar
RM := rm
MV := mv

TOP_DIR = ../..
OUT_DIR := ./out

PLATFORM_NAME = linux
#y or n
X64 = n

ifeq ($(X64), y)
	CFLAGS := -O2 -Wall -Wno-unused-function
else
	CFLAGS := -O2 -m32
endif

ifeq ($(X64), y)
	LDFLAGS := -L$(OUT_DIR) -lid2client -lid2pal -L$(TOP_DIR)/external/mbedtls/lib/linux_x86_64 -lmbedcrypto2.4.0 
else
	LDFLAGS := -L$(OUT_DIR) -lid2client -lid2pal -L$(TOP_DIR)/external/mbedtls/lib/linux_x86_32 -lmbedcrypto2.4.0
endif


#定义make名称
ID2_LIB_NAME 	:= libid2client
ID2_PAL_NAME 	:= libid2pal
ID2_DEMO_NAME 	:= id2_demo

#定义最终输出名称
ID2_LIB_TARGET 	= $(OUT_DIR)/$(ID2_LIB_NAME).a
ID2_PAL_TARGET 	= $(OUT_DIR)/$(ID2_PAL_NAME).a
ID2_DEMO_TARGET = $(OUT_DIR)/$(ID2_DEMO_NAME)

#定义编译的源文件
ID2_LIB_SRCS := \
    $(wildcard $(TOP_DIR)/src/algorithm/*.c) \
    $(wildcard $(TOP_DIR)/src/util/*.c) \
    $(wildcard $(TOP_DIR)/src/log/*.c) \
    $(wildcard $(TOP_DIR)/src/core/*.c) \
    $(wildcard ./irot_hal/*.c) \
    $(wildcard ./se_driver/*.c) \

ID2_PAL_SRCS := \
    $(wildcard $(TOP_DIR)/platform/$(PLATFORM_NAME)/*.c) \

ID2_DEMO_SRCS := \
    $(wildcard $(TOP_DIR)/demo/*.c) \

#定义包含的头文件
INCLUDES := \
    -I$(TOP_DIR)/include \
    -I$(TOP_DIR)/platform \
    -I$(TOP_DIR)/src \
    -I$(TOP_DIR)/external/mbedtls/include \
    -I.. \
    -I.

#定义要输出的目标文件
ID2_LIB_OBJS := $(patsubst %.c,%.o,$(ID2_LIB_SRCS))
ID2_PAL_OBJS := $(patsubst %.c,%.o,$(ID2_PAL_SRCS))
ID2_DEMO_OBJS := $(patsubst %.c,%.o,$(ID2_DEMO_SRCS))

all : prepare $(ID2_LIB_TARGET) $(ID2_PAL_TARGET) $(ID2_DEMO_TARGET)

prepare:
	@-mkdir -p $(OUT_DIR)
	@-mkdir -p $(OUT_DIR)/objs

$(ID2_LIB_TARGET) : $(ID2_LIB_OBJS)
	$(AR) -rcs $@ $^
	$(MV) $(ID2_LIB_OBJS) $(OUT_DIR)/objs

$(ID2_PAL_TARGET) : $(ID2_PAL_OBJS)
	$(AR) -rcs $@ $^
	$(MV) $(ID2_PAL_OBJS) $(OUT_DIR)/objs

$(ID2_DEMO_TARGET) : $(ID2_DEMO_OBJS)
	$(CC) $(CFLAGS) $^ $(INCLUDES) $(LDFLAGS) -o $@
	$(MV) $(ID2_DEMO_OBJS) $(OUT_DIR)/objs

%.o : %.c
	$(CC) -c $(CFLAGS) $(INCLUDES) $< -o $@

clean:
	$(RM) -rf $(ID2_DEMO_OBJS)
	$(RM) -rf $(OUT_DIR)

.PHONY:clean
