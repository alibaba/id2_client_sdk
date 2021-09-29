include ./make.settings

OSA_PATH    := modules/osa
HAL_PATH    := modules/hal
ID2_PATH    := modules/id2
IROT_PATH   := modules/irot
ITLS_PATH   := modules/itls
CRYPTO_PATH := modules/crypto
APP_PATH    := app
LIB_PATH    := out/libs
BIN_PATH    := out/bin

all:
	mkdir -p $(LIB_PATH)
	mkdir -p $(BIN_PATH)
	@echo "Building osa..."
	@make -C $(OSA_PATH)
	mv $(OSA_PATH)/libls_osa.a $(LIB_PATH)
	@echo "Building hal..."
	@make -C $(HAL_PATH)
	mv $(HAL_PATH)/libls_hal.a $(LIB_PATH)
	@echo "Building crypto..."
	@make -C $(CRYPTO_PATH)
	mv $(CRYPTO_PATH)/libicrypt.a $(LIB_PATH)
	@echo "Building id2..."
	@make -C $(ID2_PATH)
ifeq ($(CONFIG_LS_ID2_ROT_TYPE), MDU)
	mv $(ID2_PATH)/libid2_stub.a $(LIB_PATH)
else
	mv $(ID2_PATH)/libid2.a $(LIB_PATH)
endif
	@echo "Building irot..."
	@make -C $(IROT_PATH)
	mv $(IROT_PATH)/libkm.a $(LIB_PATH)
	@echo "Building itls..."
	@make -C $(ITLS_PATH)
	mv $(ITLS_PATH)/libitls.a $(LIB_PATH)
	@echo "Building id2 app..."
	@make -C $(APP_PATH)
	mv $(APP_PATH)/hal_app/hal_app $(BIN_PATH)
	mv $(APP_PATH)/id2_app/id2_app $(BIN_PATH)
	mv $(APP_PATH)/itls_app/itls_app $(BIN_PATH)

clean:
	rm -rf out
	@make clean -C $(OSA_PATH)
	@make clean -C $(HAL_PATH)
	@make clean -C $(ID2_PATH)
	@make clean -C $(IROT_PATH)
	@make clean -C $(ITLS_PATH)
	@make clean -C $(CRYPTO_PATH)
	@make clean -C $(APP_PATH)

