include ../../make.settings

.PHONY: lib

$(info $(CONFIG_LS_ID2_ROT_TYPE))

lib:
ifeq ($(CONFIG_LS_ID2_ROT_TYPE), SE)
	make -C se
else ifeq ($(CONFIG_LS_ID2_ROT_TYPE), PUF)
	make -C puf
else
	make -C demo
endif

clean:
	make clean -C se
	make clean -C puf
	make clean -C demo
