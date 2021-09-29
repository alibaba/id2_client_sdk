include ../../make.settings

.PHONY: lib

lib:
ifeq ($(CONFIG_LS_ID2_ROT_TYPE), MDU)
	make -C stub
else
	make -C lib
endif

clean:
	make clean -C stub
	make clean -C lib
