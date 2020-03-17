include ../../make.settings

.PHONY: lib

lib:
ifeq ($(CONFIG_LS_ID2_KM_SE), y)
	make -C se
else
	make -C demo
endif

clean:
	make clean -C se
	make clean -C demo
