include ../make.settings

.PHONY: bin

bin:
ifeq ($(CONFIG_ID2_MDU), y)
	make -C id2_app
else
	make -C hal_app
	make -C id2_app
	make -C itls_app
endif

clean:
	make clean -C hal_app
	make clean -C id2_app
	make clean -C itls_app
