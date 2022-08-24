include ../make.settings

.PHONY: bin

bin:
	make -C hal_app
	make -C id2_app
	make -C itls_app
clean:
	make clean -C hal_app
	make clean -C id2_app
	make clean -C itls_app
