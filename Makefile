all:
	make -C ./hal/linux_emulator

clean:
	-rm -rf ./hal/linux_emulaotr/out

.PHYON: all clean
