ifneq ($(KERNELRELEASE),)

obj-m += icenet.o

else

ifndef LINUXSRC
$(error Please set the LINUXSRC environment variable to the path of your Linux source)
endif


KMAKE=make -C $(LINUXSRC) ARCH=riscv CROSS_COMPILE=riscv64-unknown-linux-gnu- M=$(PWD)

icenet.ko: icenet.c
	$(KMAKE)

clean:
	$(KMAKE) clean

endif
