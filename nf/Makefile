obj-m := lowrider.o
KDIR := /lib/modules/$(shell uname -r)/build
PWD := $(shell pwd)

default: lowrider.c
	$(MAKE) -C $(KDIR) SUBDIRS=$(PWD) modules

lowrider.ko: default

install: lowrider.ko
	insmod lowrider.ko

uninstall:
	rmmod lowrider

clean:
	$(MAKE) -C $(KDIR) SUBDIRS=$(PWD) clean
