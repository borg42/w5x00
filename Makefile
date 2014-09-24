
obj-m := w5x00.o
w5x00-objs := module.o netdrv.o  dev.o queue.o

#KDIR := /usr/src/linux-panda
KDIR := /home/olaf/ee/red-brick/image/source/red-brick-linux-sunxi
PWD := $(shell pwd)
	

default :
	$(MAKE) -C $(KDIR) SUBDIRS=$(PWD) modules

clean :
	rm -rf *.o
	rm -rf *.ko
	rm -rf *.mod.*
	rm -rf .w5x00*
	rm -rf Module.symvers
	rm -rf modules.order
	rm -rf .tmp_versions
