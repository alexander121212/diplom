obj-m += verificator_kmod.o

verificator_kmod-objs := verificator.o

ccflags-y += -w -g -ggdb -O0
EXTRA_CFLAGS += -I$(PWD)/../include/

all: modules

modules:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) CFLAGS="-I../include/" EXTRA_CFLAGS="$(EXTRA_CFLAGS)" modules

clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean

.PHONY: modules clean
