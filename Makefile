obj-m = xt_FULLCONENAT.o
CFLAGS_xt_FULLCONENAT.o := ${CFLAGS}
KVERSION = $(shell uname -r)
all:
	make -C /lib/modules/$(KVERSION)/build M=$(PWD) modules
clean:
	make -C /lib/modules/$(KVERSION)/build M=$(PWD) clean
