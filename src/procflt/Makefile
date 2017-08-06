RFS_SRC=$(PWD)
KERN_SRC="/lib/modules/$(shell uname -r)/build"
KERN_VER=$(shell uname -r | cut -c-3)

ifneq "$(KERN_VER)" "2.6"
fail:
	@echo "Just 2.6 kernel is supported for now!";
	@exit
endif

obj-m += procflt.o

procflt.ko: *.c
	$(MAKE) -C $(KERN_SRC) SUBDIRS=$(RFS_SRC) modules

.PHONY: clean
clean:
	$(MAKE) -C $(KERN_SRC) SUBDIRS=$(RFS_SRC) clean
