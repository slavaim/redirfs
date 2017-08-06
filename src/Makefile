ifneq ($(KERNELRELEASE),)

# kbuild part of makefile
include Kbuild

else

default: all

BLD_DIR ?= $(PWD)/build

# linux kernel module targets

MDIR := $(BLD_DIR)/modules/
KDIR ?= /lib/modules/`uname -r`/build

# module include directories

MINC := -I$(PWD)/redirfs

modules:
	$(MAKE) -C $(KDIR) M=$(PWD) EXTRA_CFLAGS=$(MINC) modules

modules_install: modules
	mkdir -p $(MDIR)
	$(MAKE) -C $(KDIR) M=$(PWD) EXTRA_CFLAGS=$(MINC) INSTALL_MOD_PATH=$(MDIR) modules_install

modules_uninstall:
	rm -rf $(MDIR)

modules_clean:
	$(MAKE) -C $(KDIR) M=$(PWD) EXTRA_CFLAGS=$(MINC) clean

# user-space library and utility targets

INCLUDE := -I../librfsctl -I../libavfltctl -I../libav
LIB_DIR ?= $(BLD_DIR)/lib
BIN_DIR ?= $(BLD_DIR)/bin
HDR_DIR ?= $(BLD_DIR)/include

export INCLUDE LIB_DIR BIN_DIR HDR_DIR BLD_DIR

# libraries

libs:
	$(MAKE) -C librfsctl
	$(MAKE) -C libavfltctl
	$(MAKE) -C libav

libs_install:
	$(MAKE) -C librfsctl install
	$(MAKE) -C libavfltctl install
	$(MAKE) -C libav install

libs_uninstall:
	$(MAKE) -C librfsctl uninstall
	$(MAKE) -C libavfltctl uninstall
	$(MAKE) -C libav uninstall

libs_clean:
	$(MAKE) -C librfsctl clean
	$(MAKE) -C libavfltctl clean
	$(MAKE) -C libav clean

# utilities

utils: libs_install
	$(MAKE) -C rfsctl
	$(MAKE) -C avfltctl
	$(MAKE) -C avtest

utils_install: utils
	$(MAKE) -C rfsctl install
	$(MAKE) -C avfltctl install
	$(MAKE) -C avtest install

utils_uninstall:
	$(MAKE) -C rfsctl uninstall
	$(MAKE) -C avfltctl uninstall
	$(MAKE) -C avtest uninstall

utils_clean:
	$(MAKE) -C rfsctl clean
	$(MAKE) -C avfltctl clean
	$(MAKE) -C avtest clean

# cscope targets

cscope:
	find . -type f -iregex '^.*\.\(c\|h\)' > cscope.files
	cscope -b

cscope_clean:
	rm -rf cscope*

# general targes

all: libs utils modules cscope

clean: libs_clean utils_clean modules_clean cscope_clean

install: libs_install utils_install modules_install cscope_clean

uninstall: libs_uninstall utils_uninstall modules_uninstall cscope_clean

endif

