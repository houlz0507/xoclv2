# SPDX-License-Identifier: GPL-2.0
#
# Copyright (C) 2019 Xilinx, Inc. All rights reserved.
#
# Authors: Sonal.Santan@xilinx.com
#

obj-m	+= xmgmt.o
obj-m	+= xmgmt-fmgr.o
obj-m   += xocl-lib.o
#obj-m   += ptest.o

xmgmt-y := xmgmt-drv.o alveo-ctx.o xmgmt-ioctl.o
xmgmt-fmgr-y := xmgmt-fmgr-xclbin.o xmgmt-fmgr-drv.o
xocl-lib-y := xocl-from.o xocl-xmc.o xocl-icap.o xocl-icap-ioctl.o xocl-region.o xocl-core.o
#ptest-y := ptest.o

CONFIG_MODULE_SIG=n
KERNELDIR ?= /lib/modules/$(shell uname -r)/build

PWD	:= $(shell pwd)
ROOT	:= $(dir $(M))
XILINXINCLUDE := -I$(ROOT)/include

ccflags-y += $(XILINXINCLUDE) -DPF=MGMTPF -D__XRT__
ifeq ($(DEBUG),1)
ccflags-y += -DDEBUG
endif

ifeq ($(SYMBOL),1)
ccflags-y += -g
endif

all:
	echo $(PWD)
	$(MAKE) -C $(KERNELDIR) M=$(PWD) modules

clean:
	rm -rf *.o *.o.d *~ core .depend .*.cmd *.ko *.ko.unsigned *.mod.c \
	.tmp_versions *.symvers modules.order *.mod .cache.mk

checkpatch: clean
	$(KERNELDIR)/scripts/checkpatch.pl --max-line-length=120 --color=never --emacs -f --no-tree *.c *.h
