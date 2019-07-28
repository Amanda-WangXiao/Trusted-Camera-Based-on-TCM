
# Comment/uncomment the following line to enable/disable debugging
#DEBUG = y


ifeq ($(DEBUG),y)
  DEBFLAGS = -O -g -DSCULLP_DEBUG # "-O" is needed to expand inlines
else
  DEBFLAGS = -O2
endif


main-OBJECTS = main.o 
  

#CFLAGS += $(DEBFLAGS) -I$(LDDINC) -I"../misc/"
VPATH = .:../misc

total-OBJECTS = $(main-OBJECTS)  

EXTRA_CFLAGS += -I$(INC) -I$(SELF_PATH) 

TARGET = TestLsm

ifneq ($(KERNELRELEASE),)

TestLsm-objs := $(total-OBJECTS)
obj-m	:= TestLsm.o
# obj-m 制定最后模块的名字？
else

#添加相应的头文件目录
PRIVATE_INC = $(shell pwd)/../include 
__SELF = $(shell pwd)/
KERNELDIR ?= /lib/modules/$(shell uname -r)/build
PWD       := $(shell pwd)

modules:
	$(MAKE) -C $(KERNELDIR) M=$(PWD) INC=$(PRIVATE_INC) SELF_PATH=$(__SELF) modules

# M=$(PWD) : 指定模块编译之后的路径,同时也指定了内核的MAKEFILE第二次再次调用本MAKEFILE;
# INC=$(PRIVATE_INC) ：通知内核的MAKEFILE定义一个INC变量，初始值为$(PRIVATE_INC)，
# PRIVATE_INC不能够直接传给内核MAKEFILE给第二次经过这个文件的时候用；
#

endif


install:
	install -d $(INSTALLDIR)
	install -c $(TARGET).o $(INSTALLDIR)

clean:
	rm -rf *.o $(total-OBJECTS) *~ core .depend .*.cmd *.ko *.mod.c .tmp_versions


depend .depend dep:
	$(CC) $(CFLAGS) -M *.c > .depend

ifeq (.depend,$(wildcard .depend))
include .depend
endif
