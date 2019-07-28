#ifndef __SCHEME_H__
#define __SCHEME_H__

#include <linux/version.h>
#include <linux/uaccess.h>
#include <asm/byteorder.h>
#include <linux/module.h>
#include <linux/types.h>
#include <linux/fs.h>
#include <linux/errno.h>
#include <linux/vmalloc.h>
#include <linux/mm.h>
#include <linux/cdev.h>
#include <linux/wait.h>
#include <asm/io.h>
// -- #include <asm/system.h>
#include <asm/uaccess.h>
#include <asm/atomic.h>
#include <linux/spinlock.h>
#include <linux/time.h>
#include <linux/slab.h>

#include <linux/version.h>
#include <linux/types.h>
#include <linux/kernel.h>
#include <linux/string.h>
#include <linux/mm.h>
#include <linux/utime.h>
#include <linux/file.h>
#if LINUX_VERSION_CODE <= KERNEL_VERSION(2, 6, 38)
#include <linux/smp_lock.h>
#endif
 
#include <linux/init.h>
#include <linux/slab.h>
#include <linux/highmem.h>
#include <linux/poll.h>
#include <linux/binfmts.h>
#include <linux/delay.h>
#include <linux/sched.h>
#include <linux/dcache.h>
#include <linux/mount.h>
#include <linux/net.h>
#include <linux/inet.h>
#include <linux/in.h>
#include <linux/in6.h>
#include <linux/un.h>
#endif

