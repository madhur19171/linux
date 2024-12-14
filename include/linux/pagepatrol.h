/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_PAGEPATROL_H
#define _LINUX_PAGEPATROL_H
#include <linux/types.h>
#include <linux/syscalls.h>

unsigned long pagepatrol_eviction(unsigned long pid, unsigned long type,
				  unsigned long va, unsigned long count);

#endif
