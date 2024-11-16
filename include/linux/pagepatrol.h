/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_PAGEPATROL_H
#define _LINUX_PAGEPATROL_H
#include <linux/types.h>

extern inline void pagepatrol_set_mru(void);
extern inline void pagepatrol_clear_mru(void);
extern inline u64 pagepatrol_is_mru(void);

extern inline void pagepatrol_set_single_list(void);
extern inline void pagepatrol_clear_single_list(void);
extern inline u64 pagepatrol_is_single_list(void);

extern inline void pagepatrol_set_skip_page(void);
extern inline void pagepatrol_clear_skip_page(void);
extern inline u64 pagepatrol_get_skip_page(void);

#endif
