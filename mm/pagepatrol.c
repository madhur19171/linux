// SPDX-License-Identifier: GPL-2.0+
/*
 * Yo that's a very cool file !
 *
 * Copyright (C) 2024, Gianmaria Rovelli (gianmaria.rovelli@epfl.ch)
 */
#include <linux/pagepatrol.h>
#include <linux/cache.h>

static u64 pagepatrol_mru = 0;
static u64 pagepatrol_single_list = 0;
static u64 pagepatrol_skip_page = 0;

inline void pagepatrol_set_mru(void)
{
	pagepatrol_mru = 1;
}
inline void pagepatrol_clear_mru(void)
{
	pagepatrol_mru = 0;
}
inline u64 pagepatrol_is_mru(void)
{
	return pagepatrol_mru;
}

inline void pagepatrol_set_single_list(void)
{
	pagepatrol_single_list = 1;
}
inline void pagepatrol_clear_single_list(void)
{
	pagepatrol_single_list = 0;
}
inline u64 pagepatrol_is_single_list(void)
{
	return pagepatrol_single_list;
}

inline void pagepatrol_set_skip_page(void)
{
	pagepatrol_skip_page = 1;
}
inline void pagepatrol_clear_skip_page(void)
{
	pagepatrol_skip_page = 0;
}
inline u64 pagepatrol_get_skip_page(void)
{
	return pagepatrol_skip_page;
}

EXPORT_SYMBOL(pagepatrol_is_mru);
EXPORT_SYMBOL(pagepatrol_is_single_list);
EXPORT_SYMBOL(pagepatrol_get_skip_page);
