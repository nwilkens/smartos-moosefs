/*
 * Copyright (C) 2025 Jakub Kruszona-Zawadzki, Saglabs SA
 *
 * This file is part of MooseFS.
 *
 * MooseFS is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, version 2 (only).
 *
 * MooseFS is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, see
 * <https://www.gnu.org/licenses/>.
 */

#ifndef _GMTOFFSET_H_
#define _GMTOFFSET_H_

#include <time.h>

/* Returns UTC offset in seconds (positive = east of UTC, same as tm_gmtoff) */
static inline long get_gmtoff(const struct tm *lt) {
#ifdef HAVE_STRUCT_TM_TM_GMTOFF
	return lt->tm_gmtoff;
#elif defined(__sun)
	/* Solaris/illumos: timezone/altzone are seconds WEST of UTC */
	return -(lt->tm_isdst > 0 ? altzone : timezone);
#else
	(void)lt;
	return 0;
#endif
}

#endif
