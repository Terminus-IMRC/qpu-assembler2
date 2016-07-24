/*
 * Copyright (c) 2016 Sugizaki Yukimasa
 * All rights reserved.
 *
 * This software is licensed under a Modified (3-Clause) BSD License.
 * You should have received a copy of this license along with this
 * software. If not, contact the copyright holder above.
 */

#include "error_fl.h"
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>

void error_fl(const char *file, const int line, const char *format, ...)
{
	va_list ap;

	va_start(ap, format);
	error_fl_v(file, line, format, ap);
	va_end(ap);
}

void error_fl_v(const char *file, const int line, const char *format, va_list ap)
{
	int reti;

	reti = fprintf(stderr, "%s:%d: ", file, line);
	if (reti < 0)
		exit(EXIT_FAILURE);
	reti = vfprintf(stderr, format, ap);
	if (reti < 0)
		exit(EXIT_FAILURE);
}
