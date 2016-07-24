/*
 * Copyright (c) 2016 Sugizaki Yukimasa
 * All rights reserved.
 *
 * This software is licensed under a Modified (3-Clause) BSD License.
 * You should have received a copy of this license along with this
 * software. If not, contact the copyright holder above.
 */

#ifndef ERROR_FL_H_INCLUDED_
#define ERROR_FL_H_INCLUDED_

#include <stdarg.h>

	void error_fl(const char *file, const int line, const char *format, ...);
	void error_fl_v(const char *file, const int line, const char *format, va_list ap);

#endif /* ERROR_FL_H_INCLUDED_ */
