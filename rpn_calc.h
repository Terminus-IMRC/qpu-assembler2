/*
 * Copyright (c) 2016 Sugizaki Yukimasa
 * All rights reserved.
 *
 * This software is licensed under a Modified (3-Clause) BSD License.
 * You should have received a copy of this license along with this
 * software. If not, contact the copyright holder above.
 */

#ifndef RPN_CALC_H_INCLUDED_
#define RPN_CALC_H_INCLUDED_

#include <stdint.h>

	void rpn_calc_init();
	void rpn_calc_finalize();
	int rpn_calc_do(int32_t *retval, const char *str_arg);

#endif /* RPN_CALC_H_INCLUDED_ */
