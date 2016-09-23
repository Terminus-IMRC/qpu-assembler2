/*
 * Copyright (c) 2016 Sugizaki Yukimasa
 * All rights reserved.
 *
 * This software is licensed under a Modified (3-Clause) BSD License.
 * You should have received a copy of this license along with this
 * software. If not, contact the copyright holder above.
 */

#ifndef QASM2_H_INCLUDED_
#define QASM2_H_INCLUDED_

#include <stdio.h>

	typedef struct {
		int fd;
	} qasm2_assemble_string_t;

	int qasm2_assemble_file(FILE *fp);
	int qasm2_assemble_string(const char *str);
	int qasm2_assemble_string_start(qasm2_assemble_string_t *qtp);
	int qasm2_assemble_string_append(const char *str, qasm2_assemble_string_t *qtp);
	int qasm2_assemble_string_end(qasm2_assemble_string_t *qtp);

#endif /* QASM2_H_INCLUDED_ */
