/*
 * Copyright (c) 2016 Sugizaki Yukimasa
 * All rights reserved.
 *
 * This software is licensed under a Modified (3-Clause) BSD License.
 * You should have received a copy of this license along with this
 * software. If not, contact the copyright holder above.
 */

#include "qasm2.h"
#include "qasm2_anal.h"
#include <stdio.h>

int main()
{
	return qasm2_assemble_file(stdin);
}
