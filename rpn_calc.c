/*
 * Copyright (c) 2016 Sugizaki Yukimasa
 * All rights reserved.
 *
 * This software is licensed under a Modified (3-Clause) BSD License.
 * You should have received a copy of this license along with this
 * software. If not, contact the copyright holder above.
 */

#include "rpn_calc.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <errno.h>
#include "diskstorage.h"
#include "strtoint32_ex.h"
#include "error_fl.h"

#define STACK_LEN 0x1000

typedef int32_t stack_elem_t;

static stack_elem_t popnum(int *n, stack_elem_t stack[STACK_LEN]);
static void pushnum(stack_elem_t val, int *n, stack_elem_t stack[STACK_LEN]);

void rpn_calc_init()
{
}

void rpn_calc_finalize()
{
}

int rpn_calc_do(int32_t *retval, const char *str_arg)
{
	int n = 0;
	stack_elem_t stack[STACK_LEN];
	char *str = NULL, *token = NULL, *saveptr = NULL;

	str = strdup(str_arg);
	if (str == NULL) {
		error_fl(__FILE__, __LINE__, "error: strdup: %s\n", strerror(errno));
		return 1;
	}

	token = strtok_r(str, " \t", &saveptr);
	if (token == NULL) {
		error_fl(__FILE__, __LINE__, "error: Empty RPN\n");
		return 1;
	}
	do {
		stack_elem_t a, b, c;
		if (!strcmp(token, "+")) {
			b = popnum(&n, stack);
			a = popnum(&n, stack);
			pushnum(a + b, &n, stack);
		} else if (!strcmp(token, "-")) {
			b = popnum(&n, stack);
			a = popnum(&n, stack);
			pushnum(a - b, &n, stack);
		} else if (!strcmp(token, "*")) {
			b = popnum(&n, stack);
			a = popnum(&n, stack);
			pushnum(a * b, &n, stack);
		} else if (!strcmp(token, "/")) {
			b = popnum(&n, stack);
			a = popnum(&n, stack);
			pushnum(a / b, &n, stack);
		} else if (!strcmp(token, "%")) {
			b = popnum(&n, stack);
			a = popnum(&n, stack);
			pushnum(a % b, &n, stack);
		} else if (!strcmp(token, "<<")) {
			b = popnum(&n, stack);
			a = popnum(&n, stack);
			pushnum(a << b, &n, stack);
		} else if (!strcmp(token, ">>")) {
			b = popnum(&n, stack);
			a = popnum(&n, stack);
			pushnum(a >> b, &n, stack);
		} else if (!strcmp(token, "&")) {
			b = popnum(&n, stack);
			a = popnum(&n, stack);
			pushnum(a & b, &n, stack);
		} else if (!strcmp(token, "|")) {
			b = popnum(&n, stack);
			a = popnum(&n, stack);
			pushnum(a | b, &n, stack);
		} else if (!strcmp(token, "^")) {
			b = popnum(&n, stack);
			a = popnum(&n, stack);
			pushnum(a ^ b, &n, stack);
		} else if (!strcmp(token, "~")) {
			a = popnum(&n, stack);
			pushnum(~a, &n, stack);
		} else if (!strcmp(token, "!")) {
			a = popnum(&n, stack);
			pushnum(!a, &n, stack);
		} else if (!strcmp(token, "!!")) {
			a = popnum(&n, stack);
			pushnum(!!a, &n, stack);
		} else if (!strcmp(token, "==")) {
			b = popnum(&n, stack);
			a = popnum(&n, stack);
			pushnum(a == b, &n, stack);
		} else if (!strcmp(token, "!=")) {
			b = popnum(&n, stack);
			a = popnum(&n, stack);
			pushnum(a != b, &n, stack);
		} else if (!strcmp(token, "<")) {
			b = popnum(&n, stack);
			a = popnum(&n, stack);
			pushnum(a < b, &n, stack);
		} else if (!strcmp(token, ">")) {
			b = popnum(&n, stack);
			a = popnum(&n, stack);
			pushnum(a > b, &n, stack);
		} else if (!strcmp(token, "<=")) {
			b = popnum(&n, stack);
			a = popnum(&n, stack);
			pushnum(a <= b, &n, stack);
		} else if (!strcmp(token, ">=")) {
			b = popnum(&n, stack);
			a = popnum(&n, stack);
			pushnum(a >= b, &n, stack);
		} else if (!strcmp(token, "&&")) {
			b = popnum(&n, stack);
			a = popnum(&n, stack);
			pushnum(a && b, &n, stack);
		} else if (!strcmp(token, "||")) {
			b = popnum(&n, stack);
			a = popnum(&n, stack);
			pushnum(a || b, &n, stack);
		} else if (!strcmp(token, "?")) {
			c = popnum(&n, stack);
			b = popnum(&n, stack);
			a = popnum(&n, stack);
			pushnum(a ? b : c, &n, stack);
		} else {
			int32_t val;
			char *endptr = NULL;

			errno = 0;
			val = strtoint32_ex(token, &endptr);
			if ((val == INT32_MAX) || ((val == 0) && (errno != 0)))
				return 1;
			if (*endptr != '\0') {
				error_fl(__FILE__, __LINE__, "error: Unknown token: %s\n", token);
				return 1;
			}
			pushnum(val, &n, stack);
		}
	} while ((token = strtok_r(NULL, " \t", &saveptr)) != NULL);

	if (n != 1) {
		error_fl(__FILE__, __LINE__, "error: n is not 1 but %d\n", n);
		return 1;
	}
	*retval = (int32_t) popnum(&n, stack);

	free(str);
	return 0;
}

static stack_elem_t popnum(int *n, stack_elem_t stack[STACK_LEN])
{
	return stack[--(*n)];
}

static void pushnum(stack_elem_t val, int *n, stack_elem_t stack[STACK_LEN])
{
	stack[(*n)++] = val;
}
