/*
 * Copyright (c) 2016 Sugizaki Yukimasa
 * All rights reserved.
 *
 * This software is licensed under a Modified (3-Clause) BSD License.
 * You should have received a copy of this license along with this
 * software. If not, contact the copyright holder above.
 */

#include "strtoint32_ex.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <ctype.h>
#include <limits.h>
#include <errno.h>
#include "error_fl.h"

/* This can process 0b. */
int32_t strtoint32_ex(const char *str, char **endptr)
{
	int i, j, str_len, base, sign = 0;
	long int num;
	char *str_prop = NULL;

	/* Skip spaces. */
	for (; isspace(*str) && (*str) != '\0'; str++)
		;

	switch (*str) {
		case '-':
			sign = -1;
			str ++;
			break;
		case '+':
			str ++;
			/* No break. */
		default:
			sign = +1;
			break;
	}

	if (!strncmp(str, "0b", 2)) {
		base = 2;
		str += 2;
	} else
		base = 0;

	str_len = strlen(str);
	str_prop = malloc((str_len + 1) * sizeof(char));
	if (str_prop == NULL) {
		error_fl(__FILE__, __LINE__, "error: Failed to allocate str_prop\n");
		return INT32_MAX;
	}

	for (i = 0, j = 0; i < str_len + 1; i ++)
		if (str[i] != '_')
			str_prop[j++] = str[i];

	errno = 0;
	num = strtol(str_prop, endptr, base);
	if ((errno == ERANGE && num == LONG_MAX) || (errno != 0 && num == 0)) {
		error_fl(__FILE__, __LINE__, "strtoul: %s\n", strerror(errno));
		return (num == LONG_MAX) ? INT32_MAX : 0;
	}

	if (endptr != NULL) {
		for (i = 0, j = 0; i < str_len + 1; i ++) {
			if (j == (*endptr - str_prop)) {
				*endptr = (char*) &(str[i]);
				break;
			}
			if (str[i] != '_')
				j ++;
		}
	}

	free(str_prop);

	return (int32_t) (num * sign);
}
