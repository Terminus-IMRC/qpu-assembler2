/*
 * Copyright (c) 2016 Sugizaki Yukimasa
 * All rights reserved.
 *
 * This software is licensed under a Modified (3-Clause) BSD License.
 * You should have received a copy of this license along with this
 * software. If not, contact the copyright holder above.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <errno.h>
#include "diskstorage.h"
#include "error_fl.h"

/*
 * +-------------------+---------+-------------------+---------+-----+
 * | length of data #1 | data #1 | length of data #2 | data #2 | ... |
 * +-------------------+---------+-------------------+---------+-----+
 */

void diskstorage_init(diskstorage_t *dstp)
{
	int fd;
	int umask_set, umask_orig;
	char filename[] = "tmp-ds-XXXXXX";
	int ret;

	umask_set = S_IXUSR | S_IRWXG | S_IRWXO;
	umask_orig = umask(umask_set);
	fd = mkstemp(filename);
	umask(umask_orig);
	if (fd == -1) {
		error_fl(__FILE__, __LINE__, "mkstemp: %s\n", strerror(errno));
		exit(EXIT_FAILURE);
	}

	ret = unlink(filename);
	if (ret == -1) {
		error_fl(__FILE__, __LINE__, "unlink: %s\n", strerror(errno));
		exit(EXIT_FAILURE);
	}

	ret = ftruncate(fd, 0);
	if (ret == -1) {
		error_fl(__FILE__, __LINE__, "ftruncate: %s\n", strerror(errno));
		exit(EXIT_FAILURE);
	}

	dstp->fd = fd;
	dstp->len_max = 0;
}

void diskstorage_finalize(diskstorage_t *dstp)
{
	int fd = dstp->fd;
	int ret;

	ret = close(fd);
	if (ret == -1) {
		error_fl(__FILE__, __LINE__, "close: %s\n", strerror(errno));
		exit(EXIT_FAILURE);
	}

	dstp->fd = -1;
	dstp->len_max = 0;
}

void diskstorage_append(const void *data, int len, diskstorage_t *dstp)
{
	int fd = dstp->fd;
	int len_max = dstp->len_max;
	off_t reto;
	ssize_t retss;

	if (len == 0) {
		error_fl(__FILE__, __LINE__, "len == 0\n");
		exit(EXIT_FAILURE);
	}

	reto = lseek(fd, 0, SEEK_END);
	if (reto == (off_t) -1) {
		error_fl(__FILE__, __LINE__, "lseek: %s\n", strerror(errno));
		exit(EXIT_FAILURE);
	}

	retss = write(fd, &len, sizeof(len));
	if (retss == -1) {
		error_fl(__FILE__, __LINE__, "write: %s\n", strerror(errno));
		exit(EXIT_FAILURE);
	}
	if (retss != sizeof(len)) {
		error_fl(__FILE__, __LINE__, "short write\n");
		exit(EXIT_FAILURE);
	}

	retss = write(fd, data, len);
	if (retss == -1) {
		error_fl(__FILE__, __LINE__, "write: %s\n", strerror(errno));
		exit(EXIT_FAILURE);
	}
	if (retss != len) {
		error_fl(__FILE__, __LINE__, "short write\n");
		exit(EXIT_FAILURE);
	}

	if (len > len_max) {
		len_max = len;
		dstp->len_max = len_max;
	}

	dstp->n ++;
}

void diskstorage_seek(const int n, diskstorage_t *dstp)
{
	int i;
	int fd = dstp->fd;
	int len;
	int len_max = dstp->len_max;
	ssize_t retss;
	off_t reto;

	reto = lseek(fd, 0, SEEK_SET);
	if (reto == (off_t) -1) {
		error_fl(__FILE__, __LINE__, "lseek: %s\n", strerror(errno));
		exit(EXIT_FAILURE);
	}

	for (i = 0; i < n; i ++) {
		retss = read(fd, &len, sizeof(len));
		if (retss == -1) {
			error_fl(__FILE__, __LINE__, "read: %s\n", strerror(errno));
			exit(EXIT_FAILURE);
		}
		if (retss != sizeof(len)) {
			error_fl(__FILE__, __LINE__, "short read\n");
			exit(EXIT_FAILURE);
		}

		if (len > len_max) {
			error_fl(__FILE__, __LINE__, "len exceeds len_max\n");
			exit(EXIT_FAILURE);
		}

		reto = lseek(fd, len, SEEK_CUR);
		if (reto == -1) {
			error_fl(__FILE__, __LINE__, "lseek: %s\n", strerror(errno));
			exit(EXIT_FAILURE);
		}
	}
}

int diskstorage_read_next(void *data, int maxlen, diskstorage_t *dstp)
{
	int fd = dstp->fd;
	int len;
	ssize_t retss;

	retss = read(fd, &len, sizeof(len));
	if (retss == -1) {
		error_fl(__FILE__, __LINE__, "read: %s\n", strerror(errno));
		exit(EXIT_FAILURE);
	}
	if (retss != sizeof(len)) {
		error_fl(__FILE__, __LINE__, "short read\n");
		exit(EXIT_FAILURE);
	}

	if (len > maxlen) {
		error_fl(__FILE__, __LINE__, "len exceeds maxlen\n");
		exit(EXIT_FAILURE);
	}

	retss = read(fd, data, len);
	if (retss == -1) {
		error_fl(__FILE__, __LINE__, "read: %s\n", strerror(errno));
		exit(EXIT_FAILURE);
	}
	if (retss != len) {
		error_fl(__FILE__, __LINE__, "short read\n");
		exit(EXIT_FAILURE);
	}

	return len;
}

int diskstorage_n(diskstorage_t *dstp)
{
	return dstp->n;
}

int diskstorage_len_max(diskstorage_t *dstp)
{
	return dstp->len_max;
}
