/*
 * Copyright (c) 2016 Sugizaki Yukimasa
 * All rights reserved.
 *
 * This software is licensed under a Modified (3-Clause) BSD License.
 * You should have received a copy of this license along with this
 * software. If not, contact the copyright holder above.
 */

#ifndef DISKSTORAGE_H_INCLUDED_
#define DISKSTORAGE_H_INCLUDED_

	typedef struct {
		int fd;
		int len_max;
		int n;
	} diskstorage_t;

	void diskstorage_init(diskstorage_t *dstp);
	void diskstorage_finalize(diskstorage_t *dstp);
	void diskstorage_append(const void *data, int len, diskstorage_t *dstp);
	void diskstorage_seek(const int n, diskstorage_t *dstp);
	int diskstorage_read_next(void *data, int maxlen, diskstorage_t *dstp);
	int diskstorage_n(diskstorage_t *dstp);
	int diskstorage_len_max(diskstorage_t *dstp);

#endif /* _DISKSTORAGE_H_INCLUDED_ */
