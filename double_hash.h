/*
 * File:   double_hash.h
 * Author: Alexander Nezhinsky
 *
 * Created on March 29, 2014, 8:54 AM
 */

#ifndef DOUBLE_HASH_H
#define	DOUBLE_HASH_H

#include "crc.h"

#ifdef	__cplusplus
extern "C" {
#endif

#define NUM_BUCKET_VALS	6
#define MAX_POLY	3

	struct dhash_bucket {
		uint32_t num;
		uint32_t val[NUM_BUCKET_VALS];
	};

	struct dhast_stat {
		uint32_t num_entries;
		uint32_t bucket_min;
		uint32_t bucket_max;
	};

	struct dhash_table {
		size_t num_poly;
		struct crc_poly crc_poly[MAX_POLY];
		size_t crc_width;
		size_t num_crc_vals;
		size_t num_free;
		size_t bucket_min;
		size_t bucket_max;
		size_t bucket_abs_max;
		struct dhash_bucket *bucket;
	};

	int dhash_init(struct dhash_table *dhash, size_t crc_width,
		       const uint32_t * poly, int npoly);
/* release memory, clear all counters */
	void dhash_cleanup(struct dhash_table *dhash);

/* returns 0 on success,
 * EEXIST when already in hash
 * ENOMEM on bucket overflow
 * ENOSPC when entire table full */
	int dhash_add(struct dhash_table *dhash, uint32_t val);

/* returns 0 on success,
 * ENOENT when not in hash */
	int dhash_find(struct dhash_table *dhash, uint32_t val);

/* returns 0 on success,
 * ENOENT when not in hash */
	int dhash_del(struct dhash_table *dhash, uint32_t val);

/* clear all hash entries */
	void dhash_reset(struct dhash_table *dhash);

/* get statistics */
	struct dhash_stat {
		uint32_t num_entries;	/* current */
		uint32_t bucket_abs_max;	/* max since reset */
		uint32_t bucket_num[NUM_BUCKET_VALS + 1];
	};

	void dhash_stat(struct dhash_table *dhash, struct dhash_stat *s);

#ifdef	__cplusplus
}
#endif
#endif				/* DOUBLE_HASH_H */
