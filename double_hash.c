#include <stdlib.h>
#include <stdio.h>
#include <time.h>
#include <assert.h>
#include <string.h>
#include <errno.h>

#include "crc.h"
#include "double_hash.h"

static inline int
dhash_bucket_val_find(struct dhash_bucket *bucket, uint32_t val)
{
	int i;
	for (i = 0; i < bucket->num; i++) {
		if (bucket->val[i] == val)
			return i;
	}
	return -1;
}

int dhash_add(struct dhash_table *dhash, uint32_t val)
{
	struct dhash_bucket *bucket, *min_bucket = NULL;
	crc_t crc_val;
	int p;

	if (!dhash->num_free)
		return ENOSPC;

	for (p = 0; p < dhash->num_poly; p++) {
		crc_val = calc_crc_uint32_table(&dhash->crc_poly[p], val);
		bucket = &dhash->bucket[crc_val];
		if (dhash_bucket_val_find(bucket, val) >= 0)
			return EEXIST;
		if (!min_bucket || bucket->num < min_bucket->num)
			min_bucket = bucket;
	}

	if (min_bucket->num < NUM_BUCKET_VALS) {
		min_bucket->val[min_bucket->num++] = val;
		if (min_bucket->num > dhash->bucket_abs_max)
			dhash->bucket_abs_max = min_bucket->num;
		dhash->num_free--;
		return 0;
	} else {
		printf("bucket overflows, currently %d vals\n",
		       min_bucket->num);
		return ENOMEM;
	}
}

int dhash_find(struct dhash_table *dhash, uint32_t val)
{
	struct dhash_bucket *bucket;
	crc_t crc_val;
	int p, i;

	for (p = 0; p < dhash->num_poly; p++) {
		crc_val = calc_crc_uint32_table(&dhash->crc_poly[p], val);
		bucket = &dhash->bucket[crc_val];
		i = dhash_bucket_val_find(bucket, val);
		if (i >= 0)
			return 0;
	}
	return ENOENT;
}

int dhash_del(struct dhash_table *dhash, uint32_t val)
{
	struct dhash_bucket *bucket;
	crc_t crc_val;
	int p, i, j;

	for (p = 0; p < dhash->num_poly; p++) {
		crc_val = calc_crc_uint32_table(&dhash->crc_poly[p], val);
		bucket = &dhash->bucket[crc_val];
		i = dhash_bucket_val_find(bucket, val);
		if (i >= 0) {
			for (j = i + 1; j < bucket->num; j++)
				bucket->val[j - 1] = bucket->val[j];
			bucket->num--;
			dhash->num_free++;
			return 0;
		}
	}
	return ENOENT;
}

int
dhash_init(struct dhash_table *dhash, size_t crc_width,
	   const uint32_t * poly, int npoly)
{
	int i;

	assert(npoly <= MAX_POLY);

	dhash->num_poly = npoly;
	for (i = 0; i < npoly; i++)
		crc_init(&dhash->crc_poly[i], poly[i], crc_width);

	dhash->crc_width = crc_width;
	dhash->num_crc_vals = 1 << crc_width;
	dhash->num_free = dhash->num_crc_vals * NUM_BUCKET_VALS;

	dhash->bucket = malloc(sizeof(*dhash->bucket) * dhash->num_crc_vals);
	if (!dhash->bucket) {
		printf("failed to alloc values table\n");
		return ENOMEM;
	}
	return 0;
}

void dhash_reset(struct dhash_table *dhash)
{
	memset(dhash->bucket, 0, sizeof(*dhash->bucket) * dhash->num_crc_vals);
}

void dhash_cleanup(struct dhash_table *dhash)
{
	free(dhash->bucket);
	memset(dhash, 0, sizeof(*dhash));
}

void dhash_stat(struct dhash_table *dhash, struct dhash_stat *s)
{
	int i;

	s->num_entries = (dhash->num_crc_vals * NUM_BUCKET_VALS) -
	    dhash->num_free;
	s->bucket_abs_max = dhash->bucket_abs_max;

	for (i = 0; i <= NUM_BUCKET_VALS; i++)	/* initial reset */
		s->bucket_num[i] = 0;
	for (i = 0; i < dhash->num_crc_vals; i++) {	/* count values */
		assert(dhash->bucket[i].num <= NUM_BUCKET_VALS);
		s->bucket_num[dhash->bucket[i].num]++;
	}
}
