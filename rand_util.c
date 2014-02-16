/*
 * rand_util.c
 */

#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <assert.h>
#include <math.h>
#include <time.h>

#include "rand_util.h"

static inline unsigned int rand_seed(void)
{
	return(unsigned int) time(NULL);
}

void rand_util_init(int use_seed, unsigned int *seed)
{
	assert(seed != NULL);
	if (!use_seed)
		*seed = rand_seed();
	srand(*seed);
}

#define RMAX_PERCENT        (RAND_MAX / 100)
#define RMAX_100            (RMAX_PERCENT * 100)

void rand_interval_init(struct rand_interval *ri, size_t n)
{
	int pct_accum = 0;
	size_t i;

	for (i = 0; i < n; i++) {
		ri[i].from_rmax = (ri[i].from_pct = pct_accum) * RMAX_PERCENT;
		pct_accum += ri[i].pcts_total;
		ri[i].to_rmax = (ri[i].to_pct = pct_accum) * RMAX_PERCENT;
	}
	assert(pct_accum == 100);
}

static long int random100(void)
{
	long int rand_num = random();
#if RMAX_100 < RAND_MAX
	if (rand_num > RMAX_100)
		rand_num = RMAX_100;
#endif
	return rand_num;
}

size_t rand_index(struct rand_interval *ri, size_t n)
{
	long int rand_num = random100();
	size_t i;

	for (i = 0; i < n; i++) {
		if (rand_num <= ri[i].to_rmax)
			return i;
	}
	assert(rand_num <= RMAX_100); /* should fail if reached here */
	return n;
}

int rand_int_range(int from, int to)
{
	long int rand_num = random();
	long int rand_interval;

	assert(to > from);
	rand_interval = RAND_MAX / (1 + to - from);

	return from + (int)(rand_num / rand_interval);
}

int rand_char_capital(void)
{
	return rand_int_range('A', 'Z');
}

const double RAND_MAX_FLOAT = 1.0 + (double)RAND_MAX;

double rand_uniform_one(void)
{
	double rand_num = (double) random();
	return(rand_num / RAND_MAX_FLOAT);
}

double rand_exp_time_by_rate(double rate)
{
	return(-log(rand_uniform_one()) / rate);
}

double rand_exp_time_by_mean(double mean)
{
	return(-log(rand_uniform_one()) * mean);
}

unsigned long dtime_to_sec(double dtime)
{
	return (unsigned long) trunc(dtime);
}

unsigned long dtime_to_nsec(double dtime)
{
	return (unsigned long) trunc(1.0e10 * (dtime - trunc(dtime)));
}