/*
 * File: rand_util.c
 * Summary: generating random numbers from various distributions and
 *          a few helper functions
 *
 * Copyright (c) 2014, Alexander Nezhinsky (nezhinsky@gmail.com)
 * All rights reserved.
 *
 * Licensed under BSD-MIT :
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
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
	return (unsigned int)time(NULL);
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

size_t rand_index(struct rand_interval * ri, size_t n)
{
	long int rand_num = random100();
	size_t i;

	for (i = 0; i < n; i++) {
		if (rand_num <= ri[i].to_rmax)
			return i;
	}
	assert(rand_num <= RMAX_100);	/* should fail if reached here */
	return n;
}

int rand_int_range(int from, int to)
{
	int ret_val = from;
	long int num_intervals = 1 + to - from;
	long int rand_num = random();
	long int rand_interval_sz;
	int interval_index;

	assert(num_intervals > 0);

	rand_interval_sz = RAND_MAX / num_intervals;
	interval_index = rand_num / rand_interval_sz;
	if (interval_index == num_intervals)
		interval_index--;
	ret_val += interval_index;

	return ret_val;
}

int rand_char_capital(void)
{
	return rand_int_range('A', 'Z');
}

unsigned long long rand_uint64(void)
{
	unsigned long long rand64 = (unsigned long long)random();

	return (rand64 << 32) | (unsigned long long)random();
}

unsigned long rand_uint32(void)
{
	return (unsigned long)random();
}

const double RAND_MAX_FLOAT = 1.0 + (double)RAND_MAX;

double rand_uniform_one(void)
{
	double rand_num = (double)random();
	return (rand_num / RAND_MAX_FLOAT);
}

double rand_exp_time_by_rate(double rate)
{
	return (-log(rand_uniform_one()) / rate);
}

double rand_exp_time_by_mean(double mean)
{
	return (-log(rand_uniform_one()) * mean);
}

unsigned long dtime_to_sec(double dtime)
{
	return (unsigned long)trunc(dtime);
}

unsigned long dtime_to_nsec(double dtime)
{
	return (unsigned long)trunc(1.0e9 * (dtime - trunc(dtime)));
}

unsigned long dtime_to_usec(double dtime)
{
	return (unsigned long)trunc(1.0e6 * (dtime - trunc(dtime)));
}
