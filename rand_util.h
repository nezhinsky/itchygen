/*
 * File: rand_util.h
 * Summary: generating random numbers from various distributions and
 *          a few helper functions
 * Author: Alexander Nezhinsky (nezhinsky@gmail.com)
 */

#ifndef RAND_UTIL_H
#define	RAND_UTIL_H

void rand_util_init(int use_seed, unsigned int *seed);

struct rand_interval {
	int pcts_total;		/* percents allotted for the interval */
	int from_pct;
	long int from_rmax;	/* normalized to RAND_MAX_100 */
	int to_pct;
	long int to_rmax;	/* normalized to RAND_MAX_100 */
};

void rand_interval_init(struct rand_interval *ri, size_t n);
size_t rand_index(struct rand_interval *ri, size_t n);

int rand_int_range(int from, int to);
int rand_char_capital(void);

double rand_uniform_one(void);

double rand_exp_time_by_rate(double rate);
double rand_exp_time_by_mean(double mean);

unsigned long dtime_to_sec(double dtime);
unsigned long dtime_to_nsec(double dtime);
unsigned long dtime_to_usec(double dtime);

#endif				/* RAND_UTIL_H */
