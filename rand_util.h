/*
 * File:   rand_util.h
 * Author: alexn
 *
 * Created on February 11, 2014, 7:08 PM
 */

#ifndef RAND_UTIL_H
#define	RAND_UTIL_H

#ifdef	__cplusplus
extern "C" {
#endif

    void rand_util_init(int use_seed, unsigned int *seed);

    struct rand_interval {
        int pcts_total; /* percents allotted for the interval */
        int from_pct;
        long int from_rmax; /* normalized to RAND_MAX_100 */
        int to_pct;
        long int to_rmax; /* normalized to RAND_MAX_100 */
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

#ifdef	__cplusplus
}
#endif

#endif	/* RAND_UTIL_H */