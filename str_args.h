/* 
 * File:   str_args.h
 * 
 */

#ifndef __STR_ARGS_H_
#define	__STR_ARGS_H_

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * Command line arguments processing
 */

/* convert string to integer, check for validity of the string numeric format
 * and the natural boundaries of the integer value type (first get a 64-bit
 * value and check that it fits the range of the destination integer).
 */
#define str_to_int(str, val, base)                      \
({                                                      \
        int ret = 0;                                    \
        char *ptr;                                      \
        unsigned long long ull_val;                     \
        ull_val = strtoull(str, &ptr, base);            \
        val = (typeof(val)) ull_val;                    \
        if (errno || ptr == str)                        \
                ret = EINVAL;                           \
        else if (val != ull_val)                        \
                ret = ERANGE;                           \
        ret;                                            \
})
/* convert to int and check: strictly greater than */
#define str_to_int_gt(str, val, minv)                   \
({                                                      \
        int ret = str_to_int(str, val, 0);              \
        if (!ret && (val <= minv))                      \
                ret = ERANGE;                           \
        ret;                                            \
})
/* convert and check: greater than or equal  */
#define str_to_int_ge(str, val, minv)                   \
({                                                      \
        int ret = str_to_int(str, val, 0);              \
        if (!ret && (val < minv))                       \
                ret = ERANGE;                           \
        ret;                                            \
})
/* convert and check: strictly less than  */
#define str_to_int_lt(str, val, maxv)                   \
({                                                      \
        int ret = str_to_int(str, val, 0);              \
        if (!ret && (val >= maxv))                      \
                ret = ERANGE;                           \
        ret;                                            \
})
/* convert and check: range, ends inclusive  */
#define str_to_int_range(str, val, minv, maxv, base)    \
({                                                      \
        int ret = str_to_int(str, val, base);           \
        if (!ret && (val < minv || val > maxv))         \
                ret = ERANGE;                           \
        ret;                                            \
})

static inline int bad_optarg(int err, int ch, char *optarg)
{
	if (err == ERANGE)
		printf("-%c argument value '%s' out of range\n", ch, optarg);
	else
		printf("-%c argument value '%s' invalid\n", ch, optarg);
	return err;
}

#ifdef	__cplusplus
}
#endif

#endif	/* __STR_ARGS_H_ */

