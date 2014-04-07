/*
 * File: itchygen.h
 * Summary: ITCH stream generation definitions
 * Author: Alexander Nezhinsky (nezhinsky@gmail.com)
 */

#ifndef __ITCHYGEN_H_
#define	__ITCHYGEN_H_

#include "ulist.h"
#include "double_hash.h"

#ifdef	__cplusplus
extern "C" {
#endif

#define likely(x)	__builtin_expect(!!(x), 1)
#define unlikely(x)	__builtin_expect((x), 0)

#define ITCHYGEN_VER_STR	"0.3.1"

void version(void);
void usage(int status, char *msg);

/*
 * ITCH events processing
 */

struct trade_symbol {
	char name[ITCH_SYMBOL_LEN];
	unsigned int min_price;
	unsigned int max_price;
	int auto_gen;
};

enum order_event_type {
	ORDER_ADD = 0,
	ORDER_EXEC,
	ORDER_CANCEL,
	ORDER_REPLACE,
	ORDER_TIMESTAMP,

	MODIFY_ORDER_NUM_TYPES,
};

struct itchygen_stat {
	unsigned long long orders;
	unsigned long long execs;
	unsigned long long cancels;
	unsigned long long replaces;
	unsigned int bucket_min;
	unsigned int bucket_max;
	unsigned int bucket_overflows;
};

struct order_event {
	struct ulist_node time_node;
	enum order_event_type type;
	struct order_event *prev_event;
	struct trade_symbol *symbol;
	double time;
	unsigned int t_sec;
	unsigned int t_nsec;
	unsigned int unit_id;
	unsigned int unit_time;
	unsigned long long seq_num;
	unsigned long long ref_num;
	unsigned int remain_shares;
	unsigned int cur_price;
	union {
		struct {
			unsigned int shares;
			unsigned int price;
			int buy;	/* 1 - buy, 0 - sell */
		} add;
		struct {
			struct order_event *order;
			unsigned int shares;	/* executed */
			unsigned int price;	/* at price */
			unsigned long long match_num;
		} exec;
		struct {
			struct order_event *order;
			unsigned int shares;	/* canceled */
		} cancel;
		struct {
			struct order_event *order;
			unsigned int shares;	/* new quantity */
			unsigned int price;	/* new price */
			unsigned long long orig_ref_num;
		} replace;
		struct {
			unsigned int seconds;
		} timestamp;
	};
};

const char *trade_outcome_str(enum order_event_type type);

void print_order_add(struct order_event *order);
void print_order_exec(struct order_event *event);
void print_order_cancel(struct order_event *event);
void print_order_replace(struct order_event *event);
void print_order_timestamp(struct order_event *event);
void order_event_print(struct order_event *event,
		char *prefix, int print_seq_num);

void print_stats(struct itchygen_stat *s, struct dhash_table *dhash);

/*
 * CRC related definitions
 */

#define CRC_WIDTH 20
size_t get_default_poly(uint32_t *poly, size_t max_poly);

/*
 * Symbols generation and processing
 */

void symbol_name_init(struct trade_symbol *symbol, const char *src_name);

void symbol_name_generator_init(void);
void symbol_name_generate(struct trade_symbol *symbol);

struct symbols_file {
	char *fname;
	FILE *fh;
	unsigned int num_lines;
	unsigned int num_symbols;
	struct trade_symbol *symbol;
};

int read_symbol_file(struct symbols_file * sym, int print_warn);

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

void bad_optarg(int err, int ch, char *optarg);

#ifdef	__cplusplus
}
#endif

#endif	/* __ITCHYGEN_H_ */

