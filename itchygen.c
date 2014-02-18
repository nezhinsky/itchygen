/*
 * itchygen - ITCH stream generator
 *
 */

#include <stdlib.h>
#include <stdio.h>
#include <stdarg.h>
#include <errno.h>
#include <assert.h>
#include <ctype.h>
#include <inttypes.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <endian.h>
#include <getopt.h>
#include <sys/queue.h>

#include "itch_proto.h"
#include "rand_util.h"
#include "ulist.h"
#include "pcap.h"

static void usage(int status, char *msg);

static char itchygen_version[] = "0.1";
static char program_name[] = "itchygen";

static void version(void)
{
	printf("%s\n", itchygen_version);
	exit(0);
}

/* convert string to integer, check for validity of the string numeric format
 * and the natural boundaries of the integer value type (first get a 64-bit
 * value and check that it fits the range of the destination integer).
 */
#define str_to_int(str, val)                            \
({                                                      \
        int ret = 0;                                    \
        char *ptr;                                      \
        unsigned long long ull_val;                     \
        ull_val = strtoull(str, &ptr, 0);               \
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
        int ret = str_to_int(str, val);                 \
        if (!ret && (val <= minv))                      \
                ret = ERANGE;                           \
        ret;                                            \
})
/* convert and check: greater than or equal  */
#define str_to_int_ge(str, val, minv)                   \
({                                                      \
        int ret = str_to_int(str, val);                 \
        if (!ret && (val < minv))                       \
                ret = ERANGE;                           \
        ret;                                            \
})
/* convert and check: strictly less than  */
#define str_to_int_lt(str, val, maxv)                   \
({                                                      \
        int ret = str_to_int(str, val);                 \
        if (!ret && (val >= maxv))                      \
                ret = ERANGE;                           \
        ret;                                            \
})
/* convert and check: range, ends inclusive  */
#define str_to_int_range(str, val, minv, maxv)          \
({                                                      \
        int ret = str_to_int(str, val);                 \
        if (!ret && (val < minv || val > maxv))         \
                ret = ERANGE;                           \
        ret;                                            \
})

#define MAX_SYMBOL_NAME	8

struct trade_symbol {
	char name[MAX_SYMBOL_NAME];
	unsigned int min_price;
	unsigned int max_price;
	int auto_gen;
};

enum order_event_type {
	ORDER_ADD = 0,
	ORDER_EXEC,
	ORDER_CANCEL,
	ORDER_REPLACE,

	MODIFY_ORDER_NUM_TYPES,
};

static const char *trade_outcome_str(enum order_event_type type)
{
	switch (type) {
	case ORDER_ADD:
		return "ADD";
	case ORDER_EXEC:
		return "EXEC";
	case ORDER_CANCEL:
		return "CANCEL";
	case ORDER_REPLACE:
		return "REPLACE";
	default:
		return "UNKNOWN";
	}
}

struct order_event {
	struct ulist_node time_node;
	enum order_event_type type;
	struct order_event *prev_event;
	struct trade_symbol *symbol;
	double time;
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
	};
};

struct itchygen_info {
	unsigned int num_symbols;
	struct trade_symbol *symbol;
	unsigned int run_time;
	unsigned long orders_rate;
	unsigned long num_orders;
	int num_rate_args;
	unsigned int time2update;
	int num_prob_args;
	int debug_mode;
	int verbose_mode;
	unsigned int rand_seed;
	unsigned long long cur_ref_num;
	unsigned long long cur_match_num;
	double cur_time;
	struct ulist_head time_list;
	struct rand_interval order_type_prob_int[MODIFY_ORDER_NUM_TYPES];
};

static void print_params(struct itchygen_info *itchigen)
{
	printf("itchygen params:\n"
	       "\tsymbols: %d\n\trun time: %d sec\n\trate: %ld orders/sec\n"
	       "\torders num: %ld\n\tmean time to update: %d msec\n"
	       "\tprobability of exec: %d%% cancel: %d%% replace: %d%%\n"
	       "\tdbg: %s, verbose: %s\n\tseed: %d\n\n",
	       itchigen->num_symbols, itchigen->run_time,
	       itchigen->orders_rate, itchigen->num_orders,
	       itchigen->time2update,
	       itchigen->order_type_prob_int[ORDER_EXEC].pcts_total,
	       itchigen->order_type_prob_int[ORDER_CANCEL].pcts_total,
	       itchigen->order_type_prob_int[ORDER_REPLACE].pcts_total,
	       itchigen->debug_mode ? "on" : "off",
	       itchigen->verbose_mode ? "on" : "off", itchigen->rand_seed);

	if (itchigen->run_time * itchigen->orders_rate != itchigen->num_orders)
		printf("WARNING: time * rate != orders, generation will stop "
		       "when either time or orders run out\n\n");
}

static struct rand_interval symbol_len_rand_int[2];	/* len: 3, 4 */

static void generate_symbol_name(struct trade_symbol *symbol)
{
	int len = 3 + rand_index(symbol_len_rand_int, 2);	/* 3 or 4 */
	int i;

	for (i = 0; i < len; i++)
		symbol->name[i] = rand_char_capital();
	symbol->name[len] = '\0';
	symbol->min_price = rand_int_range(10, 600);
	symbol->max_price = 3 * symbol->min_price;
	symbol->auto_gen = 1;
}

static inline double gen_inter_order_time(struct itchygen_info *itchygen)
{
	return rand_exp_time_by_rate((double)itchygen->orders_rate);
}

static inline double gen_time_to_update(struct itchygen_info *itchygen)
{
	/* mean time-to-update is given in msecs */
	return rand_exp_time_by_mean(0.001 * (double)itchygen->time2update);
}

static void print_order_add(struct itchygen_info *itchygen,
			    struct order_event *order)
{
	printf
	    ("time: %2.9f %s ADD order ref: %lld shares: %d price: %d, req: %s\n",
	     order->time, order->symbol->name, order->ref_num,
	     order->add.shares, order->add.price,
	     order->add.buy ? "BUY" : "SELL");
}

static void print_order_exec(struct itchygen_info *itchygen,
			     struct order_event *event)
{
	struct order_event *order = event->exec.order;
	printf("time: %2.9f %s %s order ref: %lld shares: %d price: %d "
	       "match: %lld, remains: %d\n",
	       event->time, order->symbol->name,
	       trade_outcome_str(event->type),
	       order->ref_num, event->exec.shares, event->exec.price,
	       event->exec.match_num, event->remain_shares);
}

static void print_order_cancel(struct itchygen_info *itchygen,
			       struct order_event *event)
{
	struct order_event *order = event->cancel.order;
	printf("time: %2.9f %s %s order ref: %lld shares: %d, remains: %d\n",
	       event->time, order->symbol->name,
	       trade_outcome_str(event->type),
	       order->ref_num, event->cancel.shares, event->remain_shares);
}

static void print_order_replace(struct itchygen_info *itchygen,
				struct order_event *event)
{
	struct order_event *order = event->replace.order;
	printf
	    ("time: %2.9f %s %s order ref: %lld -> %lld shares: %d price: %d\n",
	     event->time, order->symbol->name, trade_outcome_str(event->type),
	     event->replace.orig_ref_num, event->ref_num, event->replace.shares,
	     event->replace.price);
}

static void order_event_print(struct itchygen_info *itchygen,
			      struct order_event *event, char *prefix)
{
	printf("%s", prefix);
	switch (event->type) {
	case ORDER_ADD:
		print_order_add(itchygen, event);
		break;
	case ORDER_EXEC:
		print_order_exec(itchygen, event);
		break;
	case ORDER_CANCEL:
		print_order_cancel(itchygen, event);
		break;
	case ORDER_REPLACE:
		print_order_replace(itchygen, event);
		break;
	default:
		break;
	}
}

static void order_event_free_back(struct order_event *event)
{
	struct order_event *prev_event;

	do {
		prev_event = event->prev_event;
		free(event);
	} while ((event = prev_event) != NULL);
}

static int pcap_order_add(struct itchygen_info *itchygen,
			  struct order_event *event)
{
	struct itch_msg_add_order_no_mpid add_msg = {
		.msg_type = 'A',
		.timestamp_ns = htobe32(dtime_to_nsec(event->time)),
		.ref_num = htobe64(event->ref_num),
		.buy_sell = event->add.buy ? 'B' : 'S',
		.shares = htobe32(event->add.shares),
		.price = htobe32(event->add.price),
	};
	int i;

	strncpy(add_msg.stock, event->symbol->name, sizeof(add_msg.stock) - 1);
	for (i = strlen(add_msg.stock) + 1; i < sizeof(add_msg.stock); i++)
		add_msg.stock[i] = '\0';

	return pcap_file_add_record(dtime_to_sec(event->time), dtime_to_usec(event->time) + 3,	/* 3 usec delay */
				    &add_msg, sizeof(add_msg));
}

static int pcap_order_cancel(struct itchygen_info *itchygen,
			     struct order_event *event)
{
	struct itch_msg_order_cancel cancel_msg = {
		.msg_type = 'X',
		.timestamp_ns = htobe32(dtime_to_nsec(event->time)),
		.ref_num = htobe64(event->ref_num),
		.shares = htobe32(event->cancel.shares),
	};

	return pcap_file_add_record(dtime_to_sec(event->time), dtime_to_usec(event->time) + 3,	/* 3 usec delay */
				    &cancel_msg, sizeof(cancel_msg));
}

static int pcap_order_exec(struct itchygen_info *itchygen,
			   struct order_event *event)
{
	struct itch_msg_order_exec exec_msg = {
		.msg_type = 'C',
		.timestamp_ns = htobe32(dtime_to_nsec(event->time)),
		.ref_num = htobe64(event->ref_num),
		.shares = htobe32(event->exec.shares),
		.match_num = htobe64(event->exec.match_num),
		.printable = 'Y',
		.price = htobe32(event->exec.price),
	};

	return pcap_file_add_record(dtime_to_sec(event->time), dtime_to_usec(event->time) + 3,	/* 3 usec delay */
				    &exec_msg, sizeof(exec_msg));
}

static int pcap_order_replace(struct itchygen_info *itchygen,
			      struct order_event *event)
{
	struct itch_msg_order_replace replace_msg = {
		.msg_type = 'U',
		.timestamp_ns = htobe32(dtime_to_nsec(event->time)),
		.orig_ref_num = htobe64(event->replace.orig_ref_num),
		.new_ref_num = htobe64(event->ref_num),
		.shares = htobe32(event->replace.shares),
		.price = htobe32(event->replace.price),
	};

	return pcap_file_add_record(dtime_to_sec(event->time),
				    dtime_to_usec(event->time),
				    &replace_msg, sizeof(replace_msg));
}

static void order_event_pcap_msg(struct itchygen_info *itchygen,
				 struct order_event *event)
{
	int err;

	switch (event->type) {
	case ORDER_ADD:
		err = pcap_order_add(itchygen, event);
		break;
	case ORDER_EXEC:
		err = pcap_order_exec(itchygen, event);
		break;
	case ORDER_CANCEL:
		err = pcap_order_cancel(itchygen, event);
		break;
	case ORDER_REPLACE:
		err = pcap_order_replace(itchygen, event);
		break;
	default:
		assert(0);
		break;
	}

	if (err) {
		errno = err;
		printf("failed to write to pcap file, %m\n");
		exit(err);
	}
}

void order_event_submit(struct itchygen_info *itchygen,
			struct order_event *event)
{
	if (itchygen->verbose_mode)
		order_event_print(itchygen, event, ">>> ");

	order_event_pcap_msg(itchygen, event);
}

#define SUBMIT_UNTIL	0
#define ENTIRE_LIST	1

static void submit_time_list(struct itchygen_info *itchygen,
			     int entire_list, double until_time)
{				/* excluded */
	struct order_event *event, *next;

	ulist_for_each_safe(&itchygen->time_list, event, next, time_node) {
		if (!entire_list && event->time >= until_time)
			return;
		ulist_del_from(&itchygen->time_list, &event->time_node);
		if (itchygen->debug_mode)
			printf("timelist: delete %2.9f\n", event->time);
		order_event_submit(itchygen, event);
		if (!event->remain_shares)
			order_event_free_back(event);
	}
}

static void add_to_time_list(struct itchygen_info *itchygen,
			     struct order_event *add_event)
{
	struct order_event *event, *next;

	event = ulist_top(&itchygen->time_list, struct order_event, time_node);
	if (!event || add_event->time < event->time) {
		/* list empty or less than first - add as head */
		ulist_add(&itchygen->time_list, &add_event->time_node);
		if (itchygen->debug_mode)
			printf("timelist: add head %2.9f\n", add_event->time);
		return;
	}

	ulist_for_each_safe(&itchygen->time_list, event, next, time_node) {
		if (&next->time_node == &itchygen->time_list.n) {
			/* end of list - add as tail */
			ulist_add_tail(&itchygen->time_list,
				       &add_event->time_node);
			if (itchygen->debug_mode)
				printf("timelist: add tail %2.9f\n", add_event->time);
			return;
		} else if (add_event->time < next->time) {
			/* place found - add after the current node */
			ulist_insert(&itchygen->time_list,
				     &add_event->time_node, &event->time_node);
			if (itchygen->debug_mode)
				printf("timelist: insert %2.9f between %2.9f - %2.9f\n",
					add_event->time, event->time, next->time);
			return;
		}
	}
	printf("add_event not on the list, or the list is corrupted");
	assert(0);
}

static struct order_event *generate_new_order(struct itchygen_info *itchygen)
{
	struct order_event *order;
	int symbol_index;

	order = malloc(sizeof(*order));
	if (!order)
		return NULL;

	order->type = ORDER_ADD;
	order->prev_event = NULL;
	symbol_index = rand_int_range(0, itchygen->num_symbols - 1);
	order->symbol = &itchygen->symbol[symbol_index];
	order->time = itchygen->cur_time;
	order->ref_num = ++itchygen->cur_ref_num;
	order->add.buy = rand_int_range(0, 1);
	order->add.shares = 10 * rand_int_range(1, 250);
	order->add.price = rand_int_range(order->symbol->min_price,
					  order->symbol->max_price);

	order->remain_shares = order->add.shares;
	order->cur_price = order->add.price;
	return order;
}

static struct order_event *generate_modify_event(struct itchygen_info *itchygen, struct order_event *order,	/* original order */
						 struct order_event *prev_event)
{
	struct order_event *event;

	event = malloc(sizeof(*event));
	if (!event)
		return NULL;

	event->type = rand_index(itchygen->order_type_prob_int,
				 MODIFY_ORDER_NUM_TYPES);
	event->prev_event = prev_event;
	event->symbol = order->symbol;
	event->time = order->time + gen_time_to_update(itchygen);
	event->ref_num = order->ref_num;
	switch (event->type) {
	case ORDER_EXEC:
		event->exec.order = order;
		event->exec.shares = order->remain_shares;	/* ToDo: random partial shares */
		event->exec.price = order->cur_price - rand_int_range(0, 9);
		event->exec.match_num = ++itchygen->cur_match_num;

		event->remain_shares =
		    order->remain_shares - event->exec.shares;
		break;
	case ORDER_CANCEL:
		event->cancel.order = order;
		event->cancel.shares = order->remain_shares;	/* ToDo: random partial shares */

		event->remain_shares =
		    order->remain_shares - event->cancel.shares;
		break;
	case ORDER_REPLACE:
		event->replace.order = order;
		event->replace.shares = 10 * rand_int_range(1, 250);
		event->replace.price = rand_int_range(order->symbol->min_price,
						      order->symbol->max_price);
		event->replace.orig_ref_num = order->ref_num;
		event->ref_num = ++itchygen->cur_ref_num;

		event->remain_shares = event->replace.shares;
		event->cur_price = event->replace.price;
		break;
	default:
		assert(event->type < MODIFY_ORDER_NUM_TYPES);
		break;
	}
	return event;
}

static void generate_orders(struct itchygen_info *itchygen)
{
	struct order_event *order, *event, *prev_event;
	int n_order;

	itchygen->cur_time = 0.0;

	for (n_order = 0; n_order < itchygen->num_orders; n_order++) {
		itchygen->cur_time += gen_inter_order_time(itchygen);
		/* submit all events scheduled until now */
		submit_time_list(itchygen, SUBMIT_UNTIL, itchygen->cur_time);

		order = generate_new_order(itchygen);
		assert(order != NULL);

		add_to_time_list(itchygen, order);
		if (itchygen->debug_mode)
			order_event_print(itchygen, order, "+++ ");

		prev_event = order;
		do {
			event =
			    generate_modify_event(itchygen, order, prev_event);
			assert(event != NULL);

			if (event->type == ORDER_REPLACE)
				order = event;

			add_to_time_list(itchygen, event);
			if (itchygen->debug_mode)
				order_event_print(itchygen, event, "+++ ");

			prev_event = event;
		} while (event->remain_shares);
	}
	/* submit entire list */
	submit_time_list(itchygen, ENTIRE_LIST, 0.0);
}

static void bad_optarg(int err, int ch, char *optarg)
{
	if (err == ERANGE)
		fprintf(stderr, "-%c argument value '%s' out of range\n", ch,
			optarg);
	else
		fprintf(stderr, "-%c argument value '%s' invalid\n", ch,
			optarg);
	usage(err, NULL);
}

static void usage(int status, char *msg)
{
	if (msg)
		fprintf(stderr, "%s\n", msg);
	if (status)
		exit(status);

	printf("ITCH stream generator, version %s\n\n"
	       "Usage: %s [OPTION]\n"
	       "-s, --symbols       total number of [s]ymbols in use\n"
	       "-t, --run-time      total [t]ime for generated orders\n"
	       "-r, --orders-rate   orders [r]ate (1/sec), [kKmM] supported)\n"
	       "-n, --orders-num    total orders [n]umber, [kKmM] supported)\n"
	       "* * * missing -t/-r/-n inferred by: t * r = n\n\n"
	       "-u, --time2update   mean time to order's [u]pdate (msec)\n"
	       "-E, --prob-exec     probability of execution (0%%-100%%)\n"
	       "-C, --prob-cancel   probability of cancel (0%%-100%%)\n"
	       "-R, --prob-replace  probability of replace (0%%-100%%)\n"
	       "* * * missing -E/-C/-R inferred by: E + C + R = 100%%\n\n"
	       "-S, --rand-seed     set this seed before starting work\n"
	       "-d, --debug         produce debug information\n"
	       "-v, --verbose       produce verbose output\n"
	       "-V, --version       print version and exit\n"
	       "-h, --help          display this help and exit\n",
	       itchygen_version, program_name);
	exit(0);
}

static struct option const long_options[] = {
	{"symbols", required_argument, 0, 's'},
	{"run-time", required_argument, 0, 't'},
	{"orders-rate", required_argument, 0, 'r'},
	{"orders-num", required_argument, 0, 'n'},
	{"time2update", required_argument, 0, 'u'},
	{"prob-exec", required_argument, 0, 'E'},
	{"prob-cancel", required_argument, 0, 'C'},
	{"prob-replace", required_argument, 0, 'R'},
	{"rand-seed", required_argument, 0, 'S'},
	{"debug", no_argument, 0, 'd'},
	{"verbose", no_argument, 0, 'v'},
	{"version", no_argument, 0, 'V'},
	{"help", no_argument, 0, 'h'},
	{0, 0, 0, 0},
};

static char *short_options = "s:t:r:n:u:E:C:R:S:dvVh";

int main(int argc, char **argv)
{
	int ch, longindex, err;
	struct itchygen_info itchygen;
	int num_rate_args = 0;
	int num_prob_args = 0;
	unsigned int run_time = 0;
	unsigned long orders_rate = 0;
	unsigned long num_orders = 0;
	int prob_exec = -1;
	int prob_cancel = -1;
	int prob_replace = -1;
	int use_seed = 0;
	int mult, suffix, i;

	if (argc < 2)
		usage(0, NULL);

	memset(&itchygen, 0, sizeof(itchygen));
	opterr = 0;		/* global getopt variable */
	for (;;) {
		ch = getopt_long(argc, argv, short_options, long_options,
				 &longindex);
		if (ch < 0)
			break;

		switch (ch) {
		case 's':	/* number of symbols */
			err = str_to_int_gt(optarg, itchygen.num_symbols, 0);
			if (err)
				bad_optarg(err, ch, optarg);
			break;
		case 'r':	/* orders rate */
			mult = 1;

			suffix = optarg[strlen(optarg) - 1];
			if (!isdigit(suffix)) {
				if (suffix == 'k' || suffix == 'K')
					mult = 1000;
				else if (suffix == 'm' || suffix == 'M')
					mult = 1000000;
			}

			err = str_to_int_gt(optarg, orders_rate, 0);
			if (err)
				bad_optarg(err, ch, optarg);
			orders_rate *= mult;
			num_rate_args++;
			break;
		case 't':	/* run time */
			err = str_to_int_gt(optarg, run_time, 0);
			if (err)
				bad_optarg(err, ch, optarg);
			num_rate_args++;
			break;
		case 'n':	/* total number of orders */
			mult = 1;

			suffix = optarg[strlen(optarg) - 1];
			if (!isdigit(suffix)) {
				if (suffix == 'k' || suffix == 'K')
					mult = 1000;
				else if (suffix == 'm' || suffix == 'M')
					mult = 1000000;
			}

			err = str_to_int_gt(optarg, num_orders, 0);
			if (err)
				bad_optarg(err, ch, optarg);
			num_orders *= mult;
			num_rate_args++;
			break;
		case 'u':	/* mean time to next update message, msec */
			err = str_to_int_gt(optarg, itchygen.time2update, 0);
			if (err)
				bad_optarg(err, ch, optarg);
			break;
		case 'E':	/* probability of execution */
			if (prob_exec >= 0)
				usage(E2BIG, "error: -E supplied twice");
			err = str_to_int_range(optarg, prob_exec, 0, 100);
			if (err)
				bad_optarg(err, ch, optarg);
			num_prob_args++;
			break;
		case 'C':	/* probability of cancel */
			if (prob_cancel >= 0)
				usage(E2BIG, "error: -C supplied twice");
			err = str_to_int_range(optarg, prob_cancel, 0, 100);
			if (err)
				bad_optarg(err, ch, optarg);
			num_prob_args++;
			break;
		case 'R':	/* probability of replace */
			if (prob_replace >= 0)
				usage(E2BIG, "error: -U supplied twice");
			err = str_to_int_range(optarg, prob_replace, 0, 100);
			if (err)
				bad_optarg(err, ch, optarg);
			num_prob_args++;
			break;
		case 'S':	/* random seed */
			err = str_to_int_gt(optarg, itchygen.rand_seed, 0);
			if (err)
				bad_optarg(err, ch, optarg);
			use_seed = 1;
			break;
		case 'd':
			itchygen.debug_mode = 1;
			itchygen.verbose_mode = 1;
			break;
		case 'v':
			itchygen.verbose_mode = 1;
			break;
		case 'V':
			version();
			break;
		case 'h':
			usage(0, NULL);
			break;
		default:
			if (optind == 1)
				optind++;
			printf("don't understand: %s\n", argv[optind - 1]);
			usage(EINVAL, "error: unsupported arguments");
			break;
		}
	}

	if (!itchygen.num_symbols)
		usage(EINVAL, "error: number of symbols not supplied");

	if (!itchygen.time2update)
		usage(EINVAL, "error: mean time to next update not supplied");

	assert(num_rate_args < 4);
	if (num_rate_args == 3)
		assert(run_time && orders_rate && num_orders);
	else if (num_rate_args == 2) {
		if (run_time && num_orders) {
			orders_rate = num_orders / run_time;
			if (!orders_rate)
				orders_rate = 1;
		} else if (run_time && orders_rate) {
			num_orders = run_time * orders_rate;
		} else if (orders_rate && num_orders) {
			run_time = num_orders / orders_rate;
			if (!run_time)
				run_time = 1;
		}
	} else
		usage(EINVAL, "error: you should supply at least "
		      "2 of 3 (-t/-n/-r) arguments");

	itchygen.num_orders = num_orders;
	itchygen.run_time = run_time;
	itchygen.orders_rate = orders_rate;

	assert(num_prob_args < 4);
	if (num_prob_args == 3) {
		assert(prob_exec >= 0 && prob_cancel >= 0 && prob_replace >= 0);
		if (prob_exec + prob_cancel + prob_replace != 100)
			usage(EINVAL, "error: 3 probability arguments "
			      "(-E,-C,-R) do not sum up to 100%%");
	} else if (num_prob_args == 2) {
		if (prob_exec < 0) {
			assert(prob_cancel >= 0 && prob_replace >= 0);
			prob_exec = 100 - (prob_cancel + prob_replace);
		} else if (prob_cancel < 0) {
			assert(prob_exec >= 0 && prob_replace >= 0);
			prob_cancel = 100 - (prob_exec + prob_replace);
		} else if (prob_replace < 0) {
			assert(prob_cancel >= 0 && prob_exec >= 0);
			prob_replace = 100 - (prob_exec + prob_cancel);
		}
	} else
		usage(EINVAL, "error: you should supply at least "
		      "2 of 3 probability (-E/-C/-R) arguments");

	rand_util_init(use_seed, &itchygen.rand_seed);

	symbol_len_rand_int[0].pcts_total = 80;
	symbol_len_rand_int[1].pcts_total = 20;
	rand_interval_init(symbol_len_rand_int, 2);

	itchygen.symbol =
	    calloc(itchygen.num_symbols, sizeof(*itchygen.symbol));
	if (!itchygen.symbol) {
		printf("failed to alloc %d symbol names\n",
		       itchygen.num_symbols);
		exit(ENOMEM);
	}
	for (i = 0; i < itchygen.num_symbols; i++)
		generate_symbol_name(&itchygen.symbol[i]);

	itchygen.order_type_prob_int[ORDER_ADD].pcts_total = 0;
	itchygen.order_type_prob_int[ORDER_EXEC].pcts_total = prob_exec;
	itchygen.order_type_prob_int[ORDER_CANCEL].pcts_total = prob_cancel;
	itchygen.order_type_prob_int[ORDER_REPLACE].pcts_total = prob_replace;
	rand_interval_init(itchygen.order_type_prob_int,
			   MODIFY_ORDER_NUM_TYPES);

	ulist_head_init(&itchygen.time_list);

	err = pcap_file_open("itchygen.pcap");
	if (err) {
		printf("failed to open pcap file, %m\n");
		return err;
	}

	if (itchygen.verbose_mode)
		print_params(&itchygen);
	generate_orders(&itchygen);
	pcap_file_close();

	return err;
}
