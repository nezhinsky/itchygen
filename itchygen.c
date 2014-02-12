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
#include <getopt.h>

#include "itch_proto.h"
#include "rand_util.h"

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
	int auto_gen;
};

enum trade_outcom_type {
	TRADE_EXEC = 0,
	TRADE_CANCEL,
	TRADE_UPDATE,

	TRADE_NUM_OUTCOMES,
};

static const char *trade_outcome_str(enum trade_outcom_type type)
{
	switch (type) {
	case TRADE_EXEC:
		return "EXEC";
	case TRADE_CANCEL:
		return "CANCEL";
	case TRADE_UPDATE:
		return "UPDATE";
	default:
		return "UNKNOWN";
	}
}

struct itchygen_info {
	unsigned int num_symbols;
	struct trade_symbol *symbol;
	unsigned int run_time;
	unsigned long orders_rate;
	unsigned long num_orders;
	int num_rate_args;
	unsigned int time2update;
	int prob_exec;
	int prob_cancel;
	int prob_replace;
	int num_prob_args;
	int debug_mode;
	int verbose_mode;
	unsigned int rand_seed;
	struct rand_interval trade_outcome_int[TRADE_NUM_OUTCOMES];
};

static void print_params(struct itchygen_info *itchigen)
{
	printf("itchygen params:\n"
		"\tsymbols: %d\n\trun time:%d\n\trate: %ld orders/sec\n"
		"\torders num: %ld\n\tmean time to update: %d msec\n"
		"\tprobability of exec: %d%% cancel: %d%% update: %d%%\n"
		"\tdbg: %s, verbose: %s\n\tseed: %d\n\n",
		itchigen->num_symbols, itchigen->run_time,
		itchigen->orders_rate, itchigen->num_orders,
		itchigen->time2update, itchigen->prob_exec,
		itchigen->prob_cancel, itchigen->prob_replace,
		itchigen->debug_mode ? "on" : "off",
		itchigen->verbose_mode ? "on" : "off",
		itchigen->rand_seed);

	if (itchigen->run_time * itchigen->orders_rate != itchigen->num_orders)
		printf("WARNING: time * rate != orders, generation will stop "
		"when either time or orders run out\n\n");
}

static struct rand_interval symbol_len_rand_int[2]; /* len: 3, 4 */

static void generate_symbol_name(struct trade_symbol *symbol)
{
	
	int len = 3 + rand_index(symbol_len_rand_int, 2);
	int i;

	for (i = 0; i < len; i++)
		symbol->name[i] = rand_char_capital();
	symbol->name[len] = '\0';
	symbol->auto_gen = 1;
}

static void print_rand_trade(int n, struct itchygen_info *itchygen)
{
	unsigned int num_symbols = itchygen->num_symbols;
	unsigned long trades_rate = itchygen->orders_rate;
	unsigned long exec_mean_time = itchygen->time2update;
	double trade_time, exec_time;
	int si;

	si = rand_int_range(0, num_symbols - 1);

	trade_time = rand_exp_time_by_rate((double) trades_rate);
	exec_time = rand_exp_time_by_mean(0.001 * (double) exec_mean_time);

	printf("%d: %s %s inter-trade:%ld.%09ld exec:%ld.%09ld\n",
		n, itchygen->symbol[si].name,
		trade_outcome_str(rand_index(itchygen->trade_outcome_int, TRADE_NUM_OUTCOMES)),
		dtime_to_sec(trade_time), dtime_to_nsec(trade_time),
		dtime_to_sec(exec_time), dtime_to_nsec(exec_time));
}

static void generate_orders(struct itchygen_info *itchygen)
{
	struct rand_interval *outcome = itchygen->trade_outcome_int;
	int i;

	outcome[TRADE_EXEC].pcts_total = itchygen->prob_exec;
	outcome[TRADE_CANCEL].pcts_total = itchygen->prob_cancel;
	outcome[TRADE_UPDATE].pcts_total = itchygen->prob_replace;
	rand_interval_init(outcome, TRADE_NUM_OUTCOMES);
	
	for (i = 0; i < itchygen->num_orders; i++)
		print_rand_trade(i, itchygen);
}

static void bad_optarg(int err, int ch, char *optarg)
{
	if (err == ERANGE)
		fprintf(stderr, "-%c argument value '%s' out of range\n", ch, optarg);
	else
		fprintf(stderr, "-%c argument value '%s' invalid\n", ch, optarg);
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

	memset(&itchygen, 0, sizeof(itchygen));

	opterr = 0; /* global getopt variable */
	for (;;) {
		ch = getopt_long(argc, argv, short_options, long_options,
			&longindex);
		if (ch < 0)
			break;

		switch (ch) {
		case 's': /* number of symbols */
			err = str_to_int_gt(optarg, itchygen.num_symbols, 0);
			if (err)
				bad_optarg(err, ch, optarg);
			break;
		case 'r': /* orders rate */
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
		case 't': /* run time */
			err = str_to_int_gt(optarg, run_time, 0);
			if (err)
				bad_optarg(err, ch, optarg);
			num_rate_args++;
			break;
		case 'n': /* total number of orders */
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
		case 'u': /* mean time to next update message, msec */
			err = str_to_int_gt(optarg, itchygen.time2update, 0);
			if (err)
				bad_optarg(err, ch, optarg);
			break;
		case 'E': /* probability of execution */
			if (prob_exec >= 0)
				usage(E2BIG, "error: -E supplied twice");
			err = str_to_int_range(optarg, prob_exec, 0, 100);
			if (err)
				bad_optarg(err, ch, optarg);
			num_prob_args++;
			break;
		case 'C': /* probability of cancel */
			if (prob_cancel >= 0)
				usage(E2BIG, "error: -C supplied twice");
			err = str_to_int_range(optarg, prob_cancel, 0, 100);
			if (err)
				bad_optarg(err, ch, optarg);
			num_prob_args++;
			break;
		case 'R': /* probability of replace */
			if (prob_replace >= 0)
				usage(E2BIG, "error: -U supplied twice");
			err = str_to_int_range(optarg, prob_replace, 0, 100);
			if (err)
				bad_optarg(err, ch, optarg);
			num_prob_args++;
			break;
		case 'S': /* random seed */
			err = str_to_int_gt(optarg, itchygen.rand_seed, 0);
			if (err)
				bad_optarg(err, ch, optarg);
			use_seed = 1;
			break;
		case 'd':
			itchygen.debug_mode = 1;
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
	
	itchygen.prob_exec = prob_exec;
	itchygen.prob_cancel = prob_cancel;
	itchygen.prob_replace = prob_replace;

	rand_util_init(use_seed, &itchygen.rand_seed);

	itchygen.symbol = calloc(itchygen.num_symbols, sizeof(*itchygen.symbol));
	if (!itchygen.symbol) {
		printf("failed to alloc %d symbol names\n", itchygen.num_symbols);
		exit(ENOMEM);
	}

	print_params(&itchygen);

	symbol_len_rand_int[0].pcts_total = 80;
	symbol_len_rand_int[1].pcts_total = 20;
	rand_interval_init(symbol_len_rand_int, 2);
	for (i = 0; i < itchygen.num_symbols; i++)
		generate_symbol_name(&itchygen.symbol[i]);
	
	generate_orders(&itchygen);

	return err;
}
