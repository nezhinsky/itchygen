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

static struct trade_symbol *symbol;

struct rand_interval symbol_len_rand_int[2]; /* len: 3, 4 */

static void generate_symbol_name(struct trade_symbol *symbol)
{
	int len = 3 + rand_index(symbol_len_rand_int, 2);
	int i;

	for (i = 0; i < len; i++)
		symbol->name[i] = rand_char_capital();
	symbol->name[len] = '\0';
	symbol->auto_gen = 1;
}

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

struct rand_interval trade_outcome_int[TRADE_NUM_OUTCOMES];

static void print_rand_trade(int n, unsigned int num_symbols,
	unsigned long trades_rate,
	unsigned long exec_mean_time)
{
	double trade_time, exec_time;
	int si;

	si = rand_int_range(0, num_symbols-1);

	trade_time = rand_exp_time_by_rate((double) trades_rate);
	exec_time = rand_exp_time_by_mean(0.001 * (double) exec_mean_time);

	printf("%d: %s %s inter-trade:%ld.%09ld exec:%ld.%09ld\n",
		n, symbol[si].name,
		trade_outcome_str(rand_index(trade_outcome_int, TRADE_NUM_OUTCOMES)),
		dtime_to_sec(trade_time), dtime_to_nsec(trade_time),
		dtime_to_sec(exec_time), dtime_to_nsec(exec_time));
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
		"-S, --symbols       total number of symbols in use\n"
		"-r, --rate          event rate (evts/sec), suffixes [kKmM] supported)\n"
		"-t, --mean-time     mean time of trade execution or termination (msec)\n"
		"-E, --prob-exec     probability of execution (0%%-100%%)\n"
		"-C, --prob-cancel   probability of cancel (0%%-100%%)\n"
		"-U, --prob-update   probability of update (0%%-100%%)\n"
		"      missing -E, -C, -U inferred by: E + C + U = 100%%\n\n"
		"-R, --rand-seed     set this seed before starting work\n"
		"-d, --debug         produce debug information\n"
		"-V, --version       print version and exit\n"
		"-h, --help          display this help and exit\n",
		itchygen_version, program_name);
	exit(0);
}

static struct option const long_options[] = {
	{"symbols", required_argument, 0, 'S'},
	{"rate", required_argument, 0, 'r'},
	{"mean-time", required_argument, 0, 't'},
	{"prob-exec", required_argument, 0, 'E'},
	{"prob-cancel", required_argument, 0, 'C'},
	{"prob-update", required_argument, 0, 'U'},
	{"rand-seed", required_argument, 0, 'R'},
	{"debug", no_argument, 0, 'd'},
	{"version", no_argument, 0, 'V'},
	{"help", no_argument, 0, 'h'},
	{0, 0, 0, 0},
};

static char *short_options = "S:r:t:E:C:U:R:dVh";

int main(int argc, char **argv)
{
	int ch, longindex, err;
	unsigned int num_symbols = 0;
	unsigned long evt_rate = 0;
	unsigned int mean_trade_time = 0;
	int prob_exec = -1, prob_cancel = -1, prob_update = -1;
	int num_prob_args = 0;
	int debug_mode = 0;
	int use_seed = 0;
	unsigned int rand_seed = 0;
	int mult, suffix, i;

	if (argc == 1)
		usage(EINVAL, "error: no arguments supplied");

	opterr = 0; /* global getopt variable */
	for (;;) {
		ch = getopt_long(argc, argv, short_options, long_options,
			&longindex);
		if (ch < 0)
			break;

		switch (ch) {
		case 'S':
			err = str_to_int_gt(optarg, num_symbols, 0);
			if (err)
				bad_optarg(err, ch, optarg);
			break;
		case 'r': /* events rate */
			mult = 1;

			suffix = optarg[strlen(optarg) - 1];
			if (!isdigit(suffix)) {
				if (suffix == 'k' || suffix == 'K')
					mult = 1000;
				else if (suffix == 'm' || suffix == 'M')
					mult = 1000000;
			}

			err = str_to_int_gt(optarg, evt_rate, 0);
			if (err)
				bad_optarg(err, ch, optarg);
			evt_rate *= mult;
			break;
		case 't': /* mean time to execution. msec */
			err = str_to_int_gt(optarg, mean_trade_time, 0);
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
		case 'U': /* probability of update */
			if (prob_update >= 0)
				usage(E2BIG, "error: -U supplied twice");
			err = str_to_int_range(optarg, prob_update, 0, 100);
			if (err)
				bad_optarg(err, ch, optarg);
			num_prob_args++;
			break;
		case 'R':
			err = str_to_int_gt(optarg, rand_seed, 0);
			if (err)
				bad_optarg(err, ch, optarg);
			use_seed = 1;
			break;
		case 'd':
			debug_mode = 1;
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

	if (!evt_rate)
		usage(EINVAL, "error: event rate not supplied");
	if (!mean_trade_time)
		usage(EINVAL, "error: mean trade time not supplied");
	if (!num_symbols)
		usage(EINVAL, "error: number of symbols not supplied");

	assert(num_prob_args < 4);
	if (num_prob_args == 3) {
		assert(prob_exec >= 0 && prob_cancel >= 0 && prob_update >= 0);
		if (prob_exec + prob_cancel + prob_update != 100)
			usage(EINVAL, "error: 3 probability arguments "
			"(-E,-C,-U) do not sum up to 100%%");
	} else if (num_prob_args == 2) {
		if (prob_exec < 0) {
			assert(prob_cancel >= 0 && prob_update >= 0);
			prob_exec = 100 - (prob_cancel + prob_update);
		} else if (prob_cancel < 0) {
			assert(prob_exec >= 0 && prob_update >= 0);
			prob_cancel = 100 - (prob_exec + prob_update);
		} else if (prob_update < 0) {
			assert(prob_cancel >= 0 && prob_exec >= 0);
			prob_update = 100 - (prob_exec + prob_cancel);
		}
	} else
		usage(EINVAL,
		"error: you should supply at least 2 of 3 probability arguments");

	rand_util_init(use_seed, &rand_seed);

	printf("itchygen args:\n"
		"\tsymbols: %d\n\trate: %ld evt/sec\n\ttime: %d msec\n"
		"\tprobability of exec: %d%% cancel: %d%% update: %d%%\n"
		"\tseed: %d\n"
		"\tdbg: %s\n",
		num_symbols, evt_rate, 
		mean_trade_time, prob_exec, prob_cancel, prob_update,
		rand_seed, debug_mode ? "on" : "off");

	trade_outcome_int[TRADE_EXEC].pcts_total = prob_exec;
	trade_outcome_int[TRADE_CANCEL].pcts_total = prob_cancel;
	trade_outcome_int[TRADE_UPDATE].pcts_total = prob_update;
	rand_interval_init(trade_outcome_int, TRADE_NUM_OUTCOMES);

	symbol = calloc(num_symbols, sizeof(*symbol));
	if (!symbol) {
		printf("failed to alloc %d symbol names\n", num_symbols);
		exit(ENOMEM);
	}

	symbol_len_rand_int[0].pcts_total = 80;
	symbol_len_rand_int[1].pcts_total = 20;
	rand_interval_init(symbol_len_rand_int, 2);

	for (i = 0; i < num_symbols; i++)
		generate_symbol_name(&symbol[i]);
	
	for (i = 0; i < 10; i++)
		print_rand_trade(i, num_symbols, evt_rate, mean_trade_time);

	return err;
}
