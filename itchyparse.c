/*
 * File: itchyparse.c
 * Summary: a parser ot UDP ITCH stream capture files in PCAP format,
 *          generated by itchygen stream generator
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
#include <stdarg.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <assert.h>
#include <ctype.h>
#define __STDC_FORMAT_MACROS	/* for PRIu64 etc. */
#include <inttypes.h>
#include <endian.h>
#include <getopt.h>
#include <time.h>

#include "itch_proto.h"
#include "itchygen.h"
#include "pcap.h"
#include "double_hash.h"

struct itchyparse_info {
	char *pcap_fname;
	struct symbols_file subscription;
	int no_hash_del;
	int debug_mode;
	int verbose_mode;
	unsigned int num_poly;
	uint32_t poly[MAX_POLY];
	struct dhash_table dhash;
	struct dhash_table subscr_dhash;
	struct dhash_table unsubscr_dhash;
	struct itchygen_stat stat;
	unsigned int unsubscr_orders;
	unsigned int subscr_orders;
	unsigned long long expect_first_seq;
	unsigned long long edit_first_seq;
	unsigned long long edit_start_sec;
};

static char program_name[] = "itchyparse";

void usage(int status, char *msg)
{
	if (msg)
		fprintf(stderr, "%s\n", msg);
	if (status)
		exit(status);

	printf("ITCH PCAP file parser, version %s\n\n"
	       "Usage: %s [OPTION]\n"
	       "-s, --symbol-file   file with ticker [s]ymbols to use\n"
	       "-f, --file          output PCAP file name\n"
	       "-x, --expect        first sequence num to expect\n"
	       "-1, --edit-first    re-write seq. numbers, start with first\n"
	       "-t, --edit-time     re-write time stamps, start with this\n"
	       "-Q, --seq           sequential ref.nums, default: random\n"
	       "    --no-hash-del   refnums not deleted from hash on expiration\n"
	       "-d, --debug         produce debug information\n"
	       "-v, --verbose       produce verbose output\n"
	       "-V, --version       print version and exit\n"
	       "-h, --help          display this help and exit\n",
	       ITCHYGEN_VER_STR, program_name);
	exit(0);
}

static struct option const long_options[] = {
	{"symbol-file", required_argument, 0, 's'},
	{"file", required_argument, 0, 'f'},
	{"expect", required_argument, 0, 'x'},
	{"edit-first", required_argument, 0, '1'},
	{"time", required_argument, 0, 't'},
	{"no-hash-del", no_argument, 0, '0'},
	{"debug", no_argument, 0, 'd'},
	{"verbose", no_argument, 0, 'v'},
	{"version", no_argument, 0, 'V'},
	{"help", no_argument, 0, 'h'},
	{0, 0, 0, 0},
};

static char *short_options = "s:f:x:1:t:0dvVh";

static inline uint32_t name4_to_u32(char *name)
{
	uint32_t int_val;

	int_val = (uint32_t)name[0];
	int_val |= ((uint32_t)name[1]) << 8;
	int_val |= ((uint32_t)name[2]) << 16;
	int_val |= ((uint32_t)name[3]) << 24;

	return int_val;
}

static uint32_t symbol_name_to_u32(struct trade_symbol *symbol)
{
	return name4_to_u32(symbol->name);
}

int main(int argc, char **argv)
{
	struct itchyparse_info itchyparse;
	unsigned long long cur_seq_num = 0;
	unsigned long long seq_errors = 0;
	unsigned long long rec_seq_num, first_seq_num, last_seq_num;
	unsigned int illegal_types = 0;
	unsigned long long new_seq_num;
	int ch, longindex, err, first = 1, edit_recs = 0;

	if (argc < 2)
		usage(0, NULL);

	memset(&itchyparse, 0, sizeof(itchyparse));
	itchyparse.num_poly = get_default_poly(itchyparse.poly, MAX_POLY);

	opterr = 0;		/* global getopt variable */
	for (;;) {
		ch = getopt_long(argc, argv, short_options,
				 long_options, &longindex);
		if (ch < 0)
			break;

		switch (ch) {
		case 's':
			itchyparse.subscription.fname = strdup(optarg);
			if (!itchyparse.subscription.fname) {
				printf("failed to alloc mem for sym file name\n");
				exit(ENOMEM);
			}
			break;
		case 'f':
			itchyparse.pcap_fname = strdup(optarg);
			if (!itchyparse.pcap_fname) {
				printf("failed to alloc mem for pcap file name\n");
				exit(ENOMEM);
			}
			break;
		case 'x':
			err = str_to_int_ge(optarg, itchyparse.expect_first_seq, 0);
			if (err)
				bad_optarg(err, ch, optarg);
			break;
		case '1':
			err = str_to_int_ge(optarg, itchyparse.edit_first_seq, 0);
			if (err)
				bad_optarg(err, ch, optarg);
			break;
		case 't':
			err = str_to_int_ge(optarg, itchyparse.edit_start_sec, 0);
			if (err)
				bad_optarg(err, ch, optarg);
			break;
		case '0':
			itchyparse.no_hash_del = 1;
			break;
		case 'd':
			itchyparse.debug_mode = 1;
			itchyparse.verbose_mode = 1;
			break;
		case 'v':
			itchyparse.verbose_mode = 1;
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

	if (!itchyparse.pcap_fname)
		usage(EINVAL, "error: pcap file name not supplied");

	if (itchyparse.subscription.fname) {
		int i;

		err = dhash_init(&itchyparse.subscr_dhash, CRC_WIDTH,
				 itchyparse.poly, 1);
		assert(!err);

		err = dhash_init(&itchyparse.unsubscr_dhash, CRC_WIDTH,
				 itchyparse.poly, 1);
		assert(!err);

		err = read_symbol_file(&itchyparse.subscription, 1);
		if (err) {
			printf("failed to read symbols file\n");
			exit(err);
		}

		for (i = 0; i < itchyparse.subscription.num_symbols; i++) {
			err = dhash_add(&itchyparse.subscr_dhash,
				symbol_name_to_u32(&itchyparse.subscription.symbol[i]));
			assert(!err || err == EEXIST);
		}
	}

//	time_list_init(&itchyparse);

	err = dhash_init(&itchyparse.dhash, CRC_WIDTH,
			 itchyparse.poly, itchyparse.num_poly);
	if (err) {
		errno = err;
		printf("failed to init hash table, %m\n");
		return err;
	}

	err = pcap_file_open_rd(itchyparse.pcap_fname);
	if (err) {
		errno = err;
		printf("failed to open pcap file for read, %m\n");
		return errno;
	}

	itchyparse.no_hash_del = 1;

	for (;;) {
		struct itch_packet itch_pkt;
		size_t pkt_len;
		uint32_t refn32, name32;
		int err;

		err = pcap_file_read_record(&itch_pkt, sizeof(itch_pkt), &pkt_len);
		if (unlikely(err)) {
			if (err != ENOENT) {
				printf("failed to read from pcap file, %m\n");
				exit(err);
			}
			break;
		}

		rec_seq_num = be64toh(itch_pkt.mold.seq_num);
		if (unlikely(first)) {
			first = 0;
			first_seq_num = rec_seq_num;
			cur_seq_num = itchyparse.expect_first_seq;
			if (itchyparse.edit_first_seq != first_seq_num) {
				new_seq_num = itchyparse.edit_first_seq;
				edit_recs = 1;
			}
		}
		if (rec_seq_num != cur_seq_num) {
			printf("seq.err. expected:%llu recvd:%llu\n",
				cur_seq_num, rec_seq_num);
			if (edit_recs) {
				if (rec_seq_num > cur_seq_num)
					new_seq_num += (rec_seq_num - cur_seq_num);
				else
					new_seq_num -= (cur_seq_num - rec_seq_num);
			}
			cur_seq_num = rec_seq_num; /* update expected */
			seq_errors ++;
		}
		cur_seq_num ++;

		switch (itch_pkt.msg.common.msg_type) {
		case MSG_TYPE_ADD_ORDER_NO_MPID:
			itchyparse.stat.orders ++;
			refn32 = (uint32_t)be64toh(itch_pkt.msg.common.ref_num);
			err = dhash_add(&itchyparse.dhash, refn32);
			if (unlikely(err)) {
				if (err == EEXIST)
					assert(itchyparse.no_hash_del);
				else if (err == ENOMEM)
					itchyparse.stat.bucket_overflows++;
				else {
					assert(err == ENOSPC);
					printf("hash table full\n");
					exit(1);
				}
			}

			name32 = name4_to_u32(itch_pkt.msg.order.stock);
			err = dhash_find(&itchyparse.subscr_dhash, name32);
			if (!err) /* this order is for a subscribed symbol */
				itchyparse.subscr_orders ++;
			else {
				assert(err == ENOENT);
				itchyparse.unsubscr_orders ++;
				/* added now or already present */
				err = dhash_add(&itchyparse.unsubscr_dhash, name32);
				assert(!err || err == EEXIST);
			}
			break;
		case MSG_TYPE_ORDER_EXECUTED:
			itchyparse.stat.execs ++;
			break;
		case MSG_TYPE_ORDER_CANCEL:
			itchyparse.stat.cancels ++;
			break;
		case MSG_TYPE_ORDER_REPLACE:
			itchyparse.stat.replaces ++;
			break;
		case MSG_TYPE_TIMESTAMP:
			break;
		default:
			illegal_types ++;
			break;
		}

		if (edit_recs) {
			itch_pkt.mold.seq_num = htobe64(new_seq_num);
			new_seq_num ++;
			err = pcap_file_replace_last_record(&itch_pkt, pkt_len);
			if (unlikely(err)) {
				printf("failed to re-write pcap file, %m\n");
				exit(err);
			}
		}
	}
	last_seq_num = rec_seq_num;

	pcap_file_close();

//	print_params(&itchyparse);
	print_stats(&itchyparse.stat, &itchyparse.dhash);
	printf("\tseq.nums: %llu - %llu, seq.errors: %llu, "
		"illegal msg.types: %u\n",
		first_seq_num, last_seq_num, seq_errors, illegal_types);

	assert(itchyparse.subscr_orders + itchyparse.unsubscr_orders ==
		itchyparse.stat.orders);

	if (itchyparse.subscription.fname && itchyparse.stat.orders) {
		printf("\torders:%llu, subscription symbols: %u, "
			"subscribed: %u (%3.1f%%), unsubscribed: %u (%3.1f%%)\n",
			itchyparse.stat.orders,
			itchyparse.subscription.num_symbols,
			itchyparse.subscr_orders,
			(itchyparse.subscr_orders * 100.0) /
			itchyparse.stat.orders,
			itchyparse.unsubscr_orders,
			(itchyparse.unsubscr_orders * 100.0) /
			itchyparse.stat.orders);
	}

	dhash_cleanup(&itchyparse.dhash);
	if (itchyparse.pcap_fname)
		free(itchyparse.pcap_fname);
	if (itchyparse.subscription.fname)
		free(itchyparse.subscription.fname);

	return 0;
}
