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
#include "str_args.h"

struct itchyparse_info {
	char *pcap_fname;
	struct symbols_file subscription;
	int no_hash_del;
	int debug_mode;
	int verbose_mode;
	unsigned int num_poly;
	uint32_t poly[MAX_POLY];
	struct dhash_table refn_dhash;
	struct dhash_table subscr_name_dhash;
	struct dhash_table subscr_refn_dhash;
	struct itchygen_stat stat;
	unsigned long long unsubscr_orders;
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
	       "-f, --file          PCAP file name\n"
	       "-L, --list-file     file with list of subscription symbols\n"
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
	{"file", required_argument, 0, 'f'},
	{"list-file", required_argument, 0, 'L'},
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

static char *short_options = "f:L:x:1:t:0dvVh";

static void ep_printf(struct endpoint_addr *ep)
{
	char ip_str[32];
	printf("[%02x:%02x:%02x:%02x:%02x:%02x] %s:%d",
		ep->mac[0], ep->mac[1], ep->mac[2],
		ep->mac[3], ep->mac[4], ep->mac[5],
		inet_ntop(AF_INET, &ep->ip_addr, ip_str, 32),
		(uint32_t) ep->port);
}

int main(int argc, char **argv)
{
	struct itchyparse_info itchyparse;
	unsigned long long cur_seq_num = 0;
	unsigned long long seq_errors = 0;
	unsigned long long rec_seq_num = 0;
	unsigned long long first_seq_num = 0;
	unsigned long long last_seq_num = 0;
	unsigned long long new_seq_num = 0;
	unsigned int illegal_types = 0;
	int first = 1, edit_recs = 0;
	struct endpoint_addr dst_ep, src_ep;
	struct endpoint_addr first_dst_ep, first_src_ep;
	int ch, longindex, err;

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
		case 'L':
			itchyparse.subscription.fname = strdup(optarg);
			if (!itchyparse.subscription.fname) {
				printf("failed to alloc mem for symbols list file name\n");
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
				usage(bad_optarg(err, ch, optarg), NULL);
			break;
		case '1':
			err = str_to_int_ge(optarg, itchyparse.edit_first_seq, 0);
			if (err)
				usage(bad_optarg(err, ch, optarg), NULL);
			edit_recs = 1;
			break;
		case 't':
			err = str_to_int_ge(optarg, itchyparse.edit_start_sec, 0);
			if (err)
				usage(bad_optarg(err, ch, optarg), NULL);
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

		err = read_symbol_file(&itchyparse.subscription, 1);
		if (err) {
			printf("failed to read symbols file\n");
			exit(err);
		}

		err = dhash_init(&itchyparse.subscr_name_dhash, CRC_WIDTH,
				 itchyparse.poly, 1);
		assert(!err);

		err = dhash_init(&itchyparse.subscr_refn_dhash, CRC_WIDTH,
				 itchyparse.poly, itchyparse.num_poly);
		assert(!err);

		for (i = 0; i < itchyparse.subscription.num_symbols; i++) {
			err = dhash_add(&itchyparse.subscr_name_dhash,
				symbol_name_to_u32(&itchyparse.subscription.symbol[i]));
			assert(!err); // || err == EEXIST);
		}
	}

//	time_list_init(&itchyparse);

	err = dhash_init(&itchyparse.refn_dhash, CRC_WIDTH,
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
		int src_changed, dst_changed;
		int err;

		err = pcap_file_read_record(&itch_pkt, sizeof(itch_pkt),
					    &pkt_len, &dst_ep, &src_ep);
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

			memcpy(&first_src_ep, &src_ep, sizeof(src_ep));
			ep_printf(&first_src_ep);
			printf(" -> ");
			memcpy(&first_dst_ep, &dst_ep, sizeof(dst_ep));
			ep_printf(&first_dst_ep);
			printf("\n");

			first_seq_num = rec_seq_num;
			cur_seq_num = itchyparse.expect_first_seq;
			if (edit_recs) {
				if (itchyparse.edit_first_seq != first_seq_num)
					new_seq_num = itchyparse.edit_first_seq;
				else /* no need to edit */
					edit_recs = 0;
			}
		}

		src_changed = 0;
		dst_changed = 0;
		if (memcmp(&first_src_ep, &src_ep, sizeof(src_ep))) {
			printf("new src: ");
			ep_printf(&src_ep);
			src_changed = 1;
		}
		if (memcmp(&first_dst_ep, &dst_ep, sizeof(dst_ep))) {
			printf("%snew dst: ", src_changed ? " -> " : "");
			ep_printf(&dst_ep);
			dst_changed = 1;
		}
		if (dst_changed || src_changed)
			printf("\n");

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

		refn32 = (uint32_t)be64toh(itch_pkt.msg.common.ref_num);

		switch (itch_pkt.msg.common.msg_type) {
		case MSG_TYPE_ADD_ORDER_NO_MPID:
			itchyparse.stat.orders ++;

			err = dhash_add(&itchyparse.refn_dhash, refn32);
			if (unlikely(err)) {
				if (err == EEXIST)
					assert(itchyparse.no_hash_del);
				else if (err == ENOMEM)
					itchyparse.stat.bucket_overflows++;
				else {
					assert(err == ENOSPC);
					printf("refn hash table full\n");
					exit(1);
				}
			}

			if (!itchyparse.subscription.fname) {
				itchyparse.unsubscr_orders ++;
				break;
			}

			name32 = name4_to_u32(itch_pkt.msg.order.stock);
			err = dhash_find(&itchyparse.subscr_name_dhash, name32);
			if (!err) {/* this order is for a subscribed symbol */
				itchyparse.stat.subscr_orders ++;
				if (itchyparse.debug_mode) {
					printf("%s refn:%u\n",
					       itch_pkt.msg.order.stock,
					       refn32);
				}
				/* store this order's ref num */
				err = dhash_add(&itchyparse.subscr_refn_dhash,
						refn32);
				assert(!err || err == EEXIST);
			} else {
				assert(err == ENOENT);
				itchyparse.unsubscr_orders ++;
			}
			break;
		case MSG_TYPE_ORDER_EXECUTED:
			itchyparse.stat.execs ++;
			err = dhash_find(&itchyparse.subscr_refn_dhash, refn32);
			if (!err)
				itchyparse.stat.subscr_execs ++;
			else
				assert(err == ENOENT);
			break;
		case MSG_TYPE_ORDER_CANCEL:
			itchyparse.stat.cancels ++;
			err = dhash_find(&itchyparse.subscr_refn_dhash, refn32);
			if (!err)
				itchyparse.stat.subscr_cancels ++;
			else
				assert(err == ENOENT);
			break;
		case MSG_TYPE_ORDER_REPLACE:
			itchyparse.stat.replaces ++;
			err = dhash_find(&itchyparse.subscr_refn_dhash, refn32);
			if (!err)
				itchyparse.stat.subscr_replaces ++;
			else
				assert(err == ENOENT);
			break;
		case MSG_TYPE_TIMESTAMP:
			itchyparse.stat.timestamps ++;
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
	print_stats(&itchyparse.stat, &itchyparse.refn_dhash);
	printf("\tseq.nums: %llu - %llu, seq.errors: %llu, "
		"illegal msg.types: %u\n",
		first_seq_num, last_seq_num, seq_errors, illegal_types);

	assert(itchyparse.stat.subscr_orders + itchyparse.unsubscr_orders ==
		itchyparse.stat.orders);

	if (itchyparse.subscription.fname && itchyparse.stat.orders) {
		printf("\tsubscription symbols: %u\n"
			"\torders: %llu, subscribed: %llu (%3.1f%%), "
			"unsubscribed: %llu (%3.1f%%)\n"
			"\texecs: %llu, subscribed: %llu\n"
			"\tcancels: %llu, subscribed: %llu\n"
			"\treplaces: %llu, subscribed: %llu\n",
			itchyparse.subscription.num_symbols,
			itchyparse.stat.orders, itchyparse.stat.subscr_orders,
			(itchyparse.stat.subscr_orders * 100.0) /
			itchyparse.stat.orders,
			itchyparse.unsubscr_orders,
			(itchyparse.unsubscr_orders * 100.0) /
			itchyparse.stat.orders,
			itchyparse.stat.execs, itchyparse.stat.subscr_execs,
			itchyparse.stat.cancels, itchyparse.stat.subscr_cancels,
			itchyparse.stat.replaces, itchyparse.stat.subscr_replaces);
	}

	dhash_cleanup(&itchyparse.refn_dhash);
	if (itchyparse.pcap_fname)
		free(itchyparse.pcap_fname);
	if (itchyparse.subscription.fname) {
		free(itchyparse.subscription.fname);
		dhash_cleanup(&itchyparse.subscr_refn_dhash);
		dhash_cleanup(&itchyparse.subscr_name_dhash);
	}

	return 0;
}
