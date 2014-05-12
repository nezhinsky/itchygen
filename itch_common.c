/*
 * File: itch_common.c
 * Summary: common code for ITCH stream generation and parsing
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
#include "rand_util.h"
#include "ulist.h"
#include "pcap.h"
#include "double_hash.h"

void version(void)
{
	printf("%s\n", ITCHYGEN_VER_STR);
	exit(0);
}

const uint32_t def_poly[2] = {
	0x182671,
	0x11522b
};

size_t get_default_poly(uint32_t *poly, size_t max_poly)
{
	size_t i, num_poly = sizeof(def_poly) / sizeof(def_poly[0]);
	assert(poly);

	if (num_poly > max_poly)
		num_poly = max_poly;

	for (i = 0; i < num_poly; i++)
		poly[i] = def_poly[i];
	return num_poly;
}

const char *trade_outcome_str(enum order_event_type type)
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
	case ORDER_TIMESTAMP:
		return "TIMESTAMP";
	default:
		return "UNKNOWN";
	}
}

void print_order_add(struct order_event *order)
{
	printf
	    ("time: %u.%09u %s ADD order ref: %lld shares: %d price: %d, req: %s\n",
	     order->t_sec, order->t_nsec,
	     order->symbol->name, order->ref_num,
	     order->add.shares, order->add.price,
	     order->add.buy ? "BUY" : "SELL");
}

void print_order_exec(struct order_event *event)
{
	struct order_event *order = event->exec.order;
	printf("time: %u.%09u %s %s order ref: %lld shares: %d price: %d "
	       "match: %lld, remains: %d\n",
	       event->t_sec, event->t_nsec, order->symbol->name,
	       trade_outcome_str(event->type),
	       order->ref_num, event->exec.shares, event->exec.price,
	       event->exec.match_num, event->remain_shares);
}

void print_order_cancel(struct order_event *event)
{
	struct order_event *order = event->cancel.order;
	printf("time: %u.%09u %s %s order ref: %lld shares: %d, remains: %d\n",
	       event->t_sec, event->t_nsec, order->symbol->name,
	       trade_outcome_str(event->type),
	       order->ref_num, event->cancel.shares, event->remain_shares);
}

void print_order_replace(struct order_event *event)
{
	struct order_event *order = event->replace.order;
	printf
	    ("time: %u.%09u %s %s order ref: %lld -> %lld shares: %d price: %d\n",
	     event->t_sec, event->t_nsec,
	     order->symbol->name, trade_outcome_str(event->type),
	     event->replace.orig_ref_num, event->ref_num, event->replace.shares,
	     event->replace.price);
}

void print_order_timestamp(struct order_event *event)
{
	printf("time: %u.%09u timestamp: %d sec\n",
	       event->t_sec, event->t_nsec, event->timestamp.seconds);
}

void order_event_print(struct order_event *event,
		char *prefix, int print_seq_num)
{
	if (!print_seq_num)
		printf("%s ", prefix);
	else
		printf("%s %lld ", prefix, event->seq_num);

	switch (event->type) {
	case ORDER_ADD:
		print_order_add(event);
		break;
	case ORDER_EXEC:
		print_order_exec(event);
		break;
	case ORDER_CANCEL:
		print_order_cancel(event);
		break;
	case ORDER_REPLACE:
		print_order_replace(event);
		break;
	case ORDER_TIMESTAMP:
		print_order_timestamp(event);
		break;
	default:
		break;
	}
}

static char equality_char(unsigned long long x, unsigned long long y)
{
	if (x == y)
		return '=';
	else if (x > y)
		return '>';
	else
		return '<';
}

void print_stats(struct itchygen_stat *s, struct dhash_table *dhash)
{
	unsigned long long total_execs = s->execs +
				s->cancels + s->replaces;
	unsigned long long total_subscr_execs = s->subscr_execs +
				s->subscr_cancels + s->subscr_replaces;
	struct dhash_stat ds;
	int i;

	dhash_stat(dhash, &ds);
	printf(	"\tpackets: %llu timestamps: %llu\n",
		(s->orders + total_execs + s->timestamps),
		s->timestamps);
	printf( "\ttotal orders: %llu %c exec: %llu (%3.1f%%) + "
		"cancel: %llu (%3.1f%%) + replace: %llu (%3.1f%%)\n",
		s->orders, equality_char(s->orders, total_execs),
		s->execs, (s->execs * 100.0) / total_execs,
		s->cancels, (s->cancels * 100.0) / total_execs,
		s->replaces, (s->replaces * 100.0) / total_execs);
	printf(	"\tsubscribed orders: %llu (%3.1f%%) %c exec: %llu + "
		"cancel: %llu + replace: %llu\n",
		s->subscr_orders,
		(s->subscr_orders * 100.0) / s->orders,
		equality_char(s->subscr_orders, total_subscr_execs),
		s->subscr_execs, s->subscr_cancels, s->subscr_replaces);
	printf("\thash table entries: %u, bucket all-times-max: %u, overflows: %u\n",
	       ds.num_entries, ds.bucket_abs_max, s->bucket_overflows);
	printf("\tbucket ");
	for (i = 0; i <= NUM_BUCKET_VALS; i++)
		printf("num[%d]:%d ", i, ds.bucket_num[i]);
	printf("\n\n");
}

static struct rand_interval symbol_len_rand_int[2];	/* len: 3, 4 */

void symbol_name_init(struct trade_symbol *symbol, const char *src_name)
{
	memset(symbol->name, 0, sizeof(symbol->name));
	if (src_name) {
		strncpy(symbol->name, src_name, sizeof(symbol->name) - 1);
		symbol->auto_gen = 0;
	} else {
		int len = 3 + rand_index(symbol_len_rand_int, 2);	/* 3 or 4 */
		int i;

		for (i = 0; i < len; i++)
			symbol->name[i] = rand_char_capital();
		symbol->auto_gen = 1;
	}
	symbol->min_price = rand_int_range(10, 600);
	symbol->max_price = 3 * symbol->min_price;
}

void symbol_name_generate(struct trade_symbol *symbol)
{
	symbol_name_init(symbol, NULL);
}

void symbol_name_generator_init(void)
{
	symbol_len_rand_int[0].pcts_total = 80;
	symbol_len_rand_int[1].pcts_total = 20;
	rand_interval_init(symbol_len_rand_int, 2);
}

static void load_symbol_file(struct symbols_file * sym, int print_warn)
{
	int i = 0, ln = 0;
	char *lf, *comma;
	char line[4096];

	while (fgets(line, sizeof(line), sym->fh)) {
		sym->num_lines++;
	}
	fseek(sym->fh, 0, SEEK_SET);

	sym->symbol = calloc(sym->num_lines, sizeof(*sym->symbol));
	if (!sym->symbol) {
		printf("failed to alloc %d symbol names\n", sym->num_lines);
		exit(ENOMEM);
	}

	while (fgets(line, sizeof(line), sym->fh)) {
		ln++;

		lf = strchr(line, '\n');
		if (lf)
			*lf = '\0';
		lf = strchr(line, '\r');
		if (lf)
			*lf = '\0';

		comma = strchr(line, ',');
		if (likely(comma != NULL)) {
			*comma = '\0';
			if (strlen(line) < 5)
				symbol_name_init(&sym->symbol[i++], line);
			else if (print_warn)
				printf("%s +%d symbol longer than "
					"4 chars: [%s]\n",
					sym->fname, ln, line);
		} else if (print_warn)
			printf("%s +%d unexpected format: [%s]\n",
				sym->fname, ln, line);
	}
	sym->num_symbols = i;
	assert(sym->num_lines == ln);
}

int read_symbol_file(struct symbols_file * sym, int print_warn)
{
	assert(sym->fname);
	sym->fh = fopen(sym->fname, "r");
	if (!sym->fh) {
		perror(sym->fname);
		return errno;
	}
	load_symbol_file(sym, 1);
	fclose(sym->fh);
	return 0;
}

uint32_t name4_to_u32(char *name)
{
	uint32_t int_val;

	int_val = (uint32_t)name[0];
	int_val |= ((uint32_t)name[1]) << 8;
	int_val |= ((uint32_t)name[2]) << 16;
	int_val |= ((uint32_t)name[3]) << 24;

	return int_val;
}

uint32_t symbol_name_to_u32(struct trade_symbol *symbol)
{
	return name4_to_u32(symbol->name);
}

void init_symbol_file_hash(struct symbols_file * sym)
{
	uint32_t poly[2];
	uint32_t name32, i;
	int err;

	i = get_default_poly(poly, 2);
	assert(i == 2);

	err = dhash_init(&sym->dhash, CRC_WIDTH, poly, 2);
	assert(!err);

	for (i = 0; i < sym->num_symbols; i++) {
		name32 = name4_to_u32(sym->symbol[i].name);
		dhash_add(&sym->dhash, name32);
	}
}

int is_in_symbol_file(struct symbols_file * sym, char *name)
{
	uint32_t name32 = name4_to_u32(name);
	int err;

	err = dhash_find(&sym->dhash, name32);
	if (!err) /* found in hash */
		return 1;
	else {
		assert(err == ENOENT);
		return 0;
	}
}

void cleanup_symbol_file_hash(struct symbols_file * sym)
{
	dhash_cleanup(&sym->dhash);
}

void exclude_symbol_file(struct symbols_file * from_sym,
	struct symbols_file * exclude_sym,
	int print_warn)
{
	size_t i;

	init_symbol_file_hash(exclude_sym);

	for (i = 0; i < from_sym->num_symbols;) {
		if (!is_in_symbol_file(exclude_sym, from_sym->symbol[i].name)) {
			i++;
			continue;
		}
		/* exclude this one */
		from_sym->num_symbols --;
		if (i < from_sym->num_symbols) {
			memcpy(&from_sym->symbol[i],
				&from_sym->symbol[from_sym->num_symbols],
				sizeof(from_sym->symbol[i]));
		}
	}

	cleanup_symbol_file_hash(exclude_sym);
}
