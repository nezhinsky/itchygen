/*
 * File: itchygen.c
 * Summary: a simple ITCH stream generator, output in PCAP format
 *          to be transmitted using tcp_replay or a similar utility
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
#include <pthread.h>

#include "itch_proto.h"
#include "itchygen.h"
#include "rand_util.h"
#include "ulist.h"
#include "usync_queue.h"
#include "pcap.h"
#include "double_hash.h"
#include "str_args.h"


static char program_name[] = "itchygen";

struct time_list {
	struct ulist_head *head;
	unsigned int time_units;
	unsigned int first_unit;
	unsigned int last_unit;
};

#define DEFAULT_MIN_TIME2UPD	10

struct itchygen_info {
	struct symbols_file all_sym;
	struct symbols_file list_sym;

	unsigned int run_time;
	unsigned long orders_rate;
	unsigned long num_orders;
	int num_rate_args;

	unsigned int time2update;
	unsigned int time2update_min;
	double time2update_min_f;

	int num_prob_args;
	int seq_ref_num;
	int no_hash_del;
	int debug_mode;
	int verbose_mode;
	unsigned int rand_seed;
	char *out_fname;

	struct endpoint_addr dst;
	struct endpoint_addr src;

	unsigned int first_ref_num;
	unsigned long long first_seq_num;

	unsigned long long cur_ref_num;
	unsigned long long cur_match_num;
	unsigned long long cur_seq_num;

	unsigned int num_poly;
	uint32_t poly[MAX_POLY];
	struct dhash_table dhash;
	struct itchygen_stat stat;
	double cur_time;
	struct time_list time_list;
	struct usync_queue ev_queue;
	struct rand_interval order_type_prob_int[MODIFY_ORDER_NUM_TYPES];
	struct rand_interval subscribed_prob_int[2];
};

static void print_params(struct itchygen_info *itchygen)
{
	char time_buf[32], s_ip_str[32], d_ip_str[32];
	time_t t = time(NULL);

	strftime(time_buf, sizeof(time_buf), "%F %T", localtime(&t));

	printf("\nitchygen ver %s started at %s\narguments:\n"
	       "\tsymbols file: %s, lines: %d, used: %d\n"
	       "\trun time: %d sec, rate: %ld orders/sec, orders: %ld, "
	       "mean update time: %d msec (minimal: %d msec)\n"
	       "\tprobability of exec: %d%% cancel: %d%% replace: %d%%\n"
	       "\t[%02x:%02x:%02x:%02x:%02x:%02x] %s:%d -> "
	       "[%02x:%02x:%02x:%02x:%02x:%02x] %s:%d\n"
	       "\tref_nums: %s, first ref_num: %u, first seq_num: %llu\n"
	       "\tdbg: %s, verbose: %s, seed: %d\n"
	       "\toutput file: %s\n",
	       ITCHYGEN_VER_STR, time_buf,
	       itchygen->all_sym.fname, itchygen->all_sym.num_lines,
	       itchygen->all_sym.num_symbols,
	       itchygen->run_time, itchygen->orders_rate, itchygen->num_orders,
	       itchygen->time2update, itchygen->time2update_min,
	       itchygen->order_type_prob_int[ORDER_EXEC].pcts_total,
	       itchygen->order_type_prob_int[ORDER_CANCEL].pcts_total,
	       itchygen->order_type_prob_int[ORDER_REPLACE].pcts_total,
	       itchygen->src.mac[0], itchygen->src.mac[1], itchygen->src.mac[2],
	       itchygen->src.mac[3], itchygen->src.mac[4], itchygen->src.mac[5],
	       inet_ntop(AF_INET, &itchygen->src.ip_addr, s_ip_str, 32),
	       (uint32_t) itchygen->src.port,
	       itchygen->dst.mac[0], itchygen->dst.mac[1], itchygen->dst.mac[2],
	       itchygen->dst.mac[3], itchygen->dst.mac[4], itchygen->dst.mac[5],
	       inet_ntop(AF_INET, &itchygen->dst.ip_addr, d_ip_str, 32),
	       (uint32_t) itchygen->dst.port,
	       itchygen->seq_ref_num ? "sequential" : "random",
	       itchygen->first_ref_num, itchygen->first_seq_num,
	       itchygen->debug_mode ? "on" : "off",
	       itchygen->verbose_mode ? "on" : "off",
	       itchygen->rand_seed,
	       itchygen->out_fname ? : "itchygen.pcap");

	if (itchygen->run_time * itchygen->orders_rate != itchygen->num_orders)
		printf("WARNING: time * rate != orders, generation will stop "
		       "when either time or orders run out\n\n");
}

static unsigned long long generate_ref_num(struct itchygen_info *itchygen)
{
	uint32_t refn32;
	int err;

 generate:
	if (!itchygen->seq_ref_num)
		refn32 = rand_uint32();
	else
		refn32 = (uint32_t) (++itchygen->cur_ref_num);

	err = dhash_add(&itchygen->dhash, refn32);
	if (likely(!err))	/* added successfully */
		return (unsigned long long)refn32;
	if (err == EEXIST) {
		assert(itchygen->no_hash_del);
		//return (unsigned long long)refn32;
		goto generate;
	}
	if (err == ENOMEM) {	/* no space in the bucket(s) */
		itchygen->stat.bucket_overflows++;
		goto generate;
	} else {
		assert(err == ENOSPC);
		printf("hash table full, can't generate refnum\n");
		exit(1);
	}
}

static inline double gen_inter_order_time(struct itchygen_info *itchygen)
{
	return rand_exp_time_by_rate((double)itchygen->orders_rate);
}

static inline double gen_time_to_update(struct itchygen_info *itchygen)
{
	/* mean time-to-update given in msecs */
	unsigned int mean_time_msec =
		(itchygen->time2update > itchygen->time2update_min) ?
		(itchygen->time2update - itchygen->time2update_min) : 0;
	double mean_sec = 0.001 * (double)mean_time_msec;
	/* lower limit 10 msec */
	return itchygen->time2update_min_f + rand_exp_time_by_mean(mean_sec);
}

static void order_event_free_back(struct order_event *event)
{
	struct order_event *prev_event;

	do {
		prev_event = event->prev_event;
		free(event);
	}
	while ((event = prev_event) != NULL);
}

static int pcap_order_add(struct itchygen_info *itchygen,
			  struct order_event *event)
{
	struct itch_packet pkt = {
		.mold = {
			 .seq_num = htobe64(event->seq_num),
			 .msg_cnt = htobe16(1),
			 },
		.msg.order = {
			      .msg_type = MSG_TYPE_ADD_ORDER_NO_MPID,
			      .timestamp_ns = htobe32(event->t_nsec),
			      .ref_num = htobe64(event->ref_num),
			      .buy_sell =
			      event->add.buy ? ITCH_ORDER_BUY : ITCH_ORDER_SELL,
			      .shares = htobe32(event->add.shares),
			      .price = htobe32(event->add.price),
			      },
	};

	memcpy(&pkt.mold.session, "sessionabc", 10);
	memcpy(pkt.msg.order.stock, event->symbol->name,
	       sizeof(pkt.msg.order.stock));

	return pcap_file_add_record(event->t_sec,
				    (event->t_nsec / 1000) + 3,
				    &pkt,
				    sizeof(pkt.mold) + sizeof(pkt.msg.order));
}

static int pcap_order_cancel(struct itchygen_info *itchygen,
			     struct order_event *event)
{
	struct itch_packet pkt = {
		.mold = {
			 .seq_num = htobe64(event->seq_num),
			 .msg_cnt = htobe16(1),
			 },
		.msg.cancel = {
			       .msg_type = MSG_TYPE_ORDER_CANCEL,
			       .timestamp_ns = htobe32(event->t_nsec),
			       .ref_num = htobe64(event->ref_num),
			       .shares = htobe32(event->cancel.shares),
			       },
	};

	memcpy(&pkt.mold.session, "sessionabc", 10);
	return pcap_file_add_record(event->t_sec,
				    (event->t_nsec / 1000) + 3,
				    &pkt,
				    sizeof(pkt.mold) + sizeof(pkt.msg.cancel));
}

static int pcap_order_exec(struct itchygen_info *itchygen,
			   struct order_event *event)
{
	struct itch_packet pkt = {
		.mold = {
			 .seq_num = htobe64(event->seq_num),
			 .msg_cnt = htobe16(1),
			 },
		.msg.exec = {
			     .msg_type = MSG_TYPE_ORDER_EXECUTED,
			     .timestamp_ns = htobe32(event->t_nsec),
			     .ref_num = htobe64(event->ref_num),
			     .shares = htobe32(event->exec.shares),
			     .match_num = htobe64(event->exec.match_num),
			     .printable = 'Y',
			     .price = htobe32(event->exec.price),
			     },
	};

	memcpy(&pkt.mold.session, "sessionabc", 10);
	return pcap_file_add_record(event->t_sec,
				    (event->t_nsec / 1000) + 3,
				    &pkt,
				    sizeof(pkt.mold) + sizeof(pkt.msg.exec));
}

static int pcap_order_replace(struct itchygen_info *itchygen,
			      struct order_event *event)
{
	struct itch_packet pkt = {
		.mold = {
			 .seq_num = htobe64(event->seq_num),
			 .msg_cnt = htobe16(1),
			 },
		.msg.replace = {
				.msg_type = MSG_TYPE_ORDER_REPLACE,
				.timestamp_ns = htobe32(event->t_nsec),
				.orig_ref_num =
				htobe64(event->replace.orig_ref_num),
				.new_ref_num = htobe64(event->ref_num),
				.shares = htobe32(event->replace.shares),
				.price = htobe32(event->replace.price),
				},
	};

	memcpy(&pkt.mold.session, "sessionabc", 10);
	return pcap_file_add_record(event->t_sec,
				    (event->t_nsec / 1000) + 3,
				    &pkt,
				    sizeof(pkt.mold) + sizeof(pkt.msg.replace));
}

static int pcap_order_timestamp(struct itchygen_info *itchygen,
				struct order_event *event)
{
	struct itch_packet pkt = {
		.mold = {
			 .seq_num = htobe64(event->seq_num),
			 .msg_cnt = htobe16(1),
			 },
		.msg.time = {
			     .msg_type = MSG_TYPE_TIMESTAMP,
			     .second = htobe32(event->timestamp.seconds),
			     },
	};

	memcpy(&pkt.mold.session, "sessionabc", 10);
	return pcap_file_add_record(event->t_sec,
				    (event->t_nsec / 1000) + 3,
				    &pkt,
				    sizeof(pkt.mold) + sizeof(pkt.msg.time));
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
	case ORDER_TIMESTAMP:
		err = pcap_order_timestamp(itchygen, event);
		break;
	default:
		assert(0);
		break;
	}

	if (unlikely(err)) {
		errno = err;
		printf("failed to write to pcap file, %m\n");
		exit(err);
	}
}

void order_event_submit(struct itchygen_info *itchygen,
			struct order_event *event)
{
	event->seq_num = itchygen->cur_seq_num++;

	if (unlikely(itchygen->verbose_mode))
		order_event_print(event, ">>>", 1);

	if (!itchygen->no_hash_del && event->type == ORDER_ADD) {
		int err = dhash_del(&itchygen->dhash,
				    (uint32_t) event->ref_num);
		assert(!err);
	}
	usync_queue_accum(&itchygen->ev_queue, &event->time_node);
}

#define TUNIT_SEC_SHIFT  9
#define TUNIT_NSEC_SHIFT (32 - TUNIT_SEC_SHIFT)
#define TUNIT_NSEC_MASK  ((1L << TUNIT_NSEC_SHIFT) - 1)

static void time_list_init(struct itchygen_info *itchygen)
{
	struct time_list *time_list = &itchygen->time_list;
	int i;

	time_list->time_units = ((itchygen->run_time + 100) << TUNIT_SEC_SHIFT);
	time_list->first_unit = 0;
	time_list->last_unit = 0;

	time_list->head =
	    malloc(sizeof(*time_list->head) * time_list->time_units);
	assert(time_list->head);

	for (i = 0; i < time_list->time_units; i++)
		ulist_head_init(&time_list->head[i]);
}

static void submit_entire_list(struct itchygen_info *itchygen,
			       struct ulist_head *uhead)
{
	struct order_event *event, *next;

	ulist_for_each_safe(uhead, event, next, time_node) {
		ulist_del_from(uhead, &event->time_node);
		if (unlikely(itchygen->debug_mode))
			printf("timelist: delete %u.%09u\n",
			       event->t_sec, event->t_nsec);
		order_event_submit(itchygen, event);
	}
	usync_queue_push_accum(&itchygen->ev_queue);
}

static void submit_list_up_to_event(struct itchygen_info *itchygen,
				    struct ulist_head *uhead,
				    struct order_event *add_event)
{
	struct order_event *event, *next;

	ulist_for_each_safe(uhead, event, next, time_node) {
		if (event->unit_time > add_event->unit_time)
			break;

		ulist_del_from(uhead, &event->time_node);
		if (unlikely(itchygen->debug_mode))
			printf("timelist: delete %u.%09u\n",
			       event->t_sec, event->t_nsec);
		order_event_submit(itchygen, event);
	}
	if (unlikely(itchygen->debug_mode))
		printf("timelist: direct submit %u.%09u\n",
		       add_event->t_sec, add_event->t_nsec);
	order_event_submit(itchygen, add_event);
	usync_queue_push_accum(&itchygen->ev_queue);
}

static void time_list_submit(struct itchygen_info *itchygen,
			     struct order_event *add_event)
{
	struct time_list *time_list = &itchygen->time_list;
	unsigned int unit_id;
	struct ulist_head *uhead;

	if (add_event && add_event->unit_id > time_list->last_unit)
		time_list->last_unit = add_event->unit_id;

	for (unit_id = time_list->first_unit;
	     unit_id <= time_list->last_unit; unit_id++) {
		uhead = &time_list->head[unit_id];

		if (!add_event || unit_id != add_event->unit_id)
			submit_entire_list(itchygen, uhead);
		else {
			submit_list_up_to_event(itchygen, uhead, add_event);
			time_list->first_unit = unit_id;
			if (unit_id > time_list->last_unit)
				time_list->last_unit = unit_id;
			return;
		}
	}
	time_list->first_unit = time_list->last_unit;
}

static void time_list_insert(struct itchygen_info *itchygen,
			     struct order_event *add_event)
{
	struct time_list *time_list = &itchygen->time_list;
	struct ulist_head *uhead = &time_list->head[add_event->unit_id];
	struct order_event *event, *next;

	if (add_event->unit_id < time_list->first_unit)
		time_list->first_unit = add_event->unit_id;
	if (add_event->unit_id > time_list->last_unit)
		time_list->last_unit = add_event->unit_id;

	event = ulist_top(uhead, struct order_event, time_node);
	if (!event || add_event->unit_time < event->unit_time) {
		/* list empty or less than first - add as head */
		ulist_add(uhead, &add_event->time_node);
		if (unlikely(itchygen->debug_mode))
			printf("timelist: add head %u.%09u\n",
			       add_event->t_sec, add_event->t_nsec);
		return;
	}
	event = ulist_tail(uhead, struct order_event, time_node);
	if (add_event->unit_time >= event->unit_time) {
		/* greater than last - add as tail */
		ulist_add_tail(uhead, &add_event->time_node);
		if (unlikely(itchygen->debug_mode))
			printf("timelist: add tail %u.%09u\n",
			       add_event->t_sec, add_event->t_nsec);
		return;
	}

	ulist_for_each_safe(uhead, event, next, time_node) {
		if (add_event->unit_time < next->unit_time) {
			/* place found - add after the current node */
			ulist_insert(uhead, &add_event->time_node,
				     &event->time_node);
			if (unlikely(itchygen->debug_mode))
				printf
				    ("timelist: insert %u.%09u between %u.%09u - %u.%09u\n",
				     add_event->t_sec, add_event->t_nsec,
				     event->t_sec, event->t_nsec,
				     next->t_sec, next->t_nsec);
			return;
		}
	}
	printf("add_event not on the list, or the list is corrupted");
	assert(0);
}

static double time_list_last(struct itchygen_info *itchygen)
{
	struct time_list *time_list = &itchygen->time_list;
	struct ulist_head *uhead = &time_list->head[time_list->last_unit];
	struct order_event *event;

	event = ulist_tail(uhead, struct order_event, time_node);
	return event ? event->time : -1.0;
}

static inline void set_event_time(struct order_event *event, double dt)
{
	event->time = dt;
	event->t_sec = dtime_to_sec(dt);
	event->t_nsec = dtime_to_nsec(dt);
	event->unit_id = (event->t_sec << TUNIT_SEC_SHIFT) |
	    (event->t_nsec >> TUNIT_NSEC_SHIFT);
	event->unit_time = (event->t_nsec & TUNIT_NSEC_MASK);
}

static struct order_event *generate_new_order(struct itchygen_info *itchygen,
					      double order_time)
{
	struct order_event *order;
	struct symbols_file *sym_file;
	int symbol_index;

	order = malloc(sizeof(*order));
	if (unlikely(!order))
		return NULL;

	order->type = ORDER_ADD;
	order->prev_event = NULL;

	if (itchygen->list_sym.fname &&
	    rand_index(itchygen->subscribed_prob_int, 2) == 0) {
		sym_file = &itchygen->list_sym;
		itchygen->stat.subscr_orders ++;
	} else
		sym_file = &itchygen->all_sym;
	symbol_index = rand_int_range(0, sym_file->num_symbols - 1);
	order->symbol = &sym_file->symbol[symbol_index];

	set_event_time(order, order_time);
	assert(order->unit_id < itchygen->time_list.time_units);
	order->ref_num = generate_ref_num(itchygen);
	order->add.buy = rand_int_range(0, 1);
	order->add.shares = 10 * rand_int_range(1, 250);
	order->add.price = rand_int_range(order->symbol->min_price,
					  order->symbol->max_price);

	order->remain_shares = order->add.shares;
	order->cur_price = order->add.price;

	itchygen->stat.orders++;
	return order;
}

static struct order_event *generate_modify_event(struct itchygen_info *itchygen,
						 struct order_event *order,	/* original order */
						 struct order_event
						 *prev_event)
{
	struct order_event *event;

	event = malloc(sizeof(*event));
	if (unlikely(!event))
		return NULL;

	event->type = rand_index(itchygen->order_type_prob_int,
				 MODIFY_ORDER_NUM_TYPES);
	event->prev_event = prev_event;
	event->symbol = order->symbol;
	set_event_time(event, order->time + gen_time_to_update(itchygen));
	assert(event->unit_id < itchygen->time_list.time_units);
	event->ref_num = order->ref_num;
	switch (event->type) {
	case ORDER_EXEC:
		event->exec.order = order;
		event->exec.shares = order->remain_shares;	/* ToDo: random partial shares */
		event->exec.price = order->cur_price - rand_int_range(0, 9);
		event->exec.match_num = ++itchygen->cur_match_num;

		event->remain_shares =
		    order->remain_shares - event->exec.shares;

		itchygen->stat.execs++;
		break;
	case ORDER_CANCEL:
		event->cancel.order = order;
		event->cancel.shares = order->remain_shares;	/* ToDo: random partial shares */

		event->remain_shares =
		    order->remain_shares - event->cancel.shares;

		itchygen->stat.cancels++;
		break;
	case ORDER_REPLACE:
		event->replace.order = order;
		event->replace.shares = 10 * rand_int_range(1, 250);
		event->replace.price =
		    rand_int_range(order->symbol->min_price,
				   order->symbol->max_price);
		event->replace.orig_ref_num = order->ref_num;
		event->ref_num = generate_ref_num(itchygen);

		event->remain_shares = event->replace.shares;
		event->cur_price = event->replace.price;

		itchygen->stat.replaces++;
		break;
	default:
		assert(event->type < MODIFY_ORDER_NUM_TYPES);
		break;
	}
	return event;
}

static void generate_single_timestamp(struct itchygen_info *itchygen,
				      unsigned int time_sec)
{
	struct order_event *event;

	event = malloc(sizeof(*event));
	assert(event);

	memset(event, 0, sizeof(*event));
	event->type = ORDER_TIMESTAMP;
	set_event_time(event, (double)time_sec);
	event->timestamp.seconds = time_sec;

	itchygen->stat.timestamps++;
	time_list_insert(itchygen, event);
}

static void generate_timestamps(struct itchygen_info *itchygen)
{
	unsigned int i;

	for (i = 0; i < itchygen->run_time; i++) {
		generate_single_timestamp(itchygen, i);
	}
}

static void *event_generator_thrd(void *arg)
{
	struct itchygen_info *itchygen = arg;
	struct order_event *order, *event, *prev_event;
	int n_order;
	double time_last;
	unsigned int time_last_sec, time_sec;

	itchygen->cur_time = 0.0;
	generate_timestamps(itchygen);

	for (n_order = 0; n_order < itchygen->num_orders; n_order++) {
		itchygen->cur_time += gen_inter_order_time(itchygen);

		if (unlikely(itchygen->cur_time >= itchygen->run_time)) {
			generate_single_timestamp(itchygen, itchygen->cur_time);
			itchygen->run_time = itchygen->cur_time + 1;
		}

		order = generate_new_order(itchygen, itchygen->cur_time);
		assert(order != NULL);
		if (unlikely(itchygen->debug_mode))
			order_event_print(order, "+++", 0);

		/* insert order and submit all events scheduled until now */
		time_list_submit(itchygen, order);

		prev_event = order;
		do {
			event =
			    generate_modify_event(itchygen, order, prev_event);
			assert(event != NULL);

			if (event->type == ORDER_REPLACE)
				order = event;
			if (unlikely(itchygen->debug_mode))
				order_event_print(event, "+++", 0);

			time_list_insert(itchygen, event);
			prev_event = event;
		}
		while (event->remain_shares);
	}

	time_last = time_list_last(itchygen);
	if (time_last >= 0.0) {
		time_last_sec = dtime_to_sec(time_last);
		if (time_last_sec >= itchygen->run_time) {
			for (time_sec = itchygen->run_time;
			     time_sec <= time_last_sec; time_sec++) {
				generate_single_timestamp(itchygen, time_sec);
			}
		}
	}
	/* submit entire list */
	time_list_submit(itchygen, NULL);
	if (itchygen->debug_mode)
		printf("waiting until ev list empty\n");
	usync_queue_shutdown(&itchygen->ev_queue);

	if (itchygen->debug_mode)
		printf("generator exits...\n");
	pthread_exit(NULL);
}

static void *pcap_writer_thrd(void *arg)
{
	struct itchygen_info *itchygen = arg;
	struct ulist_head wr_ev_list = ULIST_HEAD_INIT(wr_ev_list);
	struct order_event *event, *next;
	int err;

	while (1) {
		err = usync_queue_pull_list(&itchygen->ev_queue, &wr_ev_list);
		if (unlikely(err)) {
			assert(err == -1);
			break;
		}
		ulist_for_each_safe(&wr_ev_list, event, next, time_node) {
			ulist_del_from(&wr_ev_list, &event->time_node);
			order_event_pcap_msg(itchygen, event);
			if (!event->remain_shares)
				order_event_free_back(event);
		}
	}
	if (itchygen->debug_mode)
		printf("pcap writer exits...\n");
	pthread_exit(NULL);
}

static int str_to_mac(char *str, uint8_t * mac)
{
	int i, err;
	char ch = 0;

	if (strlen(str) != 17)
		return EINVAL;

	for (i = 0; i < 6; i++) {
		if (i < 5) {
			ch = str[3 * i + 2];
			if (ch != ':' && ch != '-' && ch != '.')
				return EINVAL;
			str[3 * i + 2] = 0;
		}
		err = str_to_int_range(&str[3 * i], mac[i], 0, 255, 16);
		if (i < 5)
			str[3 * i + 2] = ch;
		if (err)
			return err;
	}
	return 0;
}

void usage(int status, char *msg)
{
	if (msg)
		fprintf(stderr, "%s\n", msg);
	if (status)
		exit(status);

	printf("ITCH stream generator, version %s\n\n"
	       "Usage: %s [OPTION]\n"
	       "-s, --symbol-file   file with ticker [s]ymbols to use\n"
	       "-t, --run-time      total [t]ime for generated orders\n"
	       "-r, --orders-rate   orders [r]ate (1/sec), [kKmM] supported)\n"
	       "-n, --orders-num    total orders [n]umber, [kKmM] supported)\n"
	       "* * * missing -t/-r/-n inferred by: t * r = n\n\n"
	       "-L, --list-file     file with list of subscription symbols\n"
	       "-l, --list-ratio    ratio of subscribed symbols\n\n"
	       "-u, --time2update   mean time to order's [u]pdate (msec)\n"
	       "    --min-time2upd  minimal time to update, default: %d msec\n"
	       "-E, --prob-exec     probability of execution (0%%-100%%)\n"
	       "-C, --prob-cancel   probability of cancel (0%%-100%%)\n"
	       "-R, --prob-replace  probability of replace (0%%-100%%)\n"
	       "* * * missing -E/-C/-R inferred by: E + C + R = 100%%\n\n"
	       "-m, --dst-mac       destination MAC address, delimited by [:-.]\n"
	       "-M, --src-mac       source MAC address, delimited by [:-.]\n"
	       "-i, --dst-ip        destination ip address\n"
	       "-I, --src-ip        source ip address\n"
	       "-p, --dst-port      destination port\n"
	       "-P, --src-port      source port\n"
	       "* * * port range 1024..65535 supported, 49152..65535 recommended\n\n"
	       "-f, --file          output PCAP file name\n"
	       "-Q, --seq           sequential ref.nums, default: random\n"
	       "    --first-ref     first ref.num, only in sequential mode\n"
	       "    --first-seq     first seq.num\n"
	       "-S, --rand-seed     set the seed before starting work\n"
	       "    --no-hash-del   refnums not deleted from hash on expiration\n"
	       "-d, --debug         produce debug information\n"
	       "-v, --verbose       produce verbose output\n"
	       "-V, --version       print version and exit\n"
	       "-h, --help          display this help and exit\n",
	       ITCHYGEN_VER_STR, program_name, DEFAULT_MIN_TIME2UPD);
	exit(0);
}

static struct option const long_options[] = {
	{"symbol-file", required_argument, 0, 's'},
	{"run-time", required_argument, 0, 't'},
	{"orders-rate", required_argument, 0, 'r'},
	{"orders-num", required_argument, 0, 'n'},
	{"time2update", required_argument, 0, 'u'},
	{"min-time2upd", required_argument, 0, '_'}, /* short arg hidden */
	{"list-file", required_argument, 0, 'L'},
	{"list-ratio", required_argument, 0, 'l'},
	{"prob-exec", required_argument, 0, 'E'},
	{"prob-cancel", required_argument, 0, 'C'},
	{"prob-replace", required_argument, 0, 'R'},
	{"rand-seed", required_argument, 0, 'S'},
	{"dst-mac", required_argument, 0, 'm'},
	{"src-mac", required_argument, 0, 'M'},
	{"dst-port", required_argument, 0, 'p'},
	{"dst-ip", required_argument, 0, 'i'},
	{"src-port", required_argument, 0, 'P'},
	{"src-ip", required_argument, 0, 'I'},
	{"file", required_argument, 0, 'f'},
	{"no-hash-del", no_argument, 0, '0'}, /* short arg hidden */
	{"first-ref", required_argument, 0, '1'}, /* short arg hidden */
	{"first-seq", required_argument, 0, '2'}, /* short arg hidden */
	{"seq", no_argument, 0, 'Q'},
	{"debug", no_argument, 0, 'd'},
	{"verbose", no_argument, 0, 'v'},
	{"version", no_argument, 0, 'V'},
	{"help", no_argument, 0, 'h'},
	{0, 0, 0, 0},
};

static char *short_options = "s:t:r:n:L:l:u:E:C:R:S:m:M:p:i:P:I:f:1:2:Q0dvVh";

int main(int argc, char **argv)
{
	struct itchygen_info itchygen;
	int ch, longindex, err;
	const char *optname;
	unsigned int run_time = 0;
	unsigned long orders_rate = 0;
	unsigned long num_orders = 0;
	int num_rate_args = 0;
	int num_prob_args = 0;
	int prob_exec = -1;
	int prob_cancel = -1;
	int prob_replace = -1;
	int list_ratio = -1;
	int use_seed = 0;
	int mult, suffix;
	pthread_t thread1, thread2;
	uint8_t mac[8];
	in_addr_t ip_addr;
	uint16_t port;

	if (argc < 2)
		usage(0, NULL);

	memset(&itchygen, 0, sizeof(itchygen));
	itchygen.num_poly = get_default_poly(itchygen.poly, MAX_POLY);
	itchygen.time2update_min = DEFAULT_MIN_TIME2UPD;

	opterr = 0;		/* global getopt variable */
	for (;;) {
		ch = getopt_long(argc, argv, short_options,
				 long_options, &longindex);
		if (ch < 0)
			break;

		optname = long_options[longindex].name;

		switch (ch) {
		case 's':
			itchygen.all_sym.fname = strdup(optarg);
			assert(itchygen.all_sym.fname);
			break;
		case 'L':	/* subscription list file */
			itchygen.list_sym.fname = strdup(optarg);
			assert(itchygen.list_sym.fname);
			break;
		case 'l':	/* ratio of subscribed symbols from the list */
			if (list_ratio >= 0)
				usage(E2BIG, "error: -l supplied twice");
			err = str_to_int_range(optarg, list_ratio, 0, 100, 10);
			if (err)
				usage(bad_optarg(err, optname, optarg), NULL);
			break;
		case 'r':	/* orders rate */
			if (orders_rate)
				usage(EINVAL, "-r supplied twice");
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
				usage(bad_optarg(err, optname, optarg), NULL);
			orders_rate *= mult;
			num_rate_args++;
			break;
		case 't':	/* run time */
			if (run_time)
				usage(EINVAL, "-t supplied twice");
			err = str_to_int_gt(optarg, run_time, 0);
			if (err)
				usage(bad_optarg(err, optname, optarg), NULL);
			num_rate_args++;
			break;
		case 'n':	/* total number of orders */
			if (num_orders)
				usage(EINVAL, "-n supplied twice");
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
				usage(bad_optarg(err, optname, optarg), NULL);
			num_orders *= mult;
			num_rate_args++;
			break;
		case 'u':	/* mean time to next update message, msec */
			err = str_to_int_gt(optarg, itchygen.time2update, 0);
			if (err)
				usage(bad_optarg(err, optname, optarg), NULL);
			break;
		case '_':
			err = str_to_int_ge(optarg, itchygen.time2update_min, 10);
			if (err)
				usage(bad_optarg(err, optname, optarg), NULL);
			break;
		case 'E':	/* probability of execution */
			if (prob_exec >= 0)
				usage(E2BIG, "error: -E supplied twice");
			err = str_to_int_range(optarg, prob_exec, 0, 100, 10);
			if (err)
				usage(bad_optarg(err, optname, optarg), NULL);
			num_prob_args++;
			break;
		case 'C':	/* probability of cancel */
			if (prob_cancel >= 0)
				usage(E2BIG, "error: -C supplied twice");
			err = str_to_int_range(optarg, prob_cancel, 0, 100, 10);
			if (err)
				usage(bad_optarg(err, optname, optarg), NULL);
			num_prob_args++;
			break;
		case 'R':	/* probability of replace */
			if (prob_replace >= 0)
				usage(E2BIG, "error: -U supplied twice");
			err =
			    str_to_int_range(optarg, prob_replace, 0, 100, 10);
			if (err)
				usage(bad_optarg(err, optname, optarg), NULL);
			num_prob_args++;
			break;
		case 'S':	/* random seed */
			err = str_to_int_gt(optarg, itchygen.rand_seed, 0);
			if (err)
				usage(bad_optarg(err, optname, optarg), NULL);
			use_seed = 1;
			break;
		case 'm':
			err = str_to_mac(optarg, mac);
			if (err)
				usage(bad_optarg(err, optname, optarg), NULL);
			ep_addr_set_mac(&itchygen.dst, mac);
			break;
		case 'M':
			err = str_to_mac(optarg, mac);
			if (err)
				usage(bad_optarg(err, optname, optarg), NULL);
			ep_addr_set_mac(&itchygen.src, mac);
			break;
		case 'p':	/* dst port */
			err = str_to_int_range(optarg, port, 1024, 65535, 10);
			if (err)
				usage(bad_optarg(err, optname, optarg), NULL);
			ep_addr_set_port(&itchygen.dst, port);
			break;
		case 'P':	/* src port */
			err = str_to_int_range(optarg, port, 1024, 65535, 10);
			if (err)
				usage(bad_optarg(err, optname, optarg), NULL);
			ep_addr_set_port(&itchygen.src, port);
			break;
		case 'i':	/* dst ip addr */
			ip_addr = inet_addr(optarg);
			if (ip_addr == INADDR_NONE)
				bad_optarg(EINVAL, optname, optarg);
			ep_addr_set_ip(&itchygen.dst, ip_addr);
			break;
		case 'I':	/* src ip addr */
			ip_addr = inet_addr(optarg);
			if (ip_addr == INADDR_NONE)
				bad_optarg(EINVAL, optname, optarg);
			ep_addr_set_ip(&itchygen.src, ip_addr);
			break;
		case 'f':
			itchygen.out_fname = strdup(optarg);
			if (!itchygen.out_fname) {
				printf("failed to alloc mem for file name\n");
				exit(ENOMEM);
			}
			break;
		case 'Q':
			itchygen.seq_ref_num = 1;
			break;
		case '1':
			err = str_to_int(optarg, itchygen.first_ref_num, 0);
			if (err)
				usage(bad_optarg(err, optname, optarg), NULL);
			break;
		case '2':
			err = str_to_int(optarg, itchygen.first_seq_num, 0);
			if (err)
				usage(bad_optarg(err, optname, optarg), NULL);
			break;
		case '0':
			itchygen.no_hash_del = 1;
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

	if (!itchygen.all_sym.fname)
		usage(EINVAL, "error: symbols file name not supplied");

	if (itchygen.list_sym.fname && list_ratio < 0)
		usage(EINVAL, "error: subscription list was supplied but list ratio was not");

	if (!itchygen.time2update)
		usage(EINVAL, "error: mean time to next update not supplied");

	if (!ep_addr_all_set(&itchygen.dst))
		usage(EINVAL, "error: dst mac+ip+port not supplied");

	if (!ep_addr_all_set(&itchygen.src))
		usage(EINVAL, "error: src mac+ip+port not supplied");

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
			if ((prob_cancel + prob_replace) > 100)
				usage(EINVAL,
				      "error: 2 probability arguments "
				      "(-C,-R) together exceed 100%%");
			prob_exec = 100 - (prob_cancel + prob_replace);
		} else if (prob_cancel < 0) {
			assert(prob_exec >= 0 && prob_replace >= 0);
			if ((prob_exec + prob_replace) > 100)
				usage(EINVAL,
				      "error: 2 probability arguments "
				      "(-E,-R) together exceed 100%%");
			prob_cancel = 100 - (prob_exec + prob_replace);
		} else if (prob_replace < 0) {
			assert(prob_cancel >= 0 && prob_exec >= 0);
			if ((prob_cancel + prob_exec) > 100)
				usage(EINVAL,
				      "error: 2 probability arguments "
				      "(-E,-C) together exceed 100%%");
			prob_replace = 100 - (prob_exec + prob_cancel);
		}
	} else if (num_prob_args == 1) {
		if (prob_exec == 100) {
			prob_cancel = prob_replace = 0;
		} else if (prob_cancel == 100) {
			prob_exec = prob_replace = 0;
		} else if (prob_replace == 100) {
			prob_cancel = prob_exec = 0;
		} else
			usage(EINVAL,
			      "error: single probability argument "
			      "must be 100%%");
	} else {
		usage(EINVAL, "error: you should supply at least "
		      "2 of 3 probability (-E/-C/-R) arguments");
	}

	itchygen.cur_seq_num = itchygen.first_seq_num;
	if (itchygen.first_ref_num > 0) {
		if (!itchygen.seq_ref_num) {
			usage(EINVAL, "error: first ref.num is relevant "
			      "only for sequential ref.num mode (-Q)");
		}
		itchygen.cur_ref_num = itchygen.first_ref_num;
	}

	itchygen.time2update_min_f = 0.001 * (double)itchygen.time2update_min;

	rand_util_init(use_seed, &itchygen.rand_seed);

	err = read_symbol_file(&itchygen.all_sym, 1);
	if (err) {
		printf("failed to read symbols file\n");
		exit(err);
	}
	/* to generate random names:
	 *    symbol_name_generator_init();
	 *    then to make a new symbol:
	 *    symbol_name_generate(&itchygen.symbol[i], NULL);
	 */

	if (itchygen.list_sym.fname) {
		err = read_symbol_file(&itchygen.list_sym, 1);
		if (err) {
			printf("failed to read subscription list file\n");
			exit(err);
		}
		exclude_symbol_file(&itchygen.all_sym, &itchygen.list_sym, 1);
		exclude_symbol_file(&itchygen.list_sym, &itchygen.all_sym, 1);

		itchygen.subscribed_prob_int[0].pcts_total = list_ratio;
		itchygen.subscribed_prob_int[1].pcts_total = 100 - list_ratio;
		rand_interval_init(itchygen.subscribed_prob_int, 2);
	}

	itchygen.order_type_prob_int[ORDER_ADD].pcts_total = 0;
	itchygen.order_type_prob_int[ORDER_EXEC].pcts_total = prob_exec;
	itchygen.order_type_prob_int[ORDER_CANCEL].pcts_total = prob_cancel;
	itchygen.order_type_prob_int[ORDER_REPLACE].pcts_total = prob_replace;
	rand_interval_init(itchygen.order_type_prob_int,
			   MODIFY_ORDER_NUM_TYPES);

	time_list_init(&itchygen);
	usync_queue_init(&itchygen.ev_queue);

	err = dhash_init(&itchygen.dhash, CRC_WIDTH,
			 itchygen.poly, itchygen.num_poly);
	if (err) {
		errno = err;
		printf("failed to init hash table, %m\n");
		return err;
	}

	err = pcap_file_open(itchygen.out_fname ? : "itchygen.pcap",
			     &itchygen.dst, &itchygen.src);
	if (err) {
		errno = err;
		printf("failed to open pcap file, %m\n");
		return errno;
	}

	print_params(&itchygen);

	err = pthread_create(&thread1, NULL, event_generator_thrd, &itchygen);
	if (err) {
		printf("Failed to create generator thread, %m\n");
		return errno;
	}
	err = pthread_create(&thread2, NULL, pcap_writer_thrd, &itchygen);
	if (err) {
		printf("Failed to create pcap writer thread, %m\n");
		return errno;
	}
	pthread_join(thread1, NULL);
	pthread_join(thread2, NULL);

	pcap_file_close();

	print_stats(&itchygen.stat, &itchygen.dhash);
	dhash_cleanup(&itchygen.dhash);

	if (itchygen.out_fname)
		free(itchygen.out_fname);
	if (itchygen.all_sym.fname)
		free(itchygen.all_sym.fname);

	return 0;
}
