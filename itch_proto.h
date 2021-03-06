/*
 * File: itch_proto.h
 * Summary: ITCH messaging protocol definitions
 * Author: Alexander Nezhinsky (nezhinsky@gmail.com)
 */

#ifndef __ITCH_PROTO_H__
#define __ITCH_PROTO_H__

#include <stdint.h>

#define TRADING_STATE_HALTED		'H'	/* halted across all markets/SROs */
#define TRADING_STATE_PAUSED		'P'	/* paused across all markets/SROs (NASDAQ only) */
#define TRADING_STATE_QUOTE_ONLY	'Q'	/* quotation only period for cross-SRO halt/pause */
#define TRADING_STATE_TRADING		'T'	/* currently trading on NASDAQ */

#define MSG_TYPE_TRADING_ACTION		'H'
#define MSG_TYPE_TIMESTAMP		'T'
#define MSG_TYPE_ADD_ORDER_NO_MPID	'A'
#define MSG_TYPE_ADD_ORDER_WITH_MPID	'F'
#define MSG_TYPE_ORDER_EXECUTED		'C'
#define MSG_TYPE_ORDER_CANCEL		'X'
#define MSG_TYPE_ORDER_DELETE		'D'
#define MSG_TYPE_ORDER_REPLACE		'U'

#define ITCH_ORDER_BUY			'B'
#define ITCH_ORDER_SELL			'S'

#define ITCH_SYMBOL_LEN			8

struct itch_msg_timestamp {
	char msg_type;		/* 'T' - timestamp message */
	uint32_t second;	/* seconds since midnight */
} __attribute__ ((packed));

struct itch_msg_stock_trade {
	char msg_type;		/* 'H' - stock trading action message */
	uint32_t timestamp_ns;	/* ns portion f the timestamp */
	char stock[ITCH_SYMBOL_LEN];	/* stock symbol right padded with spaces */
	char trading_state;	/* current trading state for the stock */
	char reserved;
	char reason[4];		/* trading action reason */
} __attribute__ ((packed));

struct itch_msg_add_order_no_mpid {
	char msg_type;		/* 'A' - add order - no MPID Attribution message */
	uint32_t timestamp_ns;	/* ns portion f the timestamp */
	uint64_t ref_num;	/* unique reference assigned to the new order */
	char buy_sell;		/* 'B' - buy, 'S' - sell */
	uint32_t shares;	/* num of shared associated with the order */
	char stock[ITCH_SYMBOL_LEN];	/* symbol for which the order is added */
	uint32_t price;		/* display price of the order */
} __attribute__ ((packed));

struct itch_msg_add_order_with_mpid {
	char msg_type;		/* 'F' - add order - no MPID Attribution message */
	uint32_t timestamp_ns;	/* ns portion f the timestamp */
	uint64_t ref_num;	/* unique reference assigned to the new order */
	char buy_sell;		/* 'B' - buy, 'S' - sell */
	uint32_t shares;	/* num of shared associated with the order */
	char stock[ITCH_SYMBOL_LEN];	/* symbol for which the order is added */
	uint32_t price;		/* display price of the order */
	char attribution[4];	/* NASDAQ market participant id (MPID) for the order */
} __attribute__ ((packed));

struct itch_msg_order_exec {
	char msg_type;		/* 'C' - order executed message */
	uint32_t timestamp_ns;	/* ns portion f the timestamp */
	uint64_t ref_num;	/* unique reference assigned to the order */
	uint32_t shares;	/* num of shared executed */
	uint64_t match_num;	/* NASDAQ generated day-unique match num */
	char printable;		/* 'N' non-printab;e, 'Y' printable */
	uint32_t price;		/* price at which execution occurred */
} __attribute__ ((packed));

struct itch_msg_order_cancel {
	char msg_type;		/* 'X' - order cancel message */
	uint32_t timestamp_ns;	/* ns portion f the timestamp */
	uint64_t ref_num;	/* unique reference assigned to the order */
	uint32_t shares;	/* num of shared removed from the display size */
} __attribute__ ((packed));

struct itch_msg_order_delete {
	char msg_type;		/* 'D' - order delete message */
	uint32_t timestamp_ns;	/* ns portion f the timestamp */
	uint64_t ref_num;	/* unique reference assigned to the order */
} __attribute__ ((packed));

struct itch_msg_order_replace {
	char msg_type;		/* 'U' - order replace message */
	uint32_t timestamp_ns;	/* ns portion f the timestamp */
	uint64_t orig_ref_num;	/* original reference assigned to the order */
	uint64_t new_ref_num;	/* new unique reference assigned to the order */
	uint32_t shares;	/* new total display quantity */
	uint32_t price;		/* new display price */
} __attribute__ ((packed));

struct itch_msg_common {
	char msg_type;		/* only msg_type is common for all */
	uint32_t timestamp_ns;
	uint64_t ref_num;
} __attribute__ ((packed));

union itch_msg {
	struct itch_msg_common common;
	struct itch_msg_timestamp time;
	struct itch_msg_stock_trade trade;
	struct itch_msg_add_order_no_mpid order;
	struct itch_msg_add_order_with_mpid order_mpid;
	struct itch_msg_order_exec exec;
	struct itch_msg_order_cancel cancel;
	struct itch_msg_order_delete del;
	struct itch_msg_order_replace replace;
} __attribute__ ((packed));

struct mold_udp64 {
	char session[10];
	uint64_t seq_num;
	uint16_t msg_cnt;
} __attribute__ ((packed));

struct itch_packet {
	struct mold_udp64 mold;
	union itch_msg msg;
} __attribute__ ((packed));

static inline char *str_buy_sell(char buy_sell)
{
	if (buy_sell == ITCH_ORDER_BUY)
		return "BUY";
	else if (buy_sell == ITCH_ORDER_SELL)
		return "SELL";
	else
		return "INVALID";
}

#endif
