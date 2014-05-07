/*
 * File:   itchyserv.c
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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <endian.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#define __STDC_FORMAT_MACROS	/* for PRIu64 etc. */
#include <inttypes.h>
#include <getopt.h>

#include "itch_proto.h"
#include "itchygen.h"
#include "str_args.h"

static char *prog_name;

static unsigned int time_sec;

static void print_event_time(struct itch_msg_timestamp *evt)
{
	time_sec = be32toh(evt->second);
	printf("timestamp: %d sec\n", time_sec);
}

static void print_event_add(struct itch_msg_add_order_no_mpid *evt)
{
	printf("time: %d.%09d ADD ref: %" PRIu64
	       " %s shares: %d %s price: %d\n", time_sec,
	       be32toh(evt->timestamp_ns), be64toh(evt->ref_num), evt->stock,
	       be32toh(evt->shares), str_buy_sell(evt->buy_sell),
	       be32toh(evt->price));
}

static void print_event_exec(struct itch_msg_order_exec *evt)
{
	printf("time: %d.%09d EXEC ref: %" PRIu64 " shares: %d price: %d\n",
	       time_sec, be32toh(evt->timestamp_ns), be64toh(evt->ref_num),
	       be32toh(evt->shares), be32toh(evt->price));
}

static void print_event_cancel(struct itch_msg_order_cancel *evt)
{
	printf("time: %d.%09d CANCEL ref: %" PRIu64 " shares: %d\n",
	       time_sec, be32toh(evt->timestamp_ns), be64toh(evt->ref_num),
	       be32toh(evt->shares));
}

static void print_event_replace(struct itch_msg_order_replace *evt)
{
	printf("time: %d.%09d REPLACE ref: %" PRIu64 " -> %" PRIu64
	       " shares: %d price: %d\n",
	       time_sec, be32toh(evt->timestamp_ns),
	       be64toh(evt->orig_ref_num), be64toh(evt->new_ref_num),
	       be32toh(evt->shares), be32toh(evt->price));
}

static char program_name[] = "itchyparse";

void version(void)
{
	printf("%s\n", ITCHYGEN_VER_STR);
	exit(0);
}

void usage(int status, char *msg)
{
	if (msg)
		fprintf(stderr, "%s\n", msg);
	if (status)
		exit(status);

	printf("simple ITCH UDP server, version %s\n\n"
	       "Usage: %s [OPTION]\n"
	       "-a, --addr          listening ip addr (default: ANY)\n"
	       "-p, --port          listening port (1024..65535)\n"
	       "-s, --strict        strict mode, exit on seq.num mismatch\n"
	       "-q, --quiet         quiet mode, only print error msgs\n"
	       "-d, --debug         produce debug information\n"
	       "-v, --verbose       produce verbose output\n"
	       "-V, --version       print version and exit\n"
	       "-h, --help          display this help and exit\n",
	       ITCHYGEN_VER_STR, program_name);
	exit(0);
}

static struct option const long_options[] = {
	{"addr", required_argument, 0, 'a'},
	{"port", required_argument, 0, 'p'},
	{"strict", no_argument, 0, 's'},
	{"quiet", no_argument, 0, 'q'},
	{"debug", no_argument, 0, 'd'},
	{"verbose", no_argument, 0, 'v'},
	{"version", no_argument, 0, 'V'},
	{"help", no_argument, 0, 'h'},
	{0, 0, 0, 0},
};

static char *short_options = "a:p:sqdvVh";


int main(int argc, char **argv)
{
	int ch, longindex, err;
	const char *optname;
	int sockfd, n;
	struct sockaddr_in servaddr, cliaddr;
	socklen_t len;
	unsigned short port = 0;
	uint64_t seq_num = 0, rec_seq_num;
	struct itch_packet *pkt;
	int quiet_mode = 0, strict_mode = 0;
	int debug_mode = 0, verbose_mode = 0;
	char msg[1000];

	prog_name = basename(argv[0]);

	memset(&servaddr, 0, sizeof(servaddr));
	servaddr.sin_family = AF_INET;
	servaddr.sin_addr.s_addr = htonl(INADDR_ANY); /* default */

	opterr = 0;		/* global getopt variable */
	for (;;) {
		ch = getopt_long(argc, argv, short_options,
				 long_options, &longindex);
		if (ch < 0)
			break;

		optname = long_options[longindex].name;

		switch (ch) {
		case 'a':
			if (!inet_aton(optarg, &servaddr.sin_addr)) {
				printf("invalid server address: [%s]\n", optarg);
				usage(EINVAL, NULL);
			}
			break;
		case 'p':
			err = str_to_int_range(optarg, port, 1024, 65535, 10);
			if (err)
				usage(bad_optarg(err, optname, optarg), NULL);
			break;
		case 's':
			strict_mode = 1;
			break;
		case 'q':
			quiet_mode = 1;
			break;
		case 'd':
			debug_mode = 1;
			verbose_mode = 1;
			break;
		case 'v':
			verbose_mode = 1;
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

	if (!port)
		usage(EINVAL, "error: port argument not supplied");

	printf("addr:%s port:%d ", inet_ntoa(servaddr.sin_addr), (int)port);
	printf("strict:%s quiet:%s debug:%s verbose:%s\n",
		strict_mode ? "yes" : "no",
		quiet_mode ? "yes" : "no",
		debug_mode ? "yes" : "no",
		verbose_mode ? "yes" : "no");

	sockfd = socket(AF_INET, SOCK_DGRAM, 0);
	if (socket < 0) {
		printf("failed to open socket, %m\n");
		exit(errno);
	}

	/* other fields set previously */
	servaddr.sin_port = htons(port);
	bind(sockfd, (struct sockaddr *)&servaddr, sizeof(servaddr));

	for (pkt = (struct itch_packet *)msg;;) {
		len = sizeof(cliaddr);
		n = recvfrom(sockfd, msg, sizeof(msg), 0,
			     (struct sockaddr *)&cliaddr, &len);
		if (n < 0) {
			printf("error: failed to received msg, %m\n");
			exit(errno);
		} else if (n < (sizeof(pkt->mold) + sizeof(pkt->msg.time))) {
			printf("error: received %d out of %zd bytes\n", n,
			       (sizeof(pkt->mold) + sizeof(pkt->msg.time)));
			exit(EIO);
		}

		rec_seq_num = be64toh(pkt->mold.seq_num);
		if (rec_seq_num != seq_num) {
			printf("error: mold_udp64 seq num: %" PRIu64
			       " received, " "expected: %" PRIu64 "\n",
			       rec_seq_num, seq_num);
			if (!strict_mode)
				seq_num = rec_seq_num;
			else
				exit(EIO);
		}
		if (!quiet_mode)
			printf("[%" PRIu64 "] ", seq_num);
		seq_num++;

		if (be16toh(pkt->mold.msg_cnt) != 1) {
			printf("error: mold_udp64 msg cnt:%d, 1 expected\n",
			       be16toh(pkt->mold.msg_cnt));
			exit(EIO);
		}

		if (quiet_mode) {
			switch (pkt->msg.common.msg_type) {
			case MSG_TYPE_ADD_ORDER_NO_MPID:
			case MSG_TYPE_ORDER_EXECUTED:
			case MSG_TYPE_ORDER_CANCEL:
			case MSG_TYPE_ORDER_REPLACE:
			case MSG_TYPE_TIMESTAMP:
				break;
			default:
				printf("error: unsupported msg: %c, len:%d\n",
				       pkt->msg.common.msg_type, n);
				exit(EIO);
			}
			continue;
		}

		switch (pkt->msg.common.msg_type) {
		case MSG_TYPE_ADD_ORDER_NO_MPID:
			print_event_add(&pkt->msg.order);
			break;
		case MSG_TYPE_ORDER_EXECUTED:
			print_event_exec(&pkt->msg.exec);
			break;
		case MSG_TYPE_ORDER_CANCEL:
			print_event_cancel(&pkt->msg.cancel);
			break;
		case MSG_TYPE_ORDER_REPLACE:
			print_event_replace(&pkt->msg.replace);
			break;
		case MSG_TYPE_TIMESTAMP:
			print_event_time(&pkt->msg.time);
			break;
		default:
			printf("error: unsupported msg: %c, len:%d\n",
			       pkt->msg.common.msg_type, n);
			exit(EIO);
		}
	}
	return 0;
}
