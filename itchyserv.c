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
#include <endian.h>
#include <sys/socket.h>
#include <netinet/in.h>

#define __STDC_FORMAT_MACROS
#include <inttypes.h>

#include "itch_proto.h"

static void print_event_time(char *msg)
{
	struct itch_msg_timestamp *evt = (struct itch_msg_timestamp *)msg;

	printf("timestamp: %d\n", be32toh(evt->second));
}

static void print_event_add(char *msg)
{
	struct itch_msg_add_order_no_mpid *evt =
	    (struct itch_msg_add_order_no_mpid *)msg;

	printf("time: %09d ADD ref: %" PRIu64 " %s %c shares: %d price: %d\n",
	       be32toh(evt->timestamp_ns), be64toh(evt->ref_num),
	       evt->stock, evt->buy_sell,
	       be32toh(evt->shares), be32toh(evt->price));
}

static void print_event_exec(char *msg)
{
	struct itch_msg_order_exec *evt = (struct itch_msg_order_exec *)msg;

	printf("time: %09d EXEC ref: %" PRIu64 " shares: %d price: %d\n",
	       be32toh(evt->timestamp_ns), be64toh(evt->ref_num),
	       be32toh(evt->shares), be32toh(evt->price));
}

static void print_event_cancel(char *msg)
{
	struct itch_msg_order_cancel *evt = (struct itch_msg_order_cancel *)msg;

	printf("time: %09d CANCEL ref: %" PRIu64 " shares: %d\n",
	       be32toh(evt->timestamp_ns), be64toh(evt->ref_num),
	       be32toh(evt->shares));
}

static void print_event_replace(char *msg)
{
	struct itch_msg_order_replace *evt =
	    (struct itch_msg_order_replace *)msg;

	printf("time: %09d REPLACE ref: %" PRIu64 " -> %" PRIu64
	       " shares: %d price: %d\n", be32toh(evt->timestamp_ns),
	       be64toh(evt->orig_ref_num), be64toh(evt->new_ref_num),
	       be32toh(evt->shares), be32toh(evt->price));
}

int main(int argc, char **argv)
{
	int sockfd, n;
	struct sockaddr_in servaddr, cliaddr;
	socklen_t len;
	unsigned short port;
	char msg[1000];

	if (argc != 2) {
		printf("usage:  udpserver <port>\n");
		exit(1);
	}

	port = atoi(argv[1]);
	if (!port) {
		printf("port arg invalid: %s\n", argv[1]);
		printf("usage:  udpserver <port>\n");
		exit(1);
	}

	sockfd = socket(AF_INET, SOCK_DGRAM, 0);

	memset(&servaddr, 0, sizeof(servaddr));
	servaddr.sin_family = AF_INET;
	servaddr.sin_addr.s_addr = htonl(INADDR_ANY);
	servaddr.sin_port = htons(port);
	bind(sockfd, (struct sockaddr *)&servaddr, sizeof(servaddr));

	for (;;) {
		len = sizeof(cliaddr);
		n = recvfrom(sockfd, msg, 1000, 0, (struct sockaddr *)&cliaddr,
			     &len);
		switch (msg[0]) {
		case 'A':
			print_event_add(msg);
			break;
		case 'C':
			print_event_exec(msg);
			break;
		case 'X':
			print_event_cancel(msg);
			break;
		case 'U':
			print_event_replace(msg);
			break;
		case 'T':
			print_event_time(msg);
			break;
		default:
			printf("unsupported msg: %c, len:%d\n", msg[0], n);
			break;
		}
	}
}
