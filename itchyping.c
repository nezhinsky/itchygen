/* Sample UDP client */

#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <unistd.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "itch_proto.h"

static void usage(int err)
{
	printf("usage:  udpclient <ip_addr> <port>\n");
	exit(err);
}

const uint64_t REF_NUM_1 = 123456LL;
const uint64_t REF_NUM_2 = 234561LL;
const uint64_t REF_NUM_3 = 345612LL;
const uint64_t REF_NUM_4 = 456123LL;

const uint32_t TIME_SEC = 777L;

const uint32_t TIME_NS_1 = 123456789L;
const uint32_t TIME_NS_2 = 234567891L;
const uint32_t TIME_NS_3 = 345678912L;
const uint32_t TIME_NS_4 = 456789123L;
const uint32_t TIME_NS_5 = 567891234L;
const uint32_t TIME_NS_6 = 678912345L;
const uint32_t TIME_NS_7 = 789123456L;

static int sockfd;
static struct sockaddr_in servaddr;

static void send_msg(void *buf, size_t size)
{
    int n;

    n = sendto(sockfd, buf, size, 0,
	    (struct sockaddr *)&servaddr, sizeof(servaddr));
    if (n == size)
	return;
    else if (n < 0) {
	printf("failed to send msg, size %zd : %m\n", size);
	exit(errno);
    } else {
	printf("failed to send entire msg, sent %d out of %zd\n", n, size);
	exit(EIO);
    }
}

int main(int argc, char **argv)
{
	unsigned short port;

	struct itch_msg_timestamp time_msg = {
		.msg_type = MSG_TYPE_TIMESTAMP,
		.second = htobe32(TIME_SEC),
	};
	struct itch_msg_add_order_no_mpid add_msg1 = {
		.msg_type = MSG_TYPE_ADD_ORDER_NO_MPID,
		.timestamp_ns = htobe32(TIME_NS_1),
		.ref_num = htobe64(REF_NUM_1),
		.buy_sell = 'B',
		.shares = htobe32(1000L),
		.price = htobe32(280L),
		.stock = "SAP",
	};
	struct itch_msg_add_order_no_mpid add_msg2 = {
		.msg_type = MSG_TYPE_ADD_ORDER_NO_MPID,
		.timestamp_ns = htobe32(TIME_NS_2),
		.ref_num = htobe64(REF_NUM_2),
		.buy_sell = 'S',
		.shares = htobe32(600L),
		.price = htobe32(100L),
		.stock = "IBM",
	};
	struct itch_msg_order_exec exec_msg1 = {
		.msg_type = MSG_TYPE_ORDER_EXECUTED,
		.timestamp_ns = htobe32(TIME_NS_3),
		.ref_num = htobe64(REF_NUM_1),
		.shares = add_msg1.shares,
		.match_num = add_msg1.ref_num,
		.printable = 'Y',
		.price = add_msg1.price,
	};
	struct itch_msg_add_order_no_mpid add_msg3 = {
		.msg_type = MSG_TYPE_ADD_ORDER_NO_MPID,
		.timestamp_ns = htobe32(TIME_NS_4),
		.ref_num = htobe64(REF_NUM_3),
		.buy_sell = 'S',
		.shares = htobe32(500L),
		.price = htobe32(230L),
		.stock = "EMC",
	};	
	struct itch_msg_order_replace replace_msg2 = {
		.msg_type = MSG_TYPE_ORDER_REPLACE,
		.timestamp_ns = htobe32(TIME_NS_5),
		.orig_ref_num = add_msg2.ref_num,
		.new_ref_num = htobe64(REF_NUM_4),
		.shares = htobe32(200L),
		.price = htobe32(120L),
	};
	struct itch_msg_order_cancel cancel_msg3 = {
		.msg_type = MSG_TYPE_ORDER_CANCEL,
		.timestamp_ns = htobe32(TIME_NS_6),
		.ref_num = htobe64(REF_NUM_3),
		.shares = add_msg3.shares,
	};
	struct itch_msg_order_exec exec_msg2 = {
		.msg_type = MSG_TYPE_ORDER_EXECUTED,
		.timestamp_ns = htobe32(TIME_NS_7),
		.ref_num = replace_msg2.new_ref_num,
		.shares = replace_msg2.shares,
		.match_num = replace_msg2.new_ref_num,
		.printable = 'Y',
		.price = replace_msg2.price,
	};
	
	if (argc != 3) {
		printf("usage:  itchyping <ip_addr> <port>\n");
		exit(1);
	}

	sockfd = socket(AF_INET, SOCK_DGRAM, 0);

	memset(&servaddr, 0, sizeof(servaddr));
	servaddr.sin_family = AF_INET;
	servaddr.sin_addr.s_addr = inet_addr(argv[1]);
	if (servaddr.sin_addr.s_addr == INADDR_NONE || !servaddr.sin_addr.s_addr) {
		printf("ip arg invalid: %s\n", argv[1]);
		usage(EINVAL);
	}
	port = atoi(argv[2]);
	if (!port) {
		printf("port arg invalid: %s\n", argv[2]);
		usage(EINVAL);
	}
	servaddr.sin_port = htons(port);

	send_msg(&time_msg, sizeof(time_msg));
	send_msg(&add_msg1, sizeof(add_msg1));
	send_msg(&add_msg2, sizeof(add_msg2));
	send_msg(&exec_msg1, sizeof(exec_msg1));
	send_msg(&add_msg3, sizeof(add_msg3));
	send_msg(&replace_msg2, sizeof(replace_msg2));
	send_msg(&cancel_msg3, sizeof(cancel_msg3));
	send_msg(&exec_msg2, sizeof(exec_msg2));

	close(sockfd);
	return 0;
}
