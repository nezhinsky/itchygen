/*
 * File:   pcap.c
 * Summary: Creating a PCAP file with UDP packets from binary payload
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
#include <string.h>
#include <errno.h>
#include <assert.h>
#include <netinet/in.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <arpa/inet.h>

#include "pcap.h"

struct udp_hdrs {
	struct ether_header ether;
	struct iphdr ip;
	struct udphdr udp;
} __attribute__ ((packed));

struct ipv4_pseudo_hdr {
	uint32_t saddr;
	uint32_t daddr;
	uint8_t zero;
	uint8_t proto;
	uint16_t udp_len;
} __attribute__ ((packed));

static FILE *fpcap;
struct endpoint_addr _dst, _src;

int pcap_file_open(char *fname,
		   struct endpoint_addr *dst, struct endpoint_addr *src)
{
	size_t n;
	struct pcap_global_hdr ghdr = {
		.magic_number = PCAP_MAGIC_ORIG,
		.version_major = PCAP_VER_MAJOR,
		.version_minor = PCAP_VER_MINOR,
		.thiszone = 0,
		.sigfigs = 0,
		.snaplen = PCAP_SNAP_LEN,
		.network = PCAP_NET_ETH,
	};

	fpcap = fopen(fname, "wb");
	if (!fpcap)
		return errno;
	fseek(fpcap, 0l, SEEK_SET);
	n = fwrite(&ghdr, sizeof(ghdr), 1, fpcap);
	if (n < 1) {
		fclose(fpcap);
		return errno;
	}

	_dst = *dst;
	_src = *src;

	return 0;
}

static uint32_t ip_checksum_step(uint32_t init_sum, void *buf, size_t size)
{
	uint32_t sum = init_sum;
	uint16_t *b = buf;

	/* sum all 16-bit words in one's complement, pad if necessary */
	if (size & 1) {
		sum += ((uint8_t *) b)[size - 1];
		size--;		/* used only one byte tail, equivalent to padding */
	}
	for (size >>= 1; size > 0; size--)
		sum += *b++;

	return sum;
}

static uint16_t ip_checksum_final(uint32_t sum)
{
	/* calculate ones complement 16-bit sum */
	sum = (sum >> 16) + (sum & 0xffff);
	sum += sum >> 16;

	return ~sum;
}

#ifndef IPTOS_CLASS_CS0
#define IPTOS_CLASS_CS0 0x0
#endif

static void create_udp_packet(struct udp_hdrs *h, void *data, size_t len)
{
	struct ipv4_pseudo_hdr pseudo_iphdr;
	uint32_t udp_sum;

	memcpy(h->ether.ether_dhost, _dst.mac, ETH_ALEN);
	memcpy(h->ether.ether_shost, _src.mac, ETH_ALEN);
	h->ether.ether_type = htons(ETHERTYPE_IP);

	h->ip.ihl = sizeof(h->ip) / sizeof(uint32_t);
	h->ip.version = 4;	/* ipv4 */
	h->ip.tos = IPTOS_CLASS_CS0;
	/* IP header + UDP header + datalen */
	h->ip.tot_len = htons(sizeof(h->ip) + sizeof(h->udp) + len);
	h->ip.id = 0;		/* ID sequence number, single datagram - unused */
	h->ip.frag_off = htons(IP_DF);	/* flags:3 = Don't Frag, frag offset:13 = 0 */
	h->ip.ttl = 64;
	h->ip.protocol = IPPROTO_UDP;
	h->ip.saddr = _src.ip_addr;
	h->ip.daddr = _dst.ip_addr;
	h->ip.check = 0;
	h->ip.check =
	    ip_checksum_final(ip_checksum_step(0, &h->ip, sizeof(h->ip)));

	pseudo_iphdr.saddr = _src.ip_addr;
	pseudo_iphdr.daddr = _dst.ip_addr;
	pseudo_iphdr.zero = 0;
	pseudo_iphdr.proto = 0x11;
	pseudo_iphdr.udp_len = htons(sizeof(h->udp) + len);
	udp_sum = ip_checksum_step(0, &pseudo_iphdr, sizeof(pseudo_iphdr));

	h->udp.source = htons(_src.port);
	h->udp.dest = htons(_dst.port);
	/* UDP header + datalen */
	h->udp.len = htons(sizeof(h->udp) + len);
	h->udp.check = 0;	/* udp checksum */

	udp_sum = ip_checksum_step(udp_sum, &h->udp, sizeof(h->udp));
	udp_sum = ip_checksum_step(udp_sum, data, len);
	h->udp.check = ip_checksum_final(udp_sum);
}

int pcap_file_add_record(unsigned int tsec, unsigned int tusec,
			 void *data, size_t len)
{
	size_t n;
	struct pcap_record_hdr pcap_rechdr = {
		.ts_sec = tsec,
		.ts_usec = tusec,
		.incl_len = sizeof(struct udp_hdrs) + len,
		.orig_len = sizeof(struct udp_hdrs) + len,
	};
	struct udp_hdrs udp_hdrs;

	n = fwrite(&pcap_rechdr, sizeof(pcap_rechdr), 1, fpcap);
	if (n < 1)
		goto add_rec_failed;

	create_udp_packet(&udp_hdrs, data, len);

	n = fwrite(&udp_hdrs, sizeof(udp_hdrs), 1, fpcap);
	if (n < 1)
		goto add_rec_failed;

	n = fwrite(data, len, 1, fpcap);
	if (n < 1)
		goto add_rec_failed;

	return 0;

 add_rec_failed:
	n = errno;
	fclose(fpcap);
	return n;
}

void pcap_file_close(void)
{
	fclose(fpcap);
}
