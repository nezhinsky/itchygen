/*
 * File:   pcap.c
 * Author: Alexander Nezhinsky (alexander@riverscale.com)
 */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <assert.h>
//#include <sys/socket.h>
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

int pcap_file_open(char *fname)
{
	size_t n;
	struct pcap_global_hdr ghdr = {
		.magic_number = PCAP_MAGIC_ORIG,
		.version_major = PCAP_VER_MAJOR,
		.version_minor = PCAP_VER_MINOR,
		.thiszone = 0,
		.sigfigs = 0,
		.snaplen = PCAP_SNAL_LEN,
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

static void create_udp_packet(struct udp_hdrs *h,
			      void *data, size_t len,
			      in_addr_t src_ip, in_addr_t dst_ip,
			      uint16_t src_port, uint16_t dst_port)
{
	struct ipv4_pseudo_hdr pseudo_iphdr;
	uint32_t udp_sum;

	memset(h->ether.ether_dhost, 0, ETH_ALEN);
	memset(h->ether.ether_shost, 0, ETH_ALEN);
	h->ether.ether_type = htons(ETHERTYPE_IP);

	h->ip.ihl = sizeof(h->ip) / sizeof(uint32_t);
	h->ip.version = 4;	/* ipv4 */
	h->ip.tos = IPTOS_CLASS_CS0;
	/* IP header + UDP header + datalen */
	h->ip.tot_len = htons(sizeof(h->ip) + sizeof(h->udp) + len);
	h->ip.id = 0;		/* ID sequence number, single datagram - unused */
	h->ip.frag_off = htons(IP_DF);	/* flags:3 = Don't Frag, frag offset:13 = 0 */
	h->ip.ttl = 16;
	h->ip.protocol = IPPROTO_UDP;
	h->ip.saddr = src_ip;
	h->ip.daddr = dst_ip;
	h->ip.check = 0;
	h->ip.check =
	    ip_checksum_final(ip_checksum_step(0, &h->ip, sizeof(h->ip)));

	pseudo_iphdr.saddr = src_ip;
	pseudo_iphdr.daddr = dst_ip;
	pseudo_iphdr.zero = 0;
	pseudo_iphdr.proto = 0x11;
	pseudo_iphdr.udp_len = htons(sizeof(h->udp) + len);
	udp_sum = ip_checksum_step(0, &pseudo_iphdr, sizeof(pseudo_iphdr));

	h->udp.source = htons(src_port);
	h->udp.dest = htons(dst_port);
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

	create_udp_packet(&udp_hdrs,
		data, len,
		//inet_addr("127.0.0.1"), inet_addr("127.0.0.1"),
		inet_addr("192.168.42.10"), inet_addr("192.168.42.122"),
		48500, 36000);
	
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
