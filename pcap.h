/*
 * File:   pcap.h
 * Summary: Creating a PCAP file with UDP packets from binary payload
 * Author: Alexander Nezhinsky (nezhinsky@gmail.com)
 */

#ifndef PCAP_H
#define	PCAP_H

#include <stdint.h>
#include <netinet/in.h>
#include <arpa/inet.h>

struct pcap_global_hdr {
	uint32_t magic_number;	/* magic number */
	uint16_t version_major;	/* major version number */
	uint16_t version_minor;	/* minor version number */
	int32_t thiszone;	/* GMT to local correction */
	uint32_t sigfigs;	/* accuracy of timestamps */
	uint32_t snaplen;	/* max length of captured packets, in octets */
	uint32_t network;	/* data link type */
} __attribute__ ((packed));

#define PCAP_MAGIC_ORIG		0xa1b2c3d4
#define PCAP_MAGIC_SWAP		0xd4c3b2a1

#define PCAP_VER_MAJOR		2
#define PCAP_VER_MINOR		4

#define PCAP_SNAP_LEN		65535
#define PCAP_NET_ETH		1

struct pcap_record_hdr {
	uint32_t ts_sec;	/* timestamp seconds */
	uint32_t ts_usec;	/* timestamp microseconds */
	uint32_t incl_len;	/* number of octets of packet saved in file */
	uint32_t orig_len;	/* actual length of packet */
} __attribute__ ((packed));

struct endpoint_addr {
	uint8_t mac[8];
	in_addr_t ip_addr;
	uint16_t port;
	uint16_t mask;
};

#define EP_ADDR_MAC_SET		0x01
#define EP_ADDR_IP_SET		0x02
#define EP_ADDR_PORT_SET	0x04

#define EP_ADDR_ALL_SET		(EP_ADDR_MAC_SET | EP_ADDR_IP_SET | EP_ADDR_PORT_SET)

static inline void ep_addr_set_mac(struct endpoint_addr *ep, uint8_t * mac)
{
	memcpy(ep->mac, mac, sizeof(ep->mac));
	ep->mask |= EP_ADDR_MAC_SET;
}

static inline void ep_addr_set_ip(struct endpoint_addr *ep, in_addr_t ip_addr)
{
	ep->ip_addr = ip_addr;
	ep->mask |= EP_ADDR_IP_SET;
}

static inline void ep_addr_set_port(struct endpoint_addr *ep, uint16_t port)
{
	ep->port = port;
	ep->mask |= EP_ADDR_PORT_SET;
}

static inline int ep_addr_all_set(struct endpoint_addr *ep)
{
	return ((ep->mask & EP_ADDR_ALL_SET) == EP_ADDR_ALL_SET ? 1 : 0);
}

int pcap_file_open(char *fname,
		   struct endpoint_addr *dst, struct endpoint_addr *src);
int pcap_file_add_record(unsigned int tsec, unsigned int tusec,
			 void *data, size_t len);
void pcap_file_close(void);

#endif				/* PCAP_H */
