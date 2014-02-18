/* 
 * File:   pcap.h
 * Author: Alexander Nezhinsky (alexander@riverscale.com)
 */

#ifndef PCAP_H
#define	PCAP_H

#include <stdint.h>

struct pcap_global_hdr {
	uint32_t magic_number;	/* magic number */
	uint16_t version_major;	/* major version number */
	uint16_t version_minor;	/* minor version number */
	int32_t thiszone;	/* GMT to local correction */
	uint32_t sigfigs;	/* accuracy of timestamps */
	uint32_t snaplen;	/* max length of captured packets, in octets */
	uint32_t network;	/* data link type */
} __attribute__ ((packed));

#define PCAP_MAGIC_ORIG  0xa1b2c3d4
#define PCAP_MAGIC_SWAP  0xd4c3b2a1

#define PCAP_VER_MAJOR  2
#define PCAP_VER_MINOR  4

#define PCAP_SNAL_LEN   65535
#define PCAP_NET_ETH    1

struct pcap_record_hdr {
	uint32_t ts_sec;	/* timestamp seconds */
	uint32_t ts_usec;	/* timestamp microseconds */
	uint32_t incl_len;	/* number of octets of packet saved in file */
	uint32_t orig_len;	/* actual length of packet */
} __attribute__ ((packed));

int pcap_file_open(char *fname);
int pcap_file_add_record(unsigned int tsec, unsigned int tusec,
			 void *data, size_t len);
void pcap_file_close(void);

#endif				/* PCAP_H */
