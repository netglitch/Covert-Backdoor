#ifndef COVERT_H
#define COVERT_H

#include <linux/ip.h>
#include <netinet/tcp.h>

#define TCPIPMAXBYTES 21

struct send_tcp
{
	struct iphdr ip;
	struct tcphdr tcp;
};

/* From synhose.c by knight */
struct pseudo_header
{
	unsigned int source_address;
	unsigned int dest_address;
	unsigned char placeholder;
	unsigned char protocol;
	unsigned short tcp_length;
	struct tcphdr tcp;
};

int SendCovertData(char *filename,int fsize, char* dip, int dport, int protocol);
struct send_tcp* ConstructTCP(unsigned char* payload,char* dip, int dport);
unsigned int host_convert(char *hostname);
unsigned short in_cksum(unsigned short *ptr, int nbytes);
#endif
