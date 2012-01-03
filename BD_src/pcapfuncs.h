#ifndef PCAPFUNCS_H
#define PCAPFUNCS_H

char* Lookupnic();
void Lookipnet(const char* nic, bpf_u_int32 *netp, bpf_u_int32 *maskp);
pcap_t* OpenCapHandle(const char* nic, int snaplen,int promisc,int timeout);
void CompileFilter(pcap_t *nd, struct bpf_program *fp, char *filter, 
    bpf_u_int32 netp);
void SetFilter(pcap_t *nd, struct bpf_program *fp);

#endif
