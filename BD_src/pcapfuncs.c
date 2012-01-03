#include <stdlib.h>
#include <pcap.h>
#include <string.h>
#include "pcapfuncs.h"

/*------------------------------------------------------------------------------
-- FUNCTION: Lookupnic()
--
-- DATE: May 28th 2010
--
-- REVISIONS:
--
-- DESIGNER: Tajinder Thind
--
-- PROGRAMMER: Tajinder Thind
--
-- INTERFACE: char* Lookupnic()
--
-- RETURNS: char*
--
-- NOTES: Will get the name of the first available NIC and return that.
-- 
------------------------------------------------------------------------------*/
char* Lookupnic()
{
    char errbuf[PCAP_ERRBUF_SIZE];
    char* nic;
    
    if((nic = pcap_lookupdev(errbuf)) == NULL)
    {
        printf("%s\n", errbuf);
        exit(1);
    }
    
    return nic;
}

/*------------------------------------------------------------------------------
-- FUNCTION: Lookipnet
--
-- DATE: May 28th 2010
--
-- REVISIONS:
--
-- DESIGNER: Tajinder Thind
--
-- PROGRAMMER: Tajinder Thind
--
-- INTERFACE: void Lookipnet(const char* nic, bpf_u_int32 *netp, bpf_u_int32 *maskp)
--
-- RETURNS: void 
--
-- NOTES: Gets the network ip and mask of the NIC specified.
-- 
------------------------------------------------------------------------------*/
void Lookipnet(const char* nic, bpf_u_int32 *netp, bpf_u_int32 *maskp)
{
    char errbuf[PCAP_ERRBUF_SIZE];
    
    if(pcap_lookupnet(nic,netp,maskp,errbuf) < 0)
    {
        printf("%s\n", errbuf);
        exit(1);
    }
    
    return;
}

/*------------------------------------------------------------------------------
-- FUNCTION: OpenCapHandle
--
-- DATE: May28th 2010
--
-- REVISIONS:
--
-- DESIGNER: Tajinder Thind
--
-- PROGRAMMER: Tajinder Thind
--
-- INTERFACE: pcap_t* OpenCapHandle(const char* nic, int snaplen,int promisc,
--                      int timeout)
--
-- RETURNS: pcap_t*
--
-- NOTES: Will get a pcap descriptor struct of the nic specified and return that
-- 
------------------------------------------------------------------------------*/
pcap_t* OpenCapHandle(const char* nic, int snaplen,int promisc,int timeout)
{
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* nicd;
    size_t len = 0;
    
    //make errbuf zero length
    errbuf[0]='\0';
    
    //If the descriptor returned is null then kill the process
    if((nicd = pcap_open_live(nic,snaplen,promisc,timeout,errbuf)) == NULL)
    {
        printf("%s\n", errbuf);
        exit(1);
    }
    
    //check errbuf for warnings
    if((len = strlen(errbuf)) != 0)
    {
        printf("%s\n", errbuf);
    }
    
    return nicd;
}

/*------------------------------------------------------------------------------
-- FUNCTION: CompileFilter
--
-- DATE: May 28th 2010
--
-- REVISIONS:
--
-- DESIGNER: Tajinder Thind
--
-- PROGRAMMER: Tajinder Thind
--
-- INTERFACE: void CompileFilter(pcap_t *nd, struct bpf_program *fp, char *filter, 
--                 bpf_u_int32 netp)
--
-- RETURNS: void
--
-- NOTES: Compiles the specified filter to the specifed pcap handle stored at 
--        *fp
-- 
------------------------------------------------------------------------------*/
void CompileFilter(pcap_t *nd, struct bpf_program *fp, char *filter, 
    bpf_u_int32 netp)
{
    if (pcap_compile (nd, fp, filter, 0, netp) == -1)
    { 
        pcap_perror(nd,"Error calling pcap_compile"); 
        exit(1);
    }
    
    return;
}

/*------------------------------------------------------------------------------
-- FUNCTION: SetFilter
--
-- DATE: May 28th 2010
--
-- REVISIONS:
--
-- DESIGNER: Tajinder Thind
--
-- PROGRAMMER: Tajinder Thind
--
-- INTERFACE: void SetFilter(pcap_t *nicd, struct bpf_program *fp)
--
-- RETURNS: void
--
-- NOTES: Sets the compiled program at fp into the device specified by nicd
-- 
------------------------------------------------------------------------------*/
void SetFilter(pcap_t *nicd, struct bpf_program *fp)
{
    if (pcap_setfilter (nicd, fp) == -1)
    { 
        pcap_perror(nicd,"Error setting filter\n"); 
        exit(1); 
    }
    return;
}
