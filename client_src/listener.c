#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <string.h>
#include <unistd.h>
#include <netdb.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <linux/ip.h>
#include <netinet/tcp.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#define TCPIPMAXBYTES 21

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
-- NOTES: Main program of the covert listener application
-- 
------------------------------------------------------------------------------*/
int main(int argc, char *argv[])
{
	int sd,fd,fsize=0,frem=0,byteswrite=0;
	char host[80], *octet, filename[FILENAME_MAX];
	char string[TCPIPMAXBYTES+1];
    
    struct recv_tcp
    {
        struct iphdr ip;
        struct tcphdr tcp;
        char buffer[10000];
    } recv_pkt;
    
    //Check arguments
    if(argc < 2)
    {
        printf("Missing Filename\n");
        exit(1);
    }
    
    //Get filename
    strncpy(filename,argv[1],FILENAME_MAX);
	
	if((fd = open(filename, O_CREAT|O_WRONLY|O_APPEND)) == -1)
	{
		perror("Error opening file");
		return 0;
	}

    //listen for file size
    if((sd=socket(AF_INET, SOCK_RAW, 6)) < 0)
    {
        perror("Receive socket could not be opened");
        exit(1);
    }
    
    while(1)
    {
        //read from the port
        read(sd,(struct recv_tcp *)&recv_pkt,9999);
        if((ntohs(recv_pkt.tcp.dest) == 80))
        {
            fsize = recv_pkt.ip.id;
            break;
        }   
    }
    
    printf("Incoming file is %d bytes\n",fsize);
    fflush(stdout);
    frem = fsize;
    
	while(frem > 0)
	{
		/*//create a raw reading socket
		if((sd=socket(AF_INET, SOCK_RAW, 6)) < 0)
		{
			perror("Receive socket could not be opened");
			exit(1);
		}
		*/
		//read from the port
		read(sd,(struct recv_tcp *)&recv_pkt,9999);
		if((ntohs(recv_pkt.tcp.dest) == 80))
        {
            //extract data
            memcpy(string,&recv_pkt.ip.id,2);
            memcpy(string+2,&recv_pkt.ip.ttl,1);
            memcpy(string+3,&recv_pkt.ip.saddr,4);
            memcpy(string+7,&recv_pkt.tcp.source,2);
            memcpy(string+9,&recv_pkt.tcp.seq,4);
            memcpy(string+13,&recv_pkt.tcp.ack_seq,4);
            memcpy(string+17,&recv_pkt.tcp.window,2);
            memcpy(string+19,&recv_pkt.tcp.urg_ptr,2);

            string[TCPIPMAXBYTES+1]='\0';
            
            if(frem < TCPIPMAXBYTES)
            {
                byteswrite=frem;
                frem = 0;
            }
            else
            {
                byteswrite=TCPIPMAXBYTES;
                frem -= TCPIPMAXBYTES;
            }
            //output to file
            write(fd, string, byteswrite);
            printf("%d bytes remaining\n",frem);
            fflush(stdout);
        }

        //close(sd);
		
	}//end of while loop
	
	//close the output file
    close(sd);
	close(fd);
}
