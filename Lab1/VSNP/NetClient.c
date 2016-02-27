/*
 * NetClient.c File that provides function implementations for the network client.
 */

#include <sys/socket.h>
#include <netinet/in.h> 
#include <arpa/inet.h>

#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>

#include <unistd.h>//cpp compat for close function

#include "NetClient.h"

#define CONNERR 1

nethost *connectToServer(char *host, unsigned short port)
{
	nethost *server;
	int sockfd;
	struct sockaddr_in serv_addr; 

	memset(&serv_addr, '0', sizeof(serv_addr));
	if((sockfd = socket(AF_INET, SOCK_STREAM, 0)) < 0)
	{
        	printf("\n Error : Could not create socket \n");
        	exit(CONNERR);	
	} 

	serv_addr.sin_family = AF_INET;
    	serv_addr.sin_port = htons(port); 

	if(inet_pton(AF_INET, host, &serv_addr.sin_addr)<=0)
	{
		printf("Error! inet_pton error occured\n");
		exit(CONNERR);
	} 
	
	if(connect(sockfd, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0)
	{
		printf("Error! Connection Failed to host %s:%i \n", host, port);
		exit(CONNERR);
	} 
	
	server = createNetHost(sockfd, host, port);	
	return server;
}

