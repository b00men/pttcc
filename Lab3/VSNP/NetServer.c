/*
 * NetServer.c File that provides function implementations for the network server.
 */

#include <sys/socket.h>
#include <netinet/in.h> 
#include <arpa/inet.h>

#include <stdlib.h>
#include <stdio.h>

#include <unistd.h>//cpp compat for close function

#include "NetServer.h"

#define BINDERR 1
#define READERR 2

#define MAX_PORT_NUM 65535
#define MAX_PENDING_CONNS_Q 10

int getSocket(const char *host, unsigned short port)
{
	int socketfd = 0;
	struct sockaddr_in *serverAddress = (struct sockaddr_in*)malloc(sizeof(struct sockaddr_in)); 
	
	if (port < 0 || port >= MAX_PORT_NUM)
                return -1; 


	serverAddress->sin_family = AF_INET;
	serverAddress->sin_port = htons(port);

	if (inet_pton(AF_INET, host, (void*)&serverAddress->sin_addr) != 1 )
	{
		printf("Wrong host format\n");
		exit(BINDERR);	
	}

	socketfd = socket(AF_INET, SOCK_STREAM, 0);

	if(bind(socketfd, (struct sockaddr*)serverAddress, sizeof(struct sockaddr_in)) == -1)
	{
		printf("Could not bind %s:%i\n", host, port);
		exit(BINDERR);	
	}

	if (listen(socketfd, MAX_PENDING_CONNS_Q) == -1)
	{
		printf("Could not listen%s:%i\n", host, port);
		exit(BINDERR);	
	}
	
	return socketfd; 
}


void attendClient (void (*servicefunc)(nethost*, unsigned char), nethost *client, unsigned char errors)
{
	//thread
	servicefunc(client, errors);
	destroyNetHost(client);
	printf("closed conn");
}

void serveClients(void (*servicefunc)(nethost*, unsigned char), const char *host, unsigned short port, unsigned char errors)
{
	struct sockaddr_in *clientAddress = NULL;
	int listener = getSocket(host , port);
	int client;
	char IPAddress[INET6_ADDRSTRLEN];
	unsigned short clientPort;
	socklen_t *size = NULL;
	nethost *nclient = NULL;
	
	size = (socklen_t*)malloc(sizeof(int));
	*size =(unsigned int)sizeof(struct sockaddr_in);
	
		
	if (listener == -1)
	{
		printf("Wrong port number %i\n", port);
		exit(BINDERR);
	}

	while(1)
	{

		clientAddress = (struct sockaddr_in*)malloc(sizeof(struct sockaddr_in)); //if you modify anything, do not modify this line!

		client = accept(listener, (struct sockaddr*)clientAddress, size);

		inet_ntop(clientAddress->sin_family, (clientAddress->sin_family == AF_INET)?(void*)&((struct sockaddr_in*)clientAddress)->sin_addr:(void*)&((struct sockaddr_in6*)clientAddress)->sin6_addr, IPAddress, INET6_ADDRSTRLEN); //ugly line, no? well... do you even C?;
		if (client < 0)
		{
			printf("Could not accept connection of client%s\n", IPAddress); 
			continue;	
		}
		
		clientPort = htons(clientAddress->sin_port);	
		
		nclient = createNetHost(client, IPAddress, clientPort);

		attendClient(servicefunc, nclient, errors);

	}

	close(listener);

}
