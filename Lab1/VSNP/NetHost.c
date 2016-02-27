#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include <unistd.h>//cpp compat for close function

#include "NetHost.h"

#define READERR 2

void writeToHost(nethost *client, void *data, size_t datalength)
{
	write(client->fd, data, datalength);
}

void *readFromHost(nethost *client, size_t datalength)
{
	int n = 0;
	int r = 0;
	void *buffer = malloc(datalength);
	while (r < datalength)
	{
		n = read(client->fd, buffer + r, datalength - r);
		if(n < 0)	
		{
			printf("Error! could not read from client");
			exit(READERR);
		}
		r +=n;
	}
	
	return buffer;	
}

nethost *createNetHost(int client, char *IPAddress, unsigned short netport)
{
	nethost *nclient = NULL;
	char *addresscopy = NULL;

	nclient = (nethost*)malloc(sizeof(nethost));
	addresscopy = (char *)malloc(strlen(IPAddress));
	strcpy(addresscopy, IPAddress);
	nclient->fd = client;
	nclient->ip = addresscopy;
	nclient->port = netport;
}

void destroyNetHost(nethost *nclient)
{
	close(nclient->fd);
	free (nclient->ip);
	free (nclient);
}

