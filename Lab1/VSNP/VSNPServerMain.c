
#include <stdio.h>
#include "NetServer.h"

void serviceToClient(nethost *client)
{
	printf("Client: %s, %i\n",client->ip, client->port);
}

int main()
{
	const char *serviceIP = "127.0.0.1";
	unsigned short servicePort = 1010;
	serveClients(serviceToClient, serviceIP, servicePort);
}
