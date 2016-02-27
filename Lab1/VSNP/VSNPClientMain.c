
#include <stdio.h>
#include "NetClient.h"

int main() 
{
	char *hostip="127.0.0.1";
	unsigned short port = 1010;	
	nethost *server;
		
	server = connectToServer(hostip, port);
	
	printf("host: %s\n",server->ip);
}
