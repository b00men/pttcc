#include <cstddef>
using namespace std;

#include "NetServer.h"
#include <iostream>


void serviceToClient(nethost *client)
{
	/*implement me*/
	cout << "Client: " << client->ip << ", " << client->port << "\n" ;
}

int main()
{
	const char *serviceIP = "127.0.0.1";
	unsigned short servicePort = 1010;
	serveClients(serviceToClient, serviceIP, servicePort);
}
