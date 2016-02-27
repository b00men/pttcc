#include <cstddef>
using namespace std;

#include "NetClient.h"
#include <iostream>


int main()
{
	char *hostip= "127.0.0.1";
	unsigned short port = 1010;
	
	nethost *server;
                
        server = connectToServer(hostip, port);
		
	cout << server->ip<< "\n";
}
