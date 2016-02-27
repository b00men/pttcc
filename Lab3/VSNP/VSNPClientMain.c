
#include <stdio.h>
#include "NetClient.h"

#include <netinet/in.h>
#include <string.h>
#include <limits.h>
#include <stdlib.h>

#include <time.h>

#define PARAMERR 5

int main(int argc, char **argv) 
{
	char *hostip = NULL;
	const char *help = "Usage: VSNPClient <-s serverIP> [-p ServerPort]\n\tServerIP is the Ipv4 address of the VSNP\n\tserverPort is the TCP port that the server serves connections (optional parameter, default 1010)\n\tExample VSNP -s 192.168.1.112; VSNP -s 127.0.0.1 1001\n\n";
	unsigned short port = 1010;	
	struct sockaddr_in serv_addr; 
	int i = 0;
	unsigned short ID;
	unsigned short number;
	unsigned short *data;
	nethost *server;

	if (argc < 3)
	{
		printf("Error! At least the server to connect should be specified");
		printf("%s", help);
		exit(PARAMERR);
	}

	serv_addr.sin_family = AF_INET;

	for(i = 1; i < argc; i++)	
	{
		if(!strcmp(argv[i], "-s"))
		{	
			if(i + 1 >= argc)
			{
				printf("Error! after the -s flag an IP address should follow, e.g., -s 192.168.1.1\n");
				printf("%s", help);
				exit(PARAMERR);
			}
			i++;
			hostip = argv[i];
			if(inet_pton(AF_INET, hostip, &serv_addr.sin_addr)<=0)
			{
				printf("Error! host ip: %s not in the correct form, it should be aaa.bbb.ccc.ddd, e.g., -s 172.16.12.13\n", hostip);
				printf("%s", help);
				exit(PARAMERR);
			}	

			
		}
		else if(!strcmp(argv[i], "-p"))
		{	
			if(i + 1 >= argc)
			{
				printf("Error! after the -p flag a tcp port number should follow, e.g., -p 1111\n");
				printf("%s", help);
				exit(PARAMERR);
			}
			i++;
			if (sscanf(argv[i],"%hd", &port) != 1)
			{
				printf("Error! could not read the port: %s as an unsigned short", argv[i]);
				printf("%s", help);
				exit(PARAMERR);
			}
		}
		else 
		{
			printf("Error! Unrecognized parameter %s\n", argv[i]);
			printf("%s", help);
			exit(PARAMERR);
		
		}
	}
		
	if(!hostip)
	{
		printf("Error! The server IP should be provided!\n");
		printf("%s", help);
		exit(PARAMERR);
	}
	server = connectToServer(hostip, port);
	srand(time(NULL));
	ID = rand() % USHRT_MAX; 
	printf("ID: %hu \n", ID);	
	data = (unsigned short*)malloc(1*sizeof(unsigned short));
	*data = htons(ID);
	
	writeToHost(server, data, sizeof(ID));

	data = (unsigned short*)readFromHost(server, 4);
	data = data + 1;
	number = ntohs(*data); 
	//shoud check in here the id concides, but, well...
	printf("VSNP Number: %hu\n", number);
}
