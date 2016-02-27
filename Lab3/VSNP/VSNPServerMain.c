
#include <stdio.h>
#include "NetServer.h"

#include <netinet/in.h>

#include <limits.h>
#include <stdlib.h>

#include <time.h>

unsigned short fortuneCookie(unsigned short seed, unsigned char correct)
{
	unsigned char even = 1 - (unsigned char)(seed & 1);
	unsigned short cookie;
	while(1)
	{
		srand(time(NULL)*seed);
		cookie = rand() % USHRT_MAX;
		if(!correct) break; //if we don't care about the property
		if(even && (cookie & 1)) // if even and cookie oddd
			break;
		else if(!even && !(cookie & 1))//if odd and cookie even
			break;
	}
	return cookie;
}

void serviceToClient(nethost *client, unsigned char faults)
{
	void *buff;
	int read = 0;
	unsigned short number = 0;
	unsigned short ID;
	unsigned short *response;
	printf("Client: %s, Port:%i ",client->ip, client->port);
	buff = readFromHost(client, 2);
	ID = ntohs(*((unsigned short*)(buff)));
	if(((faults & 2) == 2) && (rand() % 2)) //if the second bit is on, inject ID faults randomly
		ID = ID + 1; //simple bug here :)
	printf("ID: %hu ", ID);
	number = fortuneCookie(ID, 1 - (faults & 1)); //send correctnes selection
	printf("Number: %hu\n", number);
	if(faults < 4 || (faults > 4 && rand() % 2))//if faults > 4 and randomly (binary) drop connections before replying
	{
		response = (unsigned short*)malloc(2*sizeof(unsigned short));
		*response = (unsigned short)htons(ID);
		*(response + 1) = (unsigned short)htons(number);
		writeToHost(client, response, 4);
		free(response);
	}
	free(buff);
}

#define PARAMERR 5

int main(int argc, char **argv)
{
	const char *serviceIP = "127.0.0.1";
	unsigned short servicePort = 1010;
	unsigned char errors = 0; //no errors by default
	struct sockaddr_in serv_addr; 
	int i;
	const char *help = "Usage: VSNPServer <-s serviceIP> [-p ServicePort]\n\tServiceIP is the Ipv4 address that the server will serve connections\n\tservicePort is the TCP port that the server serves connections (optional parameter, default 1010)\n\tExample VSNP -s 192.168.1.112; VSNP -s 127.0.0.1 1001\n\n";
	
	if (argc < 3)
	{
		printf("Error! At least the service IP to serve connections should be specified");
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
			serviceIP = argv[i];
			if(inet_pton(AF_INET, serviceIP, &serv_addr.sin_addr)<=0)
			{
				printf("Error! host ip: %s not in the correct form, it should be aaa.bbb.ccc.ddd, e.g., -s 172.16.12.13\n", serviceIP );
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
			if (sscanf(argv[i],"%hd", &servicePort) != 1)
			{
				printf("Error! could not read the port: %s as an unsigned short", argv[i]);
				printf("%s", help);
				exit(PARAMERR);
			}
		}
		else if(!strcmp(argv[i], "-e"))
		{	
			if(i + 1 >= argc)
			{
				printf("Error! after the -e flag an error type should follow\n");
				printf("%s", help);
				exit(PARAMERR);
			}
			i++;
			if (sscanf(argv[i],"%hhu", &errors) != 1)
			{
				printf("Error! could not read the error: %s as an unsigned char", argv[i]);
				printf("%s", help);
				exit(PARAMERR);
			}
			if(errors > 7)
			{
				printf("Error! Errors should be a number between 0 and 7", argv[i]);
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
		
	if(!serviceIP)
	{
		printf("Error! The server IP should be provided!\n");
		printf("%s", help);
		exit(PARAMERR);
	}

	serveClients(serviceToClient, serviceIP, servicePort, errors);
}
