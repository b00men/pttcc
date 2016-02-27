/*
 * NetHost.h: File that provides headers for the Network communication implementation
 */

#ifdef __cplusplus
extern "C" {
#endif

#ifndef _nethost

#define _nethost

//structure of an incoming client connection
typedef struct netclienttag
{
	int fd;
	char *ip;
	unsigned short port;
}nethost;

//writes the datalength bytes to data. make sure void* has space, of course
void writeToHost(nethost *host, void *data, size_t datalength);

//reads from the client the specified datalength bytes(will wait until it reads the whole amount), and puts returns the contents buff
void * readFromHost(nethost *host, size_t datalength);

//creates a nethost
nethost *createNetHost(int client, char *IPAddress, unsigned short netport);

//destroys a nethost
void destroyNetHost(nethost *nclient);

#endif

#ifdef __cplusplus
}
#endif
