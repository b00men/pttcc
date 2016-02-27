/*
 * NetServer.h: File that provides headers for the Network server implementation
 */

#include "NetHost.h"

#ifdef __cplusplus
extern "C" {
#endif

//function that calls the servicefunc on each new client that request service
void serveClients(void (*servicefunc)(nethost*, unsigned char), const char *host, unsigned short port, unsigned char errors);

#ifdef __cplusplus
}
#endif
