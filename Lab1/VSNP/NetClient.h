/*
 * NetClient.h: File that provides headers for the Network client implementation
 */

#include "NetHost.h"

#ifdef __cplusplus
extern "C" {
#endif

//function to connect to a server
nethost *connectToServer(char *host, unsigned short port);

#ifdef __cplusplus
}
#endif
