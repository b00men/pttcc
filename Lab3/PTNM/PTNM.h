
/*
 * runmon.h: define runmun structures
 */
#include "ethernet.h"
#include "ip4.h"
#include "tcp.h"
#include "udp.h"
#include "sip.h"
#include "vsnp.h"

#ifdef __cplusplus
extern "C" {
#endif

#define CURRENT_STATUS_FAIL -1
#define CURRENT_STATUS_PASS 1
#define CURRENT_STATUS_INCONCLUSIVE 0


typedef enum transport_e_tag
{
	TCP = 0,	
	UDP = 1	
}transport_e;

typedef enum protocol_e_tag
{
	SIP = 0,
	DNS = 1,
	GENUDP = 2,
	GENTCP = 3,
	VSNP = 4
}protocol_e;

typedef struct runmon_packet_tag
{
	ethernet_h *ethernet;
	ip4 *ip;
	void *transport;
	void *protocol;
	transport_e transport_type;
	protocol_e protocol_type;
	struct timeval *time; 	
	int location_in_trace;
	int reference_count;
}packet;

typedef struct element_tag
{
        unsigned short *id;
        void *prev;
        void *next;
}element;

typedef struct deque_tag
{
        element *head;   // указатель на начало списка
        element *tail;   // указатель на конец списка
        int size;
}deque;

#ifdef __cplusplus
}
#endif
