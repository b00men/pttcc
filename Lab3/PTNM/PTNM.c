#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>
#include <arpa/inet.h>
#include <string.h>
#include <ctype.h>
#include <pthread.h>	
#include <unistd.h>

#include "helpers.h"
#include "linked_list.h"
#include "PTNM.h"

#define DEBUG 0

#define CRLF "\r"

/**
 * create_string_from_text_payload: copies all data to a char* to manipulate the string
 * USEFUL for all TEXT BASED PROTOCOLS
 */

char *create_string_from_text_payload(u_char *payload, int size)
{
	
	char *string_form = (char*)malloc(size + 1);
	int i = 0;
	for (i; i < size; i++)
		*(string_form + i) = *(payload + i);
	*(string_form + i) = 0;
	return string_form;
}

void release_sip(sip_packet *sip)
{
	char *start_of_text = (sip->start_line->method)?sip->start_line->method:sip->start_line->version;
	free(start_of_text);
	free(sip->start_line);
	while(sip->header_fields->head)
		free(linked_list_delete(sip->header_fields));
	linked_list_delete(sip->header_fields);
	//not free sip->message_body, since message boddy is part of the main start of text when allocating.
	free(sip);
}

void release_vsnp(vsnp_packet *vsnp)
{
	free(vsnp);
}

/*
 * proccess_sip: process the payload and convert it to a sip struct
 */

sip_packet *process_sip(u_char *payload, int payload_size)
{
	char* sip_text = create_string_from_text_payload(payload, payload_size);
	char *message_body, *temp_string;
	char *start_line_text = strtok_r(sip_text, CRLF, &message_body);
	int size = 0, i = 0;
	char *save_ptr = NULL;
	start_line_s *message_start_line =(start_line_s*)malloc(sizeof(start_line_s)); 
	linked_list *header_fields = create_linked_list();
	linked_list *header_fields_text = create_linked_list();
	sip_packet *sip = (sip_packet*)malloc(sizeof(sip_packet));	
	void *header_field_value;

	#define MIN_SIP_TEXT_LENGTH 7 //at least if should have SIP/x.y version in the string text, else this is a corrupt package.

	if(strlen(sip_text) < MIN_SIP_TEXT_LENGTH)
	{
		free(sip_text);
		free(message_start_line);
		linked_list_delete(header_fields);	
		linked_list_delete(header_fields_text);
		free(sip);
		return NULL;
	}

	while (temp_string  = strtok_r(NULL, CRLF, &message_body))
	{	
		//Since splitting will leave \n at the begining I'll remove this \n
		if(*temp_string == '\n') temp_string++;
		//When only a newline is present, futher removed, that means the body message is up next.
		if (strcmp(temp_string, "") == 0) break;
		//here I just make sure folding won't affect my application
		if (!isspace(*temp_string)) 
			linked_list_add(header_fields_text, temp_string);
		else //I need to add the content to the previous header field
			strcat(((char*)linked_list_get(header_fields_text)), temp_string);
	}
	
	temp_string = strtok_r(start_line_text, " ", &save_ptr);

	if(strcasecmp(temp_string, "REGISTER") == 0 || strcasecmp(temp_string, "INVITE") == 0 || strcasecmp(temp_string, "ACK") == 0 || strcasecmp(temp_string, "CANCEL") == 0 || strcasecmp(temp_string, "BYE") == 0 || strcasecmp(temp_string, "OPTIONS") == 0 || strcasecmp(temp_string, "SUBSCRIBE") == 0 || strcasecmp(temp_string, "NOTIFY") == 0 ) // http://tools.ietf.org/html/rfc3261#page-26 request methods definition and extension http://www.ietf.org/rfc/rfc3265.txt
	{

		message_start_line->method = temp_string;	
		message_start_line->request_URI = strtok_r(NULL, " ", &save_ptr);
		message_start_line->version = save_ptr;
		message_start_line->status_code = 0;;
		message_start_line->reason_phrase = NULL;
	}
	else // it is status line actually
	{
		message_start_line->method= NULL;
		message_start_line->request_URI = NULL;
		message_start_line->version = temp_string;
		message_start_line->status_code = (short)atoi(strtok_r(NULL, " ", &save_ptr));
		message_start_line->reason_phrase = save_ptr;
	}

	if (linked_list_transverse(header_fields_text, &header_field_value))
	{
		header_field *headerfield = (header_field*)malloc(sizeof(header_field) * 1);
		headerfield->name = strtok_r((char*)header_field_value, ":", (char**)&headerfield->value);
		strtrim(&headerfield->name);
                strtrim(&headerfield->value);
                linked_list_add(header_fields, headerfield);
	}
	while (linked_list_transverse(NULL, &header_field_value))	
	{
		header_field *headerfield = (header_field*)malloc(sizeof(header_field) * 1);
		headerfield->name = strtok_r((char*)header_field_value, ":", (char**)&headerfield->value);
		strtrim(&headerfield->name);
		strtrim(&headerfield->value);
		linked_list_add(header_fields, headerfield);
	}
	delete_linked_list(header_fields_text);

	strtrim(&message_body);

	sip->start_line = message_start_line;
	sip->header_fields = header_fields;
	sip->message_body = message_body;

	return sip;
}

vsnp_packet *process_vsnp(u_char *payload, int payload_size)
{
	vsnp_packet *vsnp = (vsnp_packet*)malloc(sizeof(vsnp_packet));
	vsnp->answer = 0;
	if(payload_size == 0)
	{
		free(vsnp);
		return NULL;
	}
	unsigned short id = ntohs(*((unsigned short*)(payload)));
	vsnp->id = &id;
	if(payload_size > 2)
	{
		vsnp->answer = 1;
		unsigned short number = ntohs(*((unsigned short*)(payload)+1));
		vsnp->number = &number;
	}
	return vsnp;
}

void print_sip(sip_packet *sip)
{
	int i = 0;
	void *header_field_value;
	linked_list *header_fields = sip->header_fields;
	
	if(!DEBUG)
		return;
	
	if (sip->start_line->method != NULL)
		printf("Method: %s Request_URI: %s Version: %s\n", sip->start_line->method, sip->start_line->request_URI, sip->start_line->version);
	else
		printf("Version: %s Status Code: %i Reason Phrase: %s\n", sip->start_line->version, sip->start_line->status_code, sip->start_line->reason_phrase);

	if(linked_list_transverse(sip->header_fields, &header_field_value))
	{
		header_field *headerfield = (header_field*)header_field_value;
		printf("%s->%s\n", headerfield->name, headerfield->value);
	}

	while (linked_list_transverse(NULL, &header_field_value))
        {
                header_field *headerfield = (header_field*)header_field_value;
                printf("%s->%s\n", headerfield->name, headerfield->value);
        }

	printf("\n%s\n", sip->message_body);
}

/*function log_sip: fairly similar to print_sip, but, to a file... the writeable FP is needed*/

const char *separator = "=====================================================================================================================";

/*
 * release_packet: frees packet resources if no longer needed.
 */
void release_packet(packet* packet)
{
	free(packet->time);

        switch(packet->protocol_type)
        {   
                case SIP:
			if(packet->protocol_type)
                        	release_sip((sip_packet*)packet->protocol);
                        break;
                case DNS:
                        release_sip((sip_packet*)packet->protocol);
                        break;
                default:
                        //LOG THIS!
                break;
        }	
	
	free(packet);
}


/*
 * size_of_char_rep: function to calculate number size on string representation
 */
int size_of_char_rep(unsigned long long number)
{
	int size = 1;
	while ((number /= 10) > 0)
		size++;
	return size;
}

struct timeval *last_observed_time; //last observed time
pthread_mutex_t *last_observed_time_lock; //to guarantee thread safe of time reading and writing.


/*implement me*/

void check_properties(packet *pkt)
{
	if(pkt->protocol_type == VSNP)
	{
		vsnp_packet *vsnp;
		vsnp = pkt->protocol;
		if (vsnp == NULL) return;
		//Monitoring
		if (vsnp->answer) printf("ID: %hu, Num: %hu\n", *(vsnp->id), *(vsnp->number));
		else printf("ID: %hu \n", *(vsnp->id));
	}
}
 

/*
 * process_packet: function that processes each packet
 */

void process_packet(u_char *args, const struct pcap_pkthdr *pkthdr, const u_char *pkt)
{
	static int count = 0;
	static struct timeval *offset;
	struct timeval *result, *time; 
	ethernet_h *ether = NULL;
	ip4 *ip = NULL;
	char ip_source[INET_ADDRSTRLEN], ip_dest[INET_ADDRSTRLEN];
	packet *message = (packet*)malloc(sizeof(packet));
	u_char *payload;
	tcph *tcp = NULL;
	udph *udp = NULL;
	sip_packet *sip = NULL;
	vsnp_packet *vsnp = NULL;
	transport_e packet_transport;
	protocol_e packet_protocol;
	unsigned short sport, dport;

	if(count == 0)
	{
		offset = (struct timeval*)malloc(sizeof(struct timeval));
		offset->tv_sec = pkthdr->ts.tv_sec;
		offset->tv_usec = pkthdr->ts.tv_usec;
	}
	
	result = (struct timeval*)malloc(sizeof(struct timeval));
	time = (struct timeval*)&pkthdr->ts;
		
	timeval_substract(result,time,offset);

	pthread_mutex_lock(last_observed_time_lock);
	last_observed_time->tv_sec = result->tv_sec;
	last_observed_time->tv_usec = result->tv_usec;
	pthread_mutex_unlock(last_observed_time_lock);

	if (pkthdr->len < ETHERNET_HEADER_SIZE)
	{
		//printf("We found VSNP!\n");
		//LOG this!
		return;
	}

	ether = (ethernet_h*)pkt;
	if (ether->ether_type != ETHERNET_IPv4_TYPE)
	{
		//LOG this!
		return;
	}
	
	ip = (ip4*)(pkt + ETHERNET_HEADER_SIZE);
		
	//Leaving this here for future PO cathegorization... 
	inet_ntop(AF_INET, &ip->ip_src, ip_source, INET_ADDRSTRLEN);
	inet_ntop(AF_INET, &ip->ip_dst, ip_dest, INET_ADDRSTRLEN);

	if (ip->ip_p == IP_PROTO_UDP)
	{
		udp = (udph*)(pkt + ETHERNET_HEADER_SIZE + (IP_HL(ip) * 4)); //* 4 because size expressed in 32bit 
		payload = (u_char*)(pkt + ETHERNET_HEADER_SIZE + (IP_HL(ip) * 4) + UDP_HEADER_SIZE); //* 4 because size expressed in 32bit  
		packet_transport = UDP;
	}	 
	else if (ip->ip_p == IP_PROTO_TCP)
	{
		tcp = (tcph*)(pkt + ETHERNET_HEADER_SIZE + (IP_HL(ip) * 4)); //* 4 because size expressed in 32bit 
		payload = (u_char*)(pkt + ETHERNET_HEADER_SIZE + (IP_HL(ip) * 4) + (TH_OFF(tcp) * 4)); //* 4 because size expressed in 32bit 
		packet_transport = TCP;
	}
	else
	{
		//LOG this!
		return;
	}

	//printf("%d) length=%d time=%d.%d. from:%s:%d to:%s:%d transport:%s \n", ++count, pkthdr->len, result->tv_sec, result->tv_usec, ip_source, ntohs((udp)?udp->uh_sport:tcp->th_sport), ip_dest, ntohs((udp)?udp->uh_dport:tcp->th_dport), (udp)?"UDP":"TCP"); //interested in all packets?
	//The previous line can be used for debug... it is priceless
	
	//WHERE TO SEND THIS? I mean choose depending on ports and so on.. let's do it based on ports for now
	sport = ntohs((udp)?udp->uh_sport:tcp->th_sport);
	dport = ntohs((udp)?udp->uh_dport:tcp->th_dport);
	if(sport == 5060 || dport == 5060)
	{
		packet_protocol = SIP;
		sip = process_sip(payload, pkthdr->len - (payload - pkt));	
	}
	if(sport == 1010 || dport == 1010)
	{
		packet_protocol = VSNP;
		vsnp = process_vsnp(payload, pkthdr->len - (payload - pkt));	
	}
	//here you should add the VSNP port 
	else if(packet_transport == TCP)
	{
		packet_protocol = GENTCP; //generic TCP
		//process not payload
	}
	else if(packet_transport == UDP)
	{
		packet_protocol = GENUDP;
		//process not payload
	}

	message->ethernet = ether;	
	message->ip = ip;
	message->time = result;
	message->transport_type = packet_transport;
	message->protocol_type = packet_protocol;
	message->location_in_trace = ++count;
	message->reference_count = 0;
		
	switch(packet_transport)
	{
		case UDP:	
			message->transport = udp;
			break;
		default:
			message->transport = tcp;
	}

	switch(packet_protocol)
	{
		case SIP:
			message->protocol = sip;
			break;
		case VSNP:
			message->protocol = vsnp;
			break;
		//add new protocols
		default:
			//printf("We found new proto!\n");
			break;
	}

	check_properties(message);

	release_packet(message);//we are done with this packet
}

int main(int argc, char *argv[])
{
	char *devname = argv[1];
	char *errbuff = (char *) malloc(PCAP_ERRBUF_SIZE); 
	struct pcap_pkthdr *header;
	struct bpf_program fp;
	const u_char *payload;
	pthread_mutex_t *lock;

	pcap_t *handler;
	
	if (!(handler = pcap_open_offline(devname,errbuff)))
		 handler = pcap_open_live(devname, BUFSIZ, 1, 1000, errbuff);

	if (handler == NULL)
	{
		printf("Error while opening %s is not a valid filename or device, error: \n\t%s\n", devname, errbuff);
		exit(2);
	}

	if (pcap_compile(handler, &fp, argv[2], 0, PCAP_NETMASK_UNKNOWN) == -1)
	{
		printf("Couldn't parse filter \"%s\": %s\n", argv[2], pcap_geterr(handler));
		exit(2);
	}
 	if (pcap_setfilter(handler, &fp) == -1) 
	{
		printf("Couldn't install filter %s: %s\n", argv[2], pcap_geterr(handler));
		exit(2);
	}

	last_observed_time = (struct timeval*)malloc(1 * sizeof(struct timeval));
	last_observed_time->tv_sec = 0;
	last_observed_time->tv_usec = 0;
	last_observed_time_lock = (pthread_mutex_t*)malloc(1 * sizeof(pthread_mutex_t));
	pthread_mutex_init(last_observed_time_lock, NULL);
	
	if (pcap_loop(handler, -1, &process_packet, NULL) == -1)
		printf("Error occurred in capture!\n%s", pcap_geterr(handler));
	
	return 0;
}
