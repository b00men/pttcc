/*
 * vsnp.h: header file dor describing the VSNP protocol messages
 */

// sip_message = start_line message_headers* body
//

//typedef struct start_line_tag
//{
//	char *method;
//	char *request_URI;
//	char *version;
//	short status_code;
//	char *reason_phrase;
//}start_line_s;

//typedef struct header_field_tag
//{
//	char *name;
//	char *value;
//}header_field;

typedef struct vsnp_packet_tag
{
	unsigned short *id;
	unsigned short *number;
}vsnp_packet;
