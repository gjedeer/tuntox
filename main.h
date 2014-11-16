#ifndef _MAIN_H
#define _MAIN_H

#include <arpa/inet.h>
#include <errno.h>
#include <netdb.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>
#include <time.h>
#include <tox/tox.h>
#include <unistd.h>

#include "util.h"
#include "uthash.h"

#define READ_BUFFER_SIZE 1024

#define PROTOCOL_MAGIC_V1 0xa26a
#define PROTOCOL_MAGIC PROTOCOL_MAGIC_V1
#define PROTOCOL_MAGIC_HIGH (PROTOCOL_MAGIC >> 8)
#define PROTOCOL_MAGIC_LOW (PROTOCOL_MAGIC & 0xff)
#define PACKET_TYPE_PONG 0x0100
#define PACKET_TYPE_PING 0x0108
#define PACKET_TYPE_REQUESTTUNNEL 0x0602
#define PACKET_TYPE_ACKTUNNEL 0x0610
#define PACKET_TYPE_TCP  0x0600
#define PACKET_TYPE_TCP_FIN  0x0601

#define INT16_AT(array,pos) ( (*((array)+(pos)))*256 + (*((array)+(pos)+1)) )
#define BYTE2(number) (((number) / 256) & 0xff)
#define BYTE1(number) ((number)&0xff)

/* Offset of the data buffer in the packet */
#define PROTOCOL_BUFFER_OFFSET 8
#define PROTOCOL_MAX_PACKET_SIZE (READ_BUFFER_SIZE + PROTOCOL_BUFFER_OFFSET)

typedef struct tunnel_t {
	/* The forwarded socket fd */
	int sockfd;
	/* Connection ID, must be int because of uthash */
	int connid;
	/* Friend number of remote end */
	int32_t friendnumber;

	UT_hash_handle hh;
} tunnel;

typedef struct protocol_frame_t {
	uint32_t friendnumber;

	/* Fields actually found in the protocol */
	uint16_t magic;
	uint16_t packet_type;
	uint16_t connid;
	uint16_t data_length;
	const uint8_t *data;
} protocol_frame;


/**** GLOBAL VARIABLES ****/
extern Tox *tox;
/* Whether we're a client */
extern int client_mode;
/* Just send a ping and exit */
extern int ping_mode;
/* Open a local port and forward it */
extern int client_local_port_mode;
/* Forward stdin/stdout to remote machine - SSH ProxyCommand mode */
extern int client_pipe_mode;
/* Remote Tox ID in client mode */
extern char *remote_tox_id;
/* Ports and hostname for port forwarding */
extern int remote_port;
extern char *remote_host;
extern int local_port;

extern int select_nfds;

int parse_lossless_packet(void *sender_uc, const uint8_t *data, uint32_t len);
#endif
