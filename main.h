#ifndef _MAIN_H
#define _MAIN_H

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <netdb.h>
#include <netinet/in.h>
#include <pwd.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/types.h>
#include <syslog.h>
#include <time.h>
#include <tox/tox.h>
#include <unistd.h>

#include "util.h"
#include "uthash.h"
#include "utlist.h"


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
#define INT32_AT(array,pos) ( (*((array)+(pos)))*256*256*256 + (*((array)+(pos)+1))*256*256 +(*((array)+(pos)+2))*256 + (*((array)+(pos)+3)) )
#define BYTE1(number) ((number)&0xff)
#define BYTE2(number) (((number) / 256) & 0xff)
#define BYTE3(number) (((number) / (256*256)) & 0xff)
#define BYTE4(number) (((number) / (256*256*256)) & 0xff)

/* Offset of the data buffer in the packet */
#define PROTOCOL_BUFFER_OFFSET 8
#define READ_BUFFER_SIZE TOX_MAX_CUSTOM_PACKET_SIZE - PROTOCOL_BUFFER_OFFSET
#define PROTOCOL_MAX_PACKET_SIZE (READ_BUFFER_SIZE + PROTOCOL_BUFFER_OFFSET)


typedef struct tunnel_t {
    /* The forwarded socket fd */
    int sockfd;
    /* Connection ID, must be int because of uthash */
    int connid;
    /* Friend number of remote end */
    uint32_t friendnumber;

    UT_hash_handle hh;
} tunnel;

typedef struct tunnel_list_t {
    tunnel *tun;
    struct tunnel_list_t *next;
} tunnel_list;

typedef struct allowed_toxid {
    uint8_t toxid[TOX_ADDRESS_SIZE];
    struct allowed_toxid *next;
} allowed_toxid;

typedef struct protocol_frame_t {
    uint32_t friendnumber;

    /* Fields actually found in the protocol */
    uint16_t magic;
    uint16_t packet_type;
    uint16_t connid;
    uint16_t data_length;
    uint8_t *data;
} protocol_frame;

/* A list of local port forwards (listen locally, forward to server */
typedef struct local_port_forward_t {
    int local_port;
    char *remote_host;
    int remote_port;

    /* Sock representing the local port - call accept() on it */
    int bind_sockfd;

    /* Client mode tunnel object for this port forward */
    tunnel *tun;

    /* When the forward has been created - used in ack timeouts */
    time_t created;

    /* ID - used to identify the ack frame */
    uint32_t forward_id;

    struct local_port_forward_t *next;
} local_port_forward;

/* Rules policy */
enum rules_policy_enum { VALIDATE, NONE };
typedef struct rule {
    uint16_t port;
    char * host;
    struct rule *next;
} rule;

/**** GLOBAL VARIABLES ****/
extern Tox *tox;
/* Whether we're a client */
extern int client_mode;
/* Just send a ping and exit */
extern int ping_mode;
/* TOX_CONNECTION global variable */
extern TOX_CONNECTION connection_status;
/* Open a local port and forward it */
extern int client_local_port_mode;
/* Forward stdin/stdout to remote machine - SSH ProxyCommand mode */
extern int client_pipe_mode;
/* Remote Tox ID in client mode */
extern uint8_t *remote_tox_id;
/* Ports and hostname for port forwarding */
extern int remote_port;
extern char *remote_host;
extern int local_port;
/* Shared secret used for authentication */
extern int use_shared_secret;
extern char shared_secret[TOX_MAX_FRIEND_REQUEST_LENGTH];

extern int select_nfds;
extern tunnel *by_id;

extern local_port_forward *local_port_forwards;
extern local_port_forward *pending_port_forwards;

void parse_lossless_packet(Tox *tox, uint32_t friendnumber, const uint8_t *data, size_t len, void *tmp);
tunnel *tunnel_create(int sockfd, int connid, uint32_t friendnumber);
void tunnel_delete(tunnel *t);
void update_select_nfds(int fd);
int send_frame(protocol_frame *frame, uint8_t *data);
int send_tunnel_request_packet(char *remote_host, int remote_port, uint32_t local_forward_id, int friend_number);

void print_version(void);
#endif
