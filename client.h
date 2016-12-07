#include "main.h"

#define CLIENT_STATE_INITIAL 1
#define CLIENT_STATE_SENTREQUEST 2
#define CLIENT_STATE_REQUEST_ACCEPTED 3
#define CLIENT_STATE_PING_SENT 4
#define CLIENT_STATE_CONNECTED 5
#define CLIENT_STATE_PONG_RECEIVED 6
#define CLIENT_STATE_SEND_PING 7
#define CLIENT_STATE_REQUEST_TUNNEL 8
#define CLIENT_STATE_WAIT_FOR_ACKTUNNEL 9
#define CLIENT_STATE_FORWARDING 10
#define CLIENT_STATE_SHUTDOWN 11
#define CLIENT_STATE_BIND_PORT 12
#define CLIENT_STATE_SETUP_PIPE 13

int handle_pong_frame(protocol_frame *rcvd_frame);
int handle_acktunnel_frame(protocol_frame *rcvd_frame);
int handle_server_tcp_frame(protocol_frame *rcvd_frame);
int handle_server_tcp_fin_frame(protocol_frame *rcvd_frame);
int do_client_loop(unsigned char *tox_id_str);
