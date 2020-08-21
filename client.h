#include "main.h"

enum CLIENT_STATE {
    CLIENT_STATE_AWAIT_FRIENDSHIP,
    CLIENT_STATE_AWAIT_FRIEND_CONNECTED,
    CLIENT_STATE_AWAIT_PONG,
    CLIENT_STATE_AWAIT_TUNNEL,
    CLIENT_STATE_CONNECTED
};

int handle_pong_frame();
int handle_acktunnel_frame(protocol_frame *rcvd_frame);
int handle_server_tcp_frame(protocol_frame *rcvd_frame);
int handle_server_tcp_fin_frame(protocol_frame *rcvd_frame);
int do_client_loop(uint8_t *tox_id_str);
