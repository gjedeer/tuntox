#include "main.h"
#include "tox_bootstrap.h"

static Tox_Options tox_options;
static Tox *tox;
int client_socket = 0;

/** CONFIGURATION OPTIONS **/
/* Whether we're a client */
int client_mode = 0;
/* Just send a ping and exit */
int ping_mode = 0;
/* Remote Tox ID in client mode */
char *remote_tox_id = NULL;
/* Ports and hostname for port forwarding */
int remote_port = 0;
char *remote_host = NULL;
int local_port = 0;

/* The state machine */
int state = CLIENT_STATE_INITIAL;

/* Used in ping mode */
struct timespec ping_sent_time;

/* Client mode tunnel */
tunnel client_tunnel;

/* We keep two hash tables: one indexed by sockfd and another by "connection id" */
tunnel *by_id = NULL;
tunnel *by_fd = NULL;

/* Generate an unique tunnel ID. To be used in a server. */
uint16_t get_random_tunnel_id()
{
    while(1)
    {
        int key;
        uint16_t tunnel_id;
        tunnel *tun;

        tunnel_id = (uint16_t)rand();
        key = tunnel_id;

        HASH_FIND_INT(by_id, &key, tun);
        if(!tun)
        {
            return tunnel_id;
        }
        fprintf(stderr, "[i] Found duplicated tunnel ID %d\n", key);
    }
}

/* Constructor. Returns NULL on failure. */
static tunnel *tunnel_create(int sockfd, int connid, uint32_t friendnumber)
{
    tunnel *t = NULL;

    t = calloc(1, sizeof(tunnel));
    if(!t)
    {
        return NULL;
    }

    t->sockfd = sockfd;
    t->connid = connid;
    t->friendnumber = friendnumber;

    HASH_ADD_INT( by_id, connid, t );
    HASH_ADD_INT( by_fd, sockfd, t );

    return t;
}

static void tunnel_delete(tunnel *t)
{
    HASH_DEL( by_id, t );
    HASH_DEL( by_fd, t );
    free(t);
}

static void writechecksum(uint8_t *address)
{
    uint8_t *checksum = address + 36;
    uint32_t i;

    for (i = 0; i < 36; ++i)
	checksum[i % 2] ^= address[i];
}

/* From utox/util.c */
static void to_hex(char_t *a, const char_t *p, int size)
{
    char_t b, c;
    const char_t *end = p + size;

    while(p != end) {
        b = *p++;

        c = (b & 0xF);
        b = (b >> 4);

        if(b < 10) {
            *a++ = b + '0';
        } else {
            *a++ = b - 10 + 'A';
        }

        if(c < 10) {
            *a++ = c + '0';
        } else {
            *a++ = c  - 10 + 'A';
        }
    }
}

/* From utox/util.c */
void id_to_string(char_t *dest, const char_t *src)
{
    to_hex(dest, src, TOX_FRIEND_ADDRESS_SIZE);
}

/* From utox/util.c */
int string_to_id(char_t *w, char_t *a)
{
    char_t *end = w + TOX_FRIEND_ADDRESS_SIZE;
    while(w != end) {
        char_t c, v;

        c = *a++;
        if(c >= '0' && c <= '9') {
            v = (c - '0') << 4;
        } else if(c >= 'A' && c <= 'F') {
            v = (c - 'A' + 10) << 4;
        } else if(c >= 'a' && c <= 'f') {
            v = (c - 'a' + 10) << 4;
        } else {
            return 0;
        }

        c = *a++;
        if(c >= '0' && c <= '9') {
            v |= (c - '0');
        } else if(c >= 'A' && c <= 'F') {
            v |= (c - 'A' + 10);
        } else if(c >= 'a' && c <= 'f') {
            v |= (c - 'a' + 10);
        } else {
            return 0;
        }

        *w++ = v;
    }

    return 1;
}


/* bootstrap to dht with bootstrap_nodes */
/* From uTox/tox.c */
static void do_bootstrap(Tox *tox)
{
    static unsigned int j = 0;

    if (j == 0)
        j = rand();

    int i = 0;
    while(i < 4) {
        struct bootstrap_node *d = &bootstrap_nodes[j % countof(bootstrap_nodes)];
        tox_bootstrap_from_address(tox, d->address, d->port, d->key);
        i++;
        j++;
    }
}

/* Set username to the machine's FQDN */
void set_tox_username(Tox *tox)
{
    unsigned char hostname[1024];
    struct addrinfo hints, *info, *p;
    int gai_result;

    gethostname(hostname, 1024);
    hostname[1023] = '\0';
# if 0
    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_UNSPEC; /*either IPV4 or IPV6*/
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_CANONNAME;

    if ((gai_result = getaddrinfo(hostname, "ftp", &hints, &info)) != 0) 
    {
	    fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(gai_result));
	    exit(1);
    }

    for(p = info; p != NULL; p = p->ai_next) 
    {
	    printf("hostname: %s\n", p->ai_canonname);
    }
# endif

    tox_set_name(tox, hostname, strlen(hostname));

//    freeaddrinfo(info);
}
// get sockaddr, IPv4 or IPv6:
/* From Beej */
void *get_in_addr(struct sockaddr *sa)
{
    if (sa->sa_family == AF_INET) {
        return &(((struct sockaddr_in*)sa)->sin_addr);
    }

    return &(((struct sockaddr_in6*)sa)->sin6_addr);
}

/* From Beej */
int get_client_socket(char *hostname, int port)
{
    int sockfd, numbytes;  
    char buf[READ_BUFFER_SIZE];
    struct addrinfo hints, *servinfo, *p;
    int rv;
    char s[INET6_ADDRSTRLEN];
    char port_str[6];

    snprintf(port_str, 6, "%d", port);

    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;

    if ((rv = getaddrinfo(hostname, port_str, &hints, &servinfo)) != 0) {
        fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(rv));
        return -1;
    }

    // loop through all the results and connect to the first we can
    for(p = servinfo; p != NULL; p = p->ai_next) {
        if ((sockfd = socket(p->ai_family, p->ai_socktype,
                p->ai_protocol)) == -1) {
            perror("client: socket");
            continue;
        }

        if (connect(sockfd, p->ai_addr, p->ai_addrlen) == -1) {
            close(sockfd);
            perror("client: connect");
            continue;
        }

        break;
    }

    if (p == NULL) {
        fprintf(stderr, "failed to connect to %s:%d\n", hostname, port);
        exit(1);
    }

    inet_ntop(p->ai_family, get_in_addr((struct sockaddr *)p->ai_addr),
            s, sizeof s);
    fprintf(stderr, "connecting to %s\n", s);

    freeaddrinfo(servinfo); // all done with this structure

    fprintf(stderr, "Connected to %s:%d\n", hostname, port);

    return sockfd;
}

/* Proto - our protocol handling */

/* 
 * send_frame: (almost) zero-copy. Overwrites first PROTOCOL_BUFFER_OFFSET bytes of data 
 * so actual data should start at position PROTOCOL_BUFFER_OFFSET
 */
int send_frame(protocol_frame *frame, uint8_t *data)
{
    int rv;

    data[0] = PROTOCOL_MAGIC_HIGH;
    data[1] = PROTOCOL_MAGIC_LOW;
    data[2] = BYTE2(frame->packet_type);
    data[3] = BYTE1(frame->packet_type);
    data[4] = BYTE2(frame->connid);
    data[5] = BYTE1(frame->connid);
    data[6] = BYTE2(frame->data_length);
    data[7] = BYTE1(frame->data_length);

    rv = tox_send_lossless_packet(
            tox,
            frame->friendnumber,
            data,
            frame->data_length + PROTOCOL_BUFFER_OFFSET
    );

    if(rv < 0)
    {
        fprintf(stderr, "Failed to send packet to friend %d\n", frame->friendnumber);
    }

    return rv;
}

int handle_ping_frame(protocol_frame *rcvd_frame)
{
    uint8_t data[TOX_MAX_CUSTOM_PACKET_SIZE];
    protocol_frame frame_s;
    protocol_frame *frame = &frame_s;

    frame->data = data + PROTOCOL_BUFFER_OFFSET;
    memcpy(frame->data, rcvd_frame->data, rcvd_frame->data_length);

    frame->friendnumber = rcvd_frame->friendnumber;
    frame->packet_type = PACKET_TYPE_PONG;
    frame->data_length = rcvd_frame->data_length;
    
    send_frame(frame, data);
}

int handle_pong_frame(protocol_frame *rcvd_frame)
{
    struct timespec pong_rcvd_time;
    double secs1, secs2;

    clock_gettime(CLOCK_MONOTONIC, &pong_rcvd_time);

    secs1 = (1.0 * ping_sent_time.tv_sec) + (1e-9 * ping_sent_time.tv_nsec);
    secs2 = (1.0 * pong_rcvd_time.tv_sec) + (1e-9 * pong_rcvd_time.tv_nsec);

    printf("GOT PONG! Time = %.3fs\n", secs2-secs1);

    if(ping_mode)
    {
//        state = CLIENT_STATE_PONG_RECEIVED;
        state = CLIENT_STATE_SEND_PING;
    }
}

int handle_request_tunnel_frame(protocol_frame *rcvd_frame)
{
    char *hostname = NULL;
    tunnel *tun;
    int port = -1;
    int sockfd = 0;
    uint16_t tunnel_id;

    if(client_mode)
    {
        fprintf(stderr, "Got tunnel request frame from friend #%d when in client mode\n", rcvd_frame->friendnumber);
        return -1;
    }
    
    port = rcvd_frame->connid;
    hostname = calloc(1, rcvd_frame->data_length + 1);
    if(!hostname)
    {
        fprintf(stderr, "Could not allocate memory for tunnel request hostname\n");
        return -1;
    }

    strncpy(hostname, rcvd_frame->data, rcvd_frame->data_length);
    hostname[rcvd_frame->data_length] = '\0';

    printf("Got a request to forward data from %s:%d\n", hostname, port);

    tunnel_id = get_random_tunnel_id();
    printf("Tunnel ID: %d\n", tunnel_id);
    /* TODO make connection */
    sockfd = get_client_socket(hostname, port);
    if(sockfd > 0)
    {
        tun = tunnel_create(sockfd, tunnel_id, rcvd_frame->friendnumber);
        if(tun)
        {
            fprintf(stderr, "Created tunnel, yay!\n");
            /* TODO send ack */
        }
        else
        {
            fprintf(stderr, "Couldn't allocate memory for tunnel\n");
        }
    }
    else
    {
        fprintf(stderr, "Could not connect to %s:%d\n", hostname, port);
        /* TODO send reject */
    }

}

/* This is a dispatcher for our encapsulated protocol */
int handle_frame(protocol_frame *frame)
{
    switch(frame->packet_type)
    {
        case PACKET_TYPE_PING:
            return handle_ping_frame(frame);
            break;
        case PACKET_TYPE_PONG:
            return handle_pong_frame(frame);
            break;
        case PACKET_TYPE_TCP:
            break;
        case PACKET_TYPE_REQUESTTUNNEL:
            handle_request_tunnel_frame(frame);
            break;
        default:
            fprintf(stderr, "Got unknown packet type 0x%x from friend %d\n", 
                    frame->packet_type,
                    frame->friendnumber
            );
    }

    return 0;
}

/* 
 * This is a callback which gets a packet from Tox core.
 * It checks for basic inconsistiencies and allocates the
 * protocol_frame structure.
 */
int parse_lossless_packet(void *sender_uc, const uint8_t *data, uint32_t len)
{
    protocol_frame *frame = NULL;

    if(len < PROTOCOL_BUFFER_OFFSET)
    {
        fprintf(stderr, "Received too short data frame - only %d bytes, at least %d expected\n", len, PROTOCOL_BUFFER_OFFSET);
        return -1;
    }

    if(data[0] != PROTOCOL_MAGIC_HIGH || data[1] != PROTOCOL_MAGIC_LOW)
    {
        fprintf(stderr, "Received data frame with invalid protocol magic number 0x%x%x\n", data[0], data[1]);
        return -1;
    }

    frame = calloc(1, sizeof(protocol_frame));
    if(!frame)
    {
        fprintf(stderr, "Could not allocate memory for protocol_frame_t\n");
        return -1;
    }

    /* TODO check if friendnumber is the same in sender and connid tunnel*/
    frame->magic =                      INT16_AT(data, 0);
    frame->packet_type =                INT16_AT(data, 2);
    frame->connid =                     INT16_AT(data, 4);
    frame->data_length =                INT16_AT(data, 6);
    frame->data = data + PROTOCOL_BUFFER_OFFSET;
    frame->friendnumber = *((uint32_t*)sender_uc);
    printf("Got protocol frame magic 0x%x type 0x%x from friend %d\n", frame->magic, frame->packet_type, frame->friendnumber);

    if(len < frame->data_length + PROTOCOL_BUFFER_OFFSET)
    {
        fprintf(stderr, "Received frame too small (attempted buffer overflow?): %d bytes, excepted at least %d bytes\n", len, frame->data_length + PROTOCOL_BUFFER_OFFSET);
        return -1;
    }

    if(frame->data_length > (TOX_MAX_CUSTOM_PACKET_SIZE - PROTOCOL_BUFFER_OFFSET))
    {
        fprintf(stderr, "Declared data length too big (attempted buffer overflow?): %d bytes, excepted at most %d bytes\n", frame->data_length, (TOX_MAX_CUSTOM_PACKET_SIZE - PROTOCOL_BUFFER_OFFSET));
        return -1;
    }

    handle_frame(frame);
}

int send_tunnel_request_packet(char *remote_host, int remote_port, int friend_number)
{
    int packet_length = 0;
    protocol_frame frame_i, *frame;
    char *data = NULL;

    fprintf(stderr, "Sending packet to friend #%d to forward %s:%d\n", friend_number, remote_host, remote_port);
    packet_length = PROTOCOL_BUFFER_OFFSET + strlen(remote_host);
    frame = &frame_i;

    data = calloc(1, packet_length);
    if(!data)
    {
        fprintf(stderr, "Could not allocate memory for tunnel request packet\n");
        exit(1);
    }
    strcpy(data+PROTOCOL_BUFFER_OFFSET, remote_host);

    frame->friendnumber = friend_number;
    frame->packet_type = PACKET_TYPE_REQUESTTUNNEL;
    frame->connid = remote_port;
    frame->data_length = strlen(remote_host);

    send_frame(frame, data);

    free(data);
    return 0;
}

/* End proto */

void accept_friend_request(Tox *tox, const uint8_t *public_key, const uint8_t *data, uint16_t length, void *userdata)
{
    unsigned char tox_printable_id[TOX_FRIEND_ADDRESS_SIZE * 2 + 1];
    int32_t friendnumber;
    int32_t *friendnumber_ptr = NULL;

    printf("Got friend request\n");

    friendnumber = tox_add_friend_norequest(tox, public_key);

    id_to_string(tox_printable_id, public_key);
    printf("Accepted friend request from %s as %d\n", tox_printable_id, friendnumber);

    /* TODO: this is not freed right now, we're leaking 4 bytes per contact (OMG!) */
    friendnumber_ptr = malloc(sizeof(int32_t));
    if(!friendnumber_ptr)
    {
        fprintf(stderr, "Could not allocate memory for friendnumber_ptr\n");
        return;
    }

    *friendnumber_ptr = friendnumber;

    tox_lossless_packet_registerhandler(tox, friendnumber, (PROTOCOL_MAGIC_V1)>>8, parse_lossless_packet, (void*)friendnumber_ptr);
}

void cleanup(int status, void *tmp)
{
    printf("kthxbye\n");
    fflush(stdout);
    tox_kill(tox);
    if(client_socket)
    {
	close(client_socket);
    }
}


int do_server_loop()
{
    struct timeval tv;
    fd_set fds;
    fd_set master;
    unsigned char read_buf[READ_BUFFER_SIZE+1];
    unsigned char tox_packet_buf[PROTOCOL_MAX_PACKET_SIZE];

    tv.tv_sec = 0;
    tv.tv_usec = 20000;

    FD_ZERO(&fds);
//    FD_SET(client_socket, &fds);

    master = fds;

    while(1)
    {
	/* Let tox do its stuff */
	tox_do(tox);

	/* Poll for data from our client connection */
	select(client_socket+1, &fds, NULL, NULL, &tv);
	if(FD_ISSET(client_socket, &fds))
	{
	    int nbytes = recv(client_socket, read_buf, READ_BUFFER_SIZE, 0);

	    /* Check if connection closed */
	    if(nbytes == 0)
	    {
		printf("conn closed!\n");
	    }
	    else
	    {
		unsigned int tox_packet_length = 0;
		read_buf[nbytes] = '\0';
		printf("READ: %s\n", read_buf);
	    }
	}

	fds = master;
    }
}

int do_client_loop(char *tox_id_str)
{
    unsigned char tox_packet_buf[PROTOCOL_MAX_PACKET_SIZE];
    unsigned char tox_id[TOX_FRIEND_ADDRESS_SIZE];
    uint32_t friendnumber;

    if(!string_to_id(tox_id, tox_id_str))
    {
        fprintf(stderr, "Invalid Tox ID");
        exit(1);
    }

    fprintf(stderr, "Connecting to Tox...\n");

    while(1)
    {
	/* Let tox do its stuff */
	tox_do(tox);

        switch(state)
        {
            /* 
             * Send friend request
             */
            case CLIENT_STATE_INITIAL:
                if(tox_isconnected(tox))
                {
                    state = CLIENT_STATE_CONNECTED;
                }
                break;
            case CLIENT_STATE_CONNECTED:
                {
                    uint8_t data[] = "Hi, fellow tuntox instance!";
                    uint16_t length = sizeof(data);

                    fprintf(stderr, "Connected. Sending friend request.\n");

                    friendnumber = tox_add_friend(
                            tox,
                            tox_id,
                            data,
                            length
                    );

                    if(friendnumber < 0)
                    {
                        fprintf(stderr, "Error %d adding friend %s\n", friendnumber, tox_id);
                        exit(-1);
                    }

                    tox_lossless_packet_registerhandler(tox, friendnumber, (PROTOCOL_MAGIC_V1)>>8, parse_lossless_packet, (void*)&friendnumber);
                    state = CLIENT_STATE_SENTREQUEST;
                    fprintf(stderr, "Waiting for friend to accept us...\n");
                }
                break;
            case CLIENT_STATE_SENTREQUEST:
                if(tox_get_friend_connection_status(tox, friendnumber) == 1)
                {
                    fprintf(stderr, "Friend request accepted!\n");
                    state = CLIENT_STATE_REQUEST_ACCEPTED;
                }
                else
                {
                }
                break;
            case CLIENT_STATE_REQUEST_ACCEPTED:
                if(ping_mode)
                {
                    state = CLIENT_STATE_SEND_PING;
                }
                else
                {
                    state = CLIENT_STATE_REQUEST_TUNNEL;
                }
                break;
            case CLIENT_STATE_SEND_PING:
                /* Send the ping packet */
                {
                    uint8_t data[] = {
                        0xa2, 0x6a, 0x01, 0x08, 0x00, 0x00, 0x00, 0x05, 
                        0x48, 0x65, 0x6c, 0x6c, 0x6f
                    };

                    clock_gettime(CLOCK_MONOTONIC, &ping_sent_time);
                    tox_send_lossless_packet(
                            tox,
                            friendnumber,
                            data,
                            sizeof(data)
                    );
                }
                state = CLIENT_STATE_PING_SENT;
                break;
            case CLIENT_STATE_PING_SENT:
                /* Just sit there and wait for pong */
                break;
            case CLIENT_STATE_REQUEST_TUNNEL:
                send_tunnel_request_packet(
                        "127.0.0.1",
                        remote_port,
                        friendnumber
                );
                state = CLIENT_STATE_WAIT_FOR_ACKTUNNEL;
                break;
            case CLIENT_STATE_WAIT_FOR_ACKTUNNEL:
                break;
        }

        usleep(tox_do_interval(tox) * 1000);
    }
}

void help()
{
    fprintf(stderr, "tuntox - Forward ports over the Tox protocol\n");
    fprintf(stderr, "USAGE:\n\n");
    fprintf(stderr, "-i <toxid> - remote point Tox ID\n");
    fprintf(stderr, "-L <localport>:<remotehostname>:<remoteport> - forward <remotehostname>:<remoteport> to 127.0.0.1:<localport>\n");
    fprintf(stderr, "-p - ping the server from -i and exit\n");
}

int main(int argc, char *argv[])
{
    unsigned char tox_id[TOX_FRIEND_ADDRESS_SIZE];
    unsigned char tox_printable_id[TOX_FRIEND_ADDRESS_SIZE * 2 + 1];
    int oc;

    while ((oc = getopt(argc, argv, "L:pi:")) != -1)
    {
        switch(oc)
        {
            case 'L':
                /* Local port forwarding */
                client_mode = 1;
                remote_port = atoi(optarg);
                fprintf(stderr, "Forwarding remote port %d\n", remote_port);
                break;
            case 'p':
                /* Ping */
                client_mode = 1;
                ping_mode = 1;
                break;
            case 'i':
                remote_tox_id = optarg;
                break;
            case '?':
            default:
                help();
                exit(1);
        }
    }

    on_exit(cleanup, NULL);

    /* Bootstrap tox */
    tox_options.ipv6enabled = TOX_ENABLE_IPV6_DEFAULT;
    tox_options.udp_disabled = 0;
    tox_options.proxy_enabled = 0;

    tox = tox_new(&tox_options);

    set_tox_username(tox);

    tox_get_address(tox, tox_id);
    id_to_string(tox_printable_id, tox_id);
    tox_printable_id[TOX_FRIEND_ADDRESS_SIZE * 2] = '\0';
    printf("Generated Tox ID: %s\n", tox_printable_id);

    do_bootstrap(tox);

    /* TODO use proper argparse */
    if(client_mode)
    {
        do_client_loop(remote_tox_id);
    }
    else
    {
        /* Connect to the forwarded service */
//        client_socket = get_client_socket();

        tox_callback_friend_request(tox, accept_friend_request, NULL);
        do_server_loop();
    }

    return 0;
}
