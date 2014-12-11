#include "main.h"
#include "client.h"
#include "tox_bootstrap.h"

static Tox_Options tox_options;
Tox *tox;
int client_socket = 0;

/** CONFIGURATION OPTIONS **/
/* Whether we're a client */
int client_mode = 0;

/* Just send a ping and exit */
int ping_mode = 0;

/* Open a local port and forward it */
int client_local_port_mode = 0;

/* Forward stdin/stdout to remote machine - SSH ProxyCommand mode */
int client_pipe_mode = 0;

/* Remote Tox ID in client mode */
char *remote_tox_id = NULL;

/* Directory with config and tox save */
char config_path[500] = "/etc/tuntox/";

/* Ports and hostname for port forwarding */
int remote_port = 0;
char *remote_host = NULL;
int local_port = 0;

fd_set master_server_fds;

/* We keep two hash tables: one indexed by sockfd and another by "connection id" */
tunnel *by_id = NULL;

/* Highest used fd + 1 for select() */
int select_nfds = 4;

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

void update_select_nfds(int fd)
{
    /* TODO maybe replace with a scan every time to make select() more efficient in the long run? */
    if(fd + 1 > select_nfds)
    {
        select_nfds = fd + 1;
    }
}

/* Constructor. Returns NULL on failure. */
tunnel *tunnel_create(int sockfd, int connid, uint32_t friendnumber)
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

    fprintf(stderr, "Created a new tunnel object connid=%d sockfd=%d\n", connid, sockfd);

    update_select_nfds(t->sockfd);

    HASH_ADD_INT( by_id, connid, t );

    return t;
}

void tunnel_delete(tunnel *t)
{
    printf("Deleting tunnel #%d\n", t->connid);
    if(t->sockfd)
    {
        close(t->sockfd);
    }
    HASH_DEL( by_id, t );
    free(t);
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
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;

    if ((rv = getaddrinfo(hostname, port_str, &hints, &servinfo)) != 0) {
        fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(rv));
        return -1;
    }

    // loop through all the results and connect to the first we can
    for(p = servinfo; p != NULL; p = p->ai_next) {
        if (p->ai_family != AF_INET && p->ai_family != AF_INET6)
                    continue;

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
        return -1;
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
    int rv = -1;
    int i;

    data[0] = PROTOCOL_MAGIC_HIGH;
    data[1] = PROTOCOL_MAGIC_LOW;
    data[2] = BYTE2(frame->packet_type);
    data[3] = BYTE1(frame->packet_type);
    data[4] = BYTE2(frame->connid);
    data[5] = BYTE1(frame->connid);
    data[6] = BYTE2(frame->data_length);
    data[7] = BYTE1(frame->data_length);

    for(i = 0; i < 17;)
    {
        int j;

        rv = tox_send_lossless_packet(
                tox,
                frame->friendnumber,
                data,
                frame->data_length + PROTOCOL_BUFFER_OFFSET
        );

        if(rv < 0)
        {
            /* If this branch is ran, most likely we've hit congestion control. */
            fprintf(stderr, "[%d] Failed to send packet to friend %d\n", i, frame->friendnumber);
        }
        else
        {
            break;
        }

        if(i == 0) i = 2;
        else i = i * 2;

        for(j = 0; j < i; j++)
        {
            tox_do(tox);
            usleep(j * 10000);
        }
    }

    if(i > 0 && rv >= 0)
    {
        fprintf(stderr, "Packet succeeded at try %d\n", i+1);
    }

    return rv;
}

int send_tunnel_ack_frame(tunnel *tun)
{
    protocol_frame frame_st;
    protocol_frame *frame;
    char data[PROTOCOL_BUFFER_OFFSET];

    frame = &frame_st;
    memset(frame, 0, sizeof(protocol_frame));

    frame->packet_type = PACKET_TYPE_ACKTUNNEL;
    frame->connid = tun->connid;
    frame->data_length = 0;
    frame->friendnumber = tun->friendnumber;

    return send_frame(frame, data);
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
            FD_SET(sockfd, &master_server_fds);
            update_select_nfds(sockfd);
            fprintf(stderr, "Created tunnel, yay!\n");
            send_tunnel_ack_frame(tun);
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

/* Handle a TCP frame received from client */
int handle_client_tcp_frame(protocol_frame *rcvd_frame)
{
    tunnel *tun=NULL;
    int offset = 0;
    int connid = rcvd_frame->connid;

    HASH_FIND_INT(by_id, &connid, tun);

    if(!tun)
    {
        fprintf(stderr, "Got TCP frame with unknown tunnel ID %d\n", rcvd_frame->connid);
        return -1;
    }

    while(offset < rcvd_frame->data_length)
    {
        int sent_bytes;

        sent_bytes = send(
                tun->sockfd, 
                rcvd_frame->data + offset,
                rcvd_frame->data_length - offset,
                0
        );

        if(sent_bytes < 0)
        {
            fprintf(stderr, "Could not write to socket %d: %s\n", tun->sockfd, strerror(errno));
            return -1;
        }

        offset += sent_bytes;
    }

    return 0;
}

int handle_server_tcp_fin_frame(protocol_frame *rcvd_frame)
{

}

/* Handle close-tunnel frame received from the client */
int handle_client_tcp_fin_frame(protocol_frame *rcvd_frame)
{
    tunnel *tun=NULL;
    int offset = 0;
    int connid = rcvd_frame->connid;

    HASH_FIND_INT(by_id, &connid, tun);

    if(!tun)
    {
        fprintf(stderr, "Got TCP FIN frame with unknown tunnel ID %d\n", rcvd_frame->connid);
        return -1;
    }

    if(tun->friendnumber != rcvd_frame->friendnumber)
    {
        fprintf(stderr, "Friend #%d tried to close tunnel which belongs to #%d\n", rcvd_frame->friendnumber, tun->friendnumber);
        return -1;
    }
    
    tunnel_delete(tun);
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
            if(client_mode)
            {
                return handle_server_tcp_frame(frame);
            }
            else
            {
                return handle_client_tcp_frame(frame);
            }
            break;
        case PACKET_TYPE_REQUESTTUNNEL:
            handle_request_tunnel_frame(frame);
            break;
        case PACKET_TYPE_ACKTUNNEL:
            handle_acktunnel_frame(frame);
            break;
        case PACKET_TYPE_TCP_FIN:
            if(client_mode)
            {
                return handle_server_tcp_fin_frame(frame);
            }
            else
            {
                return handle_client_tcp_fin_frame(frame);
            }
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

/* Save tox identity to a file */
static void write_save(Tox *tox)
{
    void *data;
    uint32_t size;
    uint8_t path_tmp[512], path_real[512], *p;
    FILE *file;

    size = tox_size(tox);
    data = malloc(size);
    tox_save(tox, data);

    strncpy(path_real, config_path, sizeof(config_path));

    p = path_real + strlen(path_real);
    memcpy(p, "tox_save", sizeof("tox_save"));

    unsigned int path_len = (p - path_real) + sizeof("tox_save");
    memcpy(path_tmp, path_real, path_len);
    memcpy(path_tmp + (path_len - 1), ".tmp", sizeof(".tmp"));

    file = fopen((char*)path_tmp, "wb");
    if(file) {
        fwrite(data, size, 1, file);
        fflush(file);
        fclose(file);
        if (rename((char*)path_tmp, (char*)path_real) != 0) {
            fprintf(stderr, "Failed to rename file. %s to %s deleting and trying again\n", path_tmp, path_real);
            remove((const char *)path_real);
            if (rename((char*)path_tmp, (char*)path_real) != 0) {
                fprintf(stderr, "Saving Failed\n");
            } else {
                fprintf(stderr, "Saved data\n");
            }
        } else {
            fprintf(stderr, "Saved data\n");
        }
    }
    else
    {
        fprintf(stderr, "Could not open save file\n");
    }

    free(data);
}

/* Load tox identity from a file */
static int load_save(Tox *tox)
{
    void *data;
    uint32_t size;
    uint8_t path_tmp[512], path_real[512], *p;
    FILE *file;

    strncpy(path_real, config_path, sizeof(config_path));

    p = path_real + strlen(path_real);
    memcpy(p, "tox_save", sizeof("tox_save"));

    unsigned int path_len = (p - path_real) + sizeof("tox_save");

    data = file_raw((char *)path_real, &size);

    if(data)
    {
        tox_load(tox, data, size);
        free(data);
        return 1;
    }
    else
    {
        fprintf(stderr, "Could not open save file\n");
        return 0;
    }
}

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
    unsigned char tox_packet_buf[PROTOCOL_MAX_PACKET_SIZE];
    tunnel *tun = NULL;
    tunnel *tmp = NULL;
    int connected = 0;

    tv.tv_sec = 0;
    tv.tv_usec = 20000;

    FD_ZERO(&master_server_fds);

    while(1)
    {
        int tmp_isconnected = 0;

	/* Let tox do its stuff */
	tox_do(tox);

        /* Check change in connection state */
        tmp_isconnected = tox_isconnected(tox);
        if(tmp_isconnected != connected)
        {
            connected = tmp_isconnected;
            if(connected)
            {
                fprintf(stderr, "Connected to Tox network\n");
            }
            else
            {
                fprintf(stderr, "Disconnected from Tox network\n");
            }
        }

        fds = master_server_fds;

	/* Poll for data from our client connection */
	select(select_nfds, &fds, NULL, NULL, &tv);
        HASH_ITER(hh, by_id, tun, tmp)
        {
            if(FD_ISSET(tun->sockfd, &fds))
            {
                int nbytes = recv(tun->sockfd, 
                        tox_packet_buf+PROTOCOL_BUFFER_OFFSET, 
                        READ_BUFFER_SIZE, 0);

                /* Check if connection closed */
                if(nbytes == 0)
                {
                    char data[PROTOCOL_BUFFER_OFFSET];
                    protocol_frame frame_st, *frame;

                    printf("conn closed!\n");

                    frame = &frame_st;
                    memset(frame, 0, sizeof(protocol_frame));
                    frame->friendnumber = tun->friendnumber;
                    frame->packet_type = PACKET_TYPE_TCP_FIN;
                    frame->connid = tun->connid;
                    frame->data_length = 0;
                    send_frame(frame, data);

                    tunnel_delete(tun);
                                        
                    /* TODO remove tunnel? resume connection? */
                    continue;
                }
                else
                {
                    protocol_frame frame_st, *frame;

                    frame = &frame_st;
                    memset(frame, 0, sizeof(protocol_frame));
                    frame->friendnumber = tun->friendnumber;
                    frame->packet_type = PACKET_TYPE_TCP;
                    frame->connid = tun->connid;
                    frame->data_length = nbytes;
                    send_frame(frame, tox_packet_buf);
                }
            }
        }
    }
}

void help()
{
    fprintf(stderr, "tuntox - Forward ports over the Tox protocol\n");
    fprintf(stderr, "USAGE:\n\n");
    fprintf(stderr, "-i <toxid> - remote point Tox ID\n");
    fprintf(stderr, "-L <localport>:<remotehostname>:<remoteport> - forward <remotehostname>:<remoteport> to 127.0.0.1:<localport>\n");
    fprintf(stderr, "-P <remotehostname>:<remoteport> - forward <remotehostname>:<remoteport> to stdin/stdout (SSH ProxyCommand mode)\n");
    fprintf(stderr, "-p - ping the server from -i and exit\n");
    fprintf(stderr, "-C <dir> - save private key in <dir> instead of /etc/tuntox in server mode\n");
}

int main(int argc, char *argv[])
{
    unsigned char tox_id[TOX_FRIEND_ADDRESS_SIZE];
    unsigned char tox_printable_id[TOX_FRIEND_ADDRESS_SIZE * 2 + 1];
    int oc;

    while ((oc = getopt(argc, argv, "L:pi:C:")) != -1)
    {
        switch(oc)
        {
            case 'L':
                /* Local port forwarding */
                client_mode = 1;
                client_local_port_mode = 1;
                if(parse_local_port_forward(optarg, &local_port, &remote_host, &remote_port) < 0)
                {
                    fprintf(stderr, "Invalid value for -L option - use something like -L 22:127.0.0.1:22\n");
                    exit(1);
                }
                fprintf(stderr, "Forwarding remote port %d to local port %d\n", remote_port, local_port);
                break;
            case 'P':
                /* Pipe forwarding */
                client_mode = 1;
                client_pipe_mode = 1;
                remote_port = atoi(optarg);
                fprintf(stderr, "Forwarding remote port %d\n", remote_port);
                break;
            case 'p':
                /* Ping */
                client_mode = 1;
                ping_mode = 1;
                break;
            case 'i':
                /* Tox ID */
                remote_tox_id = optarg;
                break;
            case 'C':
                /* Config directory */
                strncpy(config_path, optarg, sizeof(config_path) - 1);
                if(optarg[strlen(optarg) - 1] != '/')
                {
                    int optarg_len = strlen(optarg);
                    
                    config_path[optarg_len] = '/';
                    config_path[optarg_len + 1] = '\0';
                }
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

    do_bootstrap(tox);

    /* TODO use proper argparse */
    if(client_mode)
    {
        tox_get_address(tox, tox_id);
        id_to_string(tox_printable_id, tox_id);
        tox_printable_id[TOX_FRIEND_ADDRESS_SIZE * 2] = '\0';
        printf("Generated Tox ID: %s\n", tox_printable_id);

        if(!remote_tox_id)
        {
            fprintf(stderr, "Tox id is required in client mode. Use -i 58435984ABCDEF475...\n");
            exit(1);
        }
        do_client_loop(remote_tox_id);
    }
    else
    {
        /* Connect to the forwarded service */
//        client_socket = get_client_socket();
        if(!load_save(tox))
        {
            /* Write generated ID if one is not already present */
            write_save(tox);
        }

        tox_get_address(tox, tox_id);
        id_to_string(tox_printable_id, tox_id);
        tox_printable_id[TOX_FRIEND_ADDRESS_SIZE * 2] = '\0';
        printf("Using Tox ID: %s\n", tox_printable_id);

        tox_callback_friend_request(tox, accept_friend_request, NULL);
        do_server_loop();
    }

    return 0;
}
