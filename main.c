#include "main.h"
#include "client.h"
#include "socks5.h"
#include "tox_bootstrap.h"
#include "tox_bootstrap_json.h"
#include "log.h"

#ifdef __MACH__
    #include "mach.h"
#endif

static struct Tox_Options tox_options;
Tox *tox;
int client_socket = 0;
TOX_CONNECTION connection_status = TOX_CONNECTION_NONE;

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
uint8_t *remote_tox_id = NULL;

/* Tox TCP relay port */
long int tcp_relay_port = 0;

/* UDP listen ports */
long int udp_start_port = 0;
long int udp_end_port = 0;

/* SOCKS5 listen port */
long int socks5_port = 0;

/* Directory with config and tox save */
char config_path[500] = "/etc/tuntox/";

/* Limit hostname and port in server */
int nrules = 0;
char rules_file[500] = "/etc/tuntox/rules";
enum rules_policy_enum rules_policy = NONE;
rule *rules = NULL;

/* Bootstrap json file */
char boot_json[500] = "/etc/tuntox/nodes.json";

/* Ports and hostname for port forwarding */
local_port_forward *local_port_forwards = NULL;
uint32_t last_forward_id;

/* Whether to daemonize/fork after startup */
int daemonize = 0;
/* Path to the pidfile */
char *pidfile = NULL;
/* Username to which we suid() in daemon mode */
char *daemon_username = NULL;

/* Shared secret used for authentication */
int use_shared_secret = 0;
char shared_secret[TOX_MAX_FRIEND_REQUEST_LENGTH];

/* Only let in a whitelisted client */
int server_whitelist_mode = 0;
allowed_toxid *allowed_toxids = NULL;

int load_saved_toxid_in_client_mode = 0;

fd_set master_server_fds;

/* We keep two hash tables: one indexed by sockfd and another by "connection id" */
tunnel *by_id = NULL;

/* Tunnels need to be delete safely, outside FD_ISSET polling */
/* See: tunnel_queue_delete() */
tunnel_list *tunnels_to_delete = NULL;

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
        log_printf(L_WARNING, "[i] Found duplicated tunnel ID %d\n", key);
    }
}

/* Comparison function for allowed_toxid objects */
int allowed_toxid_cmp(allowed_toxid *a, allowed_toxid *b)
{
    return memcmp(a->toxid, b->toxid, TOX_PUBLIC_KEY_SIZE);
}

/* Match rule r against candidate host, port. Returns 0 for match. */
int rule_match(rule *r, rule *candidate)
{
    bool host_match = !strcmp(r->host, "*") || !strcmp(r->host, candidate->host);
    bool port_match = r->port == 0 || r->port == candidate->port;

    return port_match && host_match ? 0 : -1;
}

/* When a file descriptor has been added to or removed from select() fdset,
 * we need to update select_nfds. */
void update_select_nfds(int fd, fd_set *fds, int *old_select_nfds)
{
    int new_select_nfds = 0;

    if(fd + 1 > *old_select_nfds)
    {
        *old_select_nfds = fd + 1;
    }

    for(int i = 0; i < *old_select_nfds; i++)
    {
	if(FD_ISSET(i, fds))
	{
	    if(i + 1 > new_select_nfds)
	    {
		new_select_nfds = i + 1;
	    }
	}
    }
    *old_select_nfds = new_select_nfds;
}

void update_master_server_nfds(int fd)
{
    update_select_nfds(fd, &master_server_fds, &select_nfds);
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

    log_printf(L_INFO, "Created a new tunnel object connid=%d sockfd=%d\n", connid, sockfd);

    update_master_server_nfds(t->sockfd);

    HASH_ADD_INT( by_id, connid, t );

    return t;
}

/* Please use tunnel_queue_delete() instead */
void tunnel_delete(tunnel *t)
{
    log_printf(L_INFO, "Deleting tunnel #%d ptr %p\n", t->connid, t);
    if(t->sockfd)
    {
        if(close(t->sockfd) == -1)
        {
            log_printf(L_DEBUG, "Failed to close socket: code=%d (%s)\n", errno, strerror(errno));
        }
        FD_CLR(t->sockfd, &master_server_fds);
	update_master_server_nfds(0);
    }
    HASH_DEL( by_id, t );
    free(t);
}

int tunnel_in_delete_queue(tunnel *t) 
{
    tunnel_list *element;

    LL_FOREACH(tunnels_to_delete, element)
    {
        if(element->tun == t)
        {
            return 1;
        }
    }

    return 0;
}

/* Delete the tunnel at the end of main loop */
void tunnel_queue_delete(tunnel *t)
{
    tunnel_list *tunnel_list_entry = NULL;

    if(tunnel_in_delete_queue(t))
    {
        log_printf(L_DEBUG2, "Did not queue deleting tunnel #%d ptr %p - already queued\n", t->connid, t);
        return;
    }

    log_printf(L_DEBUG2, "Queued deleting tunnel #%d ptr %p\n", t->connid, t);

    tunnel_list_entry = calloc(sizeof(tunnel_list), 1);
    tunnel_list_entry->tun = t;
    LL_APPEND(tunnels_to_delete, tunnel_list_entry);
}

local_port_forward *local_port_forward_create()
{
    local_port_forward *forward = calloc(sizeof(local_port_forward), 1);
    if(!forward)
    {
        return NULL;
    }

    forward->forward_id = ++last_forward_id;
    forward->created = time(NULL);
    forward->is_acked = false;

    return forward;
}


/* bootstrap to dht with bootstrap_nodes */
/* From uTox/tox.c */
static void do_bootstrap(Tox *tox)
{
    static unsigned int j = 0;

    if (j == 0)
        j = rand();

    int i = 0;
    while(i < 8) {
        struct bootstrap_node *d = &bootstrap_nodes[j % countof(bootstrap_nodes)];
        struct bootstrap_node *r = &tcp_relays[(4*j) % countof(tcp_relays)];
        tox_bootstrap(tox, d->address, d->port, d->key, 0);
        tox_add_tcp_relay(tox, r->address, r->port, r->key, 0);
        i++;
        j++;
    }
}

/* Set username to the machine's FQDN */
void set_tox_username(Tox *tox)
{
    char hostname[1024];
    TOX_ERR_SET_INFO error;

    gethostname((char*)hostname, 1024);
    hostname[1023] = '\0';

    tox_self_set_name(tox, (uint8_t *)hostname, strlen(hostname), &error);
    if(error != TOX_ERR_SET_INFO_OK)
    {
        log_printf(L_DEBUG, "tox_self_set_name() failed (%u)", error);
    }
}

/* Get sockaddr, IPv4 or IPv6 */
void *get_in_addr(struct sockaddr *sa)
{
    if (sa->sa_family == AF_INET) 
    {
        return &(((struct sockaddr_in*)sa)->sin_addr);
    }

    return &(((struct sockaddr_in6*)sa)->sin6_addr);
}

/* Connect to an endpoint, return sockfd */
int get_client_socket(char *hostname, int port)
{
    int sockfd;
    struct addrinfo hints, *servinfo, *p;
    int rv;
    char s[INET6_ADDRSTRLEN];
    char port_str[6];

    snprintf(port_str, 6, "%d", port);

    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;

    if ((rv = getaddrinfo(hostname, port_str, &hints, &servinfo)) != 0) 
    {
        /* Add a special case for "localhost" when name resolution is broken */
        if(!strncmp("localhost", hostname, 256))
        {
            const char localhostname[] = "127.0.0.1";
            if ((rv = getaddrinfo(localhostname, port_str, &hints, &servinfo)) != 0) {
                log_printf(L_WARNING, "getaddrinfo failed for 127.0.0.1: %s\n", gai_strerror(rv));
                return -1;
            }
        }
        else
        {
            log_printf(L_WARNING, "getaddrinfo: %s\n", gai_strerror(rv));
            return -1;
        }
    }

    // loop through all the results and connect to the first we can
    for(p = servinfo; p != NULL; p = p->ai_next) 
    {
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
        log_printf(L_WARNING, "failed to connect to %s:%d\n", hostname, port);
        freeaddrinfo(servinfo);
        return -1;
    }

    inet_ntop(p->ai_family, get_in_addr((struct sockaddr *)p->ai_addr), s, sizeof s);
    log_printf(L_DEBUG, "connecting to %s\n", s);

    freeaddrinfo(servinfo); // all done with this structure

    log_printf(L_DEBUG, "Connected to %s:%d\n", hostname, port);

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
    int try = 0;
    int i;
    TOX_ERR_FRIEND_CUSTOM_PACKET custom_packet_error;

    data[0] = PROTOCOL_MAGIC_HIGH;
    data[1] = PROTOCOL_MAGIC_LOW;
    data[2] = BYTE2(frame->packet_type);
    data[3] = BYTE1(frame->packet_type);
    data[4] = BYTE2(frame->connid);
    data[5] = BYTE1(frame->connid);
    data[6] = BYTE2(frame->data_length);
    data[7] = BYTE1(frame->data_length);

    for(i = 0; i < 33;) /* 2.667 seconds per packet max */
    {
        int j;

        try++;

        rv = tox_friend_send_lossless_packet(
                tox,
                frame->friendnumber,
                data,
                frame->data_length + PROTOCOL_BUFFER_OFFSET,
                &custom_packet_error
        );

        if(custom_packet_error == TOX_ERR_FRIEND_CUSTOM_PACKET_OK)
        {
            break;
        }
        else
        {
            /* If this branch is ran, most likely we've hit congestion control. */
            if(custom_packet_error == TOX_ERR_FRIEND_CUSTOM_PACKET_SENDQ)
            {
                log_printf(L_DEBUG, "[%d] Failed to send packet to friend %d (Packet queue is full)\n", i, frame->friendnumber);
            }
            else if(custom_packet_error == TOX_ERR_FRIEND_CUSTOM_PACKET_FRIEND_NOT_CONNECTED)
            {
                log_printf(L_DEBUG, "[%d] Failed to send packet to friend %d (Friend gone)\n", i, frame->friendnumber);
                break;
            }
            else
            {
                log_printf(L_DEBUG, "[%d] Failed to send packet to friend %d (err: %u)\n", i, frame->friendnumber, custom_packet_error);
            }
        }

        if(i == 0) i = 2;
        else i = i * 2;

        for(j = 0; j < i; j++)
        {
            tox_iterate(tox, NULL);
            usleep(j * 1000);
        }
    }

    if(i > 0 && rv >= 0)
    {
        log_printf(L_DEBUG, "Packet succeeded at try %d (friend %d tunnel %d)\n", try, frame->friendnumber, frame->connid);
    }

    return rv;
}

int send_tunnel_ack_frame(tunnel *tun, uint32_t remote_forward_id)
{
    protocol_frame frame_st;
    protocol_frame *frame;
    uint8_t *data = NULL;

    frame = &frame_st;
    memset(frame, 0, sizeof(protocol_frame));

    frame->packet_type = PACKET_TYPE_ACKTUNNEL;
    frame->connid = tun->connid;
    frame->data_length = 4;
    frame->friendnumber = tun->friendnumber;

    data = calloc(PROTOCOL_BUFFER_OFFSET + frame->data_length, 1);
    data[PROTOCOL_BUFFER_OFFSET+3] = BYTE1(remote_forward_id);
    data[PROTOCOL_BUFFER_OFFSET+2] = BYTE2(remote_forward_id);
    data[PROTOCOL_BUFFER_OFFSET+1] = BYTE3(remote_forward_id);
    data[PROTOCOL_BUFFER_OFFSET] = BYTE4(remote_forward_id);

    return send_frame(frame, data);
}

int handle_ping_frame(protocol_frame *rcvd_frame)
{
    uint8_t data[TOX_MAX_CUSTOM_PACKET_SIZE];
    protocol_frame frame_s;
    protocol_frame *frame = &frame_s;

    frame->connid = 0;
    frame->data = data + PROTOCOL_BUFFER_OFFSET;
    memcpy(frame->data, rcvd_frame->data, rcvd_frame->data_length);

    frame->friendnumber = rcvd_frame->friendnumber;
    frame->packet_type = PACKET_TYPE_PONG;
    frame->data_length = rcvd_frame->data_length;
    
    send_frame(frame, data);

    return 0;
}

int handle_request_tunnel_frame(protocol_frame *rcvd_frame)
{
    char *hostname = NULL;
    tunnel *tun;
    int port = -1;
    int sockfd = 0;
    uint16_t tunnel_id;
    /* Client-side ID of the tunnel */
    uint32_t remote_forward_id;

    if(client_mode)
    {
        log_printf(L_WARNING, "Got tunnel request frame from friend #%d when in client mode\n", rcvd_frame->friendnumber);
        return -1;
    }
    
    port = rcvd_frame->connid;
    hostname = calloc(1, rcvd_frame->data_length + 1);
    if(!hostname)
    {
        log_printf(L_ERROR, "Could not allocate memory for tunnel request hostname\n");
        return -1;
    }

    remote_forward_id = INT32_AT(rcvd_frame->data, 0);

    strncpy(hostname, ((char *)rcvd_frame->data) + 4, rcvd_frame->data_length - 4);
    hostname[rcvd_frame->data_length] = '\0';

    log_printf(L_INFO, "Got a request to forward data from %s:%d\n", hostname, port);
    
    // check rules
    if (rules_policy == VALIDATE && nrules > 0 ) {
        
        rule temp_rule, *found = NULL;
        temp_rule.host = hostname;
        temp_rule.port = port;
        
        LL_SEARCH(rules, found, &temp_rule, rule_match);
        if(!found)
        {
            log_printf(L_WARNING, "Rejected, request not in rules\n");
            if(hostname)
            {
                free(hostname);
            }
            return -1;
        }
    } else if (rules_policy != NONE) {
        log_printf(L_WARNING, "Filter option active but no allowed host/port. All requests will be dropped.\n");
        if(hostname)
        {
            free(hostname);
        }
        return -1;
    }



    tunnel_id = get_random_tunnel_id();
    log_printf(L_DEBUG, "Tunnel ID: %d\n", tunnel_id);

    sockfd = get_client_socket(hostname, port);
    if(sockfd >= 0)
    {
        tun = tunnel_create(sockfd, tunnel_id, rcvd_frame->friendnumber);
        if(tun)
        {
            FD_SET(sockfd, &master_server_fds);
            update_master_server_nfds(sockfd);
            log_printf(L_DEBUG, "Created tunnel, yay!\n");
            send_tunnel_ack_frame(tun, remote_forward_id);
        }
        else
        {
            log_printf(L_ERROR, "Couldn't allocate memory for tunnel\n");
            close(sockfd);
        }
    }
    else
    {
        log_printf(L_WARNING, "Could not connect to %s:%d\n", hostname, port);
        /* TODO send PACKET_TYPE_REQUESTTUNNEL */
    }

    free(hostname);

    return 0;
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
        log_printf(L_WARNING, "Got TCP frame with unknown tunnel ID %d\n", rcvd_frame->connid);
        return -1;
    }

    if(tun->friendnumber != rcvd_frame->friendnumber)
    {
        log_printf(L_WARNING, "Friend #%d tried to send packet to a tunnel which belongs to #%d\n", rcvd_frame->friendnumber, tun->friendnumber);
        return -1;
    }

    while(offset < rcvd_frame->data_length)
    {
        int sent_bytes;

        sent_bytes = send(
                tun->sockfd, 
                rcvd_frame->data + offset,
                rcvd_frame->data_length - offset,
                MSG_NOSIGNAL
        );

        if(sent_bytes < 0)
        {
            log_printf(L_WARNING, "Could not write to socket %d: %s\n", tun->sockfd, strerror(errno));
            return -1;
        }
        log_printf(L_DEBUG2, "Sent %d bytes to tunnel %d\n", sent_bytes, tun->sockfd);

        offset += sent_bytes;
    }

    return 0;
}

/* Handle close-tunnel frame received from the client */
int handle_client_tcp_fin_frame(protocol_frame *rcvd_frame)
{
    tunnel *tun=NULL;
    int connid = rcvd_frame->connid;

    HASH_FIND_INT(by_id, &connid, tun);

    if(!tun)
    {
        log_printf(L_DEBUG, "Got TCP FIN frame with unknown tunnel ID %d\n", rcvd_frame->connid);
        return -1;
    }

    if(tun->friendnumber != rcvd_frame->friendnumber)
    {
        log_printf(L_WARNING, "Friend #%d tried to close tunnel which belongs to #%d\n", rcvd_frame->friendnumber, tun->friendnumber);
        return -1;
    }
    
    log_printf(L_DEBUG2, "Deleting tunnel #%d (%p) in handle_client_tcp_fin_frame(), socket %d", rcvd_frame->connid, tun, tun->sockfd);
    tunnel_queue_delete(tun);

    return 0;
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
            log_printf(L_DEBUG, "Got unknown packet type 0x%x from friend %d\n", 
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
void parse_lossless_packet(Tox *tox, uint32_t friendnumber, const uint8_t *data, size_t len, void *tmp)
{
    protocol_frame *frame = NULL;

    if(len < PROTOCOL_BUFFER_OFFSET)
    {
        log_printf(L_WARNING, "Received too short data frame - only %d bytes, at least %d expected\n", len, PROTOCOL_BUFFER_OFFSET);
        return;
    }

    if(!data)
    {
        log_printf(L_ERROR, "Got NULL pointer from toxcore - WTF?\n");
        return;
    }

    if(data[0] != PROTOCOL_MAGIC_HIGH || data[1] != PROTOCOL_MAGIC_LOW)
    {
        log_printf(L_WARNING, "Received data frame with invalid protocol magic number 0x%x%x\n", data[0], data[1]);
        if(data[0] == (PROTOCOL_MAGIC_V1 >> 8) && data[1] == (PROTOCOL_MAGIC_V1 & 0xff)) 
        {
            log_printf(L_ERROR, "Tuntox on the other end uses old protocol version 1. Please upgrade it.");
        }
        return;
    }

    frame = calloc(1, sizeof(protocol_frame));
    if(!frame)
    {
        log_printf(L_ERROR, "Could not allocate memory for protocol_frame_t\n");
        return;
    }

    /* TODO check if friendnumber is the same in sender and connid tunnel*/
    frame->magic =                      INT16_AT(data, 0);
    frame->packet_type =                INT16_AT(data, 2);
    frame->connid =                     INT16_AT(data, 4);
    frame->data_length =                INT16_AT(data, 6);
    frame->data = (uint8_t *)(data + PROTOCOL_BUFFER_OFFSET);
    frame->friendnumber =               friendnumber;
    log_printf(L_DEBUG, "Got protocol frame magic 0x%x type 0x%x from friend %d\n", frame->magic, frame->packet_type, frame->friendnumber);

    if(len < (size_t)frame->data_length + PROTOCOL_BUFFER_OFFSET)
    {
        log_printf(L_WARNING, "Received frame too small (attempted buffer overflow?): %d bytes, excepted at least %d bytes\n", len, frame->data_length + PROTOCOL_BUFFER_OFFSET);
        free(frame);
        return;
    }

    if(frame->data_length > (TOX_MAX_CUSTOM_PACKET_SIZE - PROTOCOL_BUFFER_OFFSET))
    {
        log_printf(L_WARNING, "Declared data length too big (attempted buffer overflow?): %d bytes, excepted at most %d bytes\n", frame->data_length, (TOX_MAX_CUSTOM_PACKET_SIZE - PROTOCOL_BUFFER_OFFSET));
        free(frame);
        return;
    }

    handle_frame(frame);
    free(frame);
}

int send_tunnel_request_packet(char *remote_host, int remote_port, uint32_t local_forward_id, int friend_number)
{
    int packet_length = 0;
    protocol_frame frame_i, *frame;
    uint8_t *data = NULL;

    log_printf(L_INFO, "Sending packet to friend #%d to forward %s:%d\n", friend_number, remote_host, remote_port);
    packet_length = PROTOCOL_BUFFER_OFFSET + strlen(remote_host) + 4;
    if(packet_length > TOX_MAX_CUSTOM_PACKET_SIZE)
    {
        log_printf(L_WARNING, "Not requesting port forward - host name %s is too long", remote_host);
    }
    frame = &frame_i;

    data = calloc(1, packet_length);
    if(!data)
    {
        log_printf(L_ERROR, "Could not allocate memory for tunnel request packet\n");
        exit(1);
    }
    data[PROTOCOL_BUFFER_OFFSET+3] = BYTE1(local_forward_id);
    data[PROTOCOL_BUFFER_OFFSET+2] = BYTE2(local_forward_id);
    data[PROTOCOL_BUFFER_OFFSET+1] = BYTE3(local_forward_id);
    data[PROTOCOL_BUFFER_OFFSET] = BYTE4(local_forward_id);

    memcpy((char *)data+PROTOCOL_BUFFER_OFFSET+4, remote_host, strlen(remote_host));

    frame->friendnumber = friend_number;
    frame->packet_type = PACKET_TYPE_REQUESTTUNNEL;
    frame->connid = remote_port;
    frame->data_length = strlen(remote_host) + 4; 

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

    size = tox_get_savedata_size(tox);
    data = malloc(size);
    tox_get_savedata(tox, data);

    strncpy((char *)path_real, config_path, sizeof(path_real));

    p = path_real + strlen((char *)path_real);
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
            log_printf(L_WARNING, "Failed to rename file. %s to %s deleting and trying again\n", path_tmp, path_real);
            if(remove((const char *)path_real) < 0) {
                log_printf(L_WARNING, "Failed to remove old save file %s\n", path_real);
            }
            if (rename((char*)path_tmp, (char*)path_real) != 0) {
                log_printf(L_WARNING, "Saving Failed\n");
            } else {
                log_printf(L_DEBUG, "Saved data\n");
            }
        } else {
            log_printf(L_DEBUG, "Saved data\n");
        }
    }
    else
    {
        log_printf(L_WARNING, "Could not open save file\n");
    }

    free(data);
}

/* Load tox identity from a file */
static size_t load_save(uint8_t **out_data)
{
    void *data;
    uint32_t size;
    uint8_t path_real[512], *p;

    strncpy((char *)path_real, config_path, sizeof(path_real));

    p = path_real + strlen((char *)path_real);
    memcpy(p, "tox_save", sizeof("tox_save"));

    data = file_raw((char *)path_real, &size);

    if(data)
    {
        *out_data = data;
        return size;
    }
    else
    {
        log_printf(L_WARNING, "Could not open save file\n");
        return 0;
    }
}

/* Loads a list of allowed hostnames and ports from file. Format is hostname:port*/
void load_rules()
{
    char *ahost=NULL;
    int aport=0;
    char line[100 + 1] = "";
    FILE *file = NULL;
    rule *rule_obj = NULL;
    int valid_rules = 0;

    file = fopen(rules_file, "r");
    
    if (file == NULL) {
        log_printf(L_WARNING, "Could not open rules file (%s)\n", rules_file);
        return;
    }
    
    while (fgets(line, sizeof(line), file)) {
        /* allow comments & white lines */
        if (line[0]=='#'||line[0]=='\n') {
            continue;
        }
        if (parse_pipe_port_forward(line, &ahost, &aport) >= 0) {
            if (aport > 0 && aport < 65535) {

                rule_obj = (rule *)calloc(sizeof(rule), 1);
                if(!rule_obj)
                {
                    log_printf(L_ERROR, "Could not allocate memory for rule");
                    exit(1);
                }

                rule_obj->port = aport;
                rule_obj->host = strdup(ahost);

                LL_APPEND(rules, rule_obj);
                valid_rules++;
            } else {
                log_printf(L_WARNING, "Invalid port in line: %s\n", line);
            }
        } else {
            log_printf(L_WARNING, "Could not parse line: %s\n", line);
        }
    }
    fclose(file);
    
    /* save valid rules in global variable */
    nrules = valid_rules;
    
    log_printf(L_INFO, "Loaded %d rules\n", nrules);
    if (nrules==0 && rules_policy != NONE){
        log_printf(L_WARNING, "No rules loaded! NO CONNECTIONS WILL BE ALLOWED!\n");
    }
}

/* Clear rules loaded into memory */
void clear_rules()
{
    rule * elt, *tmp;
    /* delete each elemen using the safe iterator */
    LL_FOREACH_SAFE(rules,elt,tmp) {
      LL_DELETE(rules,elt);
      free(elt->host);
      free(elt);
    }
}

void accept_friend_request(Tox *tox, const uint8_t *public_key, const uint8_t *message, size_t length, void *userdata)
{
    unsigned char tox_printable_id[TOX_ADDRESS_SIZE * 2 + 1];
    uint32_t friendnumber;
    TOX_ERR_FRIEND_ADD friend_add_error;

    log_printf(L_DEBUG, "Got friend request\n");

    if(use_shared_secret)
    {
        if(!message)
        {
            log_printf(L_WARNING, "Friend sent NULL message - not accepting request");
            return;
        }

        if(message[length - 1] != '\0')
        {
            log_printf(L_WARNING, "Message of size %u is not NULL terminated - not accepting request", length);
            return;
        }

        if(strncmp((char *)message, shared_secret, TOX_MAX_FRIEND_REQUEST_LENGTH-1))
        {
            log_printf(L_WARNING, "Received shared secret \"%s\" differs from our shared secret - not accepting request", message);
            return;
        }
    }
    
    memset(tox_printable_id, '\0', sizeof(tox_printable_id));
    id_to_string(tox_printable_id, public_key);

    if(server_whitelist_mode)
    {
        allowed_toxid etmp, *found = NULL;
        memcpy(etmp.toxid, public_key, TOX_PUBLIC_KEY_SIZE);
        LL_SEARCH(allowed_toxids, found, &etmp, allowed_toxid_cmp);
        if(!found)
        {
            log_printf(L_WARNING, "Rejected friend request from non-whitelisted friend %s", tox_printable_id);
            return;
        }
        log_printf(L_DEBUG, "Friend %s passed whitelist check", tox_printable_id);
    }

    friendnumber = tox_friend_add_norequest(tox, public_key, &friend_add_error);
    if(friend_add_error != TOX_ERR_FRIEND_ADD_OK)
    {
        log_printf(L_WARNING, "Could not add friend: err %u", friend_add_error);
        return;
    }

    log_printf(L_INFO, "Accepted friend request from %s as %d\n", tox_printable_id, friendnumber);
}

/* Callback for tox_callback_self_connection_status() */
void handle_connection_status_change(Tox *tox, TOX_CONNECTION p_connection_status, void *user_data)
{
    const char *status = NULL;
    connection_status = p_connection_status;
    status = readable_connection_status(connection_status);
    log_printf(L_INFO, "Connection status changed: %s", status);
}

void cleanup()
{
    log_printf(L_DEBUG, "kthxbye\n");
    fflush(stdout);
    tox_kill(tox);
    if(client_socket)
    {
        close(client_socket);
    }
    log_close();
}


int do_server_loop()
{
    struct timeval tv, tv_start, tv_end;
    unsigned long long ms_start, ms_end;
    fd_set fds;
    unsigned char tox_packet_buf[PROTOCOL_MAX_PACKET_SIZE];
    tunnel *tun = NULL;
    tunnel *tmp = NULL;
    TOX_CONNECTION connected = 0;
    int sent_data = 0;

    tox_callback_friend_lossless_packet(tox, parse_lossless_packet);

    tv.tv_sec = 0;
    tv.tv_usec = 20000;

    FD_ZERO(&master_server_fds);

    while(1)
    {
        TOX_CONNECTION tmp_isconnected = 0;
        uint32_t tox_do_interval_ms;
        int select_rv = 0;
        sent_data = 0;

        /* Let tox do its stuff */
        tox_iterate(tox, NULL);

        /* Get the desired sleep time, used in select() later */
        tox_do_interval_ms = tox_iteration_interval(tox);
        tv.tv_usec = (tox_do_interval_ms % 1000) * 1000;
        tv.tv_sec = tox_do_interval_ms / 1000;
        log_printf(L_DEBUG2, "Iteration interval: %dms\n", tox_do_interval_ms);
        gettimeofday(&tv_start, NULL);

        /* Check change in connection state */
        tmp_isconnected = connection_status;
        if(tmp_isconnected != connected)
        {
            connected = tmp_isconnected;
            if(connected)
            {
                log_printf(L_DEBUG, "Connected to Tox network\n");
            }
            else
            {
                log_printf(L_DEBUG, "Disconnected from Tox network\n");
            }
        }

        fds = master_server_fds;

        /* Poll for data from our client connection */
        select_rv = select(select_nfds, &fds, NULL, NULL, &tv);
        if(select_rv == -1 || select_rv == 0)
        {
            if(select_rv == -1)
            {
                log_printf(L_DEBUG, "Reading from local socket failed: code=%d (%s)\n",
                        errno, strerror(errno));
            }
            else
            {
                log_printf(L_DEBUG2, "Nothing to read...");
            }
        }
        else
        {
            tunnel_list *tunnel_list_entry = NULL, *list_tmp = NULL;
            tmp = NULL;
            tun = NULL;

            log_printf(L_DEBUG, "Starting tunnel iteration...");
            HASH_ITER(hh, by_id, tun, tmp)
            {
                log_printf(L_DEBUG, "Current tunnel: %p", tun);
                if(FD_ISSET(tun->sockfd, &fds))
                {
                    int nbytes = recv(tun->sockfd, 
                            tox_packet_buf+PROTOCOL_BUFFER_OFFSET, 
                            READ_BUFFER_SIZE, 0);

                    /* Check if connection closed */
                    if(nbytes <= 0)
                    {
                        uint8_t data[PROTOCOL_BUFFER_OFFSET];
                        protocol_frame frame_st, *frame;

                        if(nbytes == 0)
                        {
                            log_printf(L_DEBUG, "conn closed!\n");
                        }
                        else
                        {
                            log_printf(L_WARNING, "conn closed, code=%d (%s)\n",
                                    errno, strerror(errno));
                        }

                        frame = &frame_st;
                        memset(frame, 0, sizeof(protocol_frame));
                        frame->friendnumber = tun->friendnumber;
                        frame->packet_type = PACKET_TYPE_TCP_FIN;
                        frame->connid = tun->connid;
                        frame->data_length = 0;
                        send_frame(frame, data);
                        sent_data = 1;

                        tunnel_queue_delete(tun);
                                            
                        continue;
                    }
                    else
                    {
                        protocol_frame frame_st, *frame;
                        log_printf(L_DEBUG2, "Read %d bytes from tunnel %d\n", nbytes, tun->sockfd);

                        frame = &frame_st;
                        memset(frame, 0, sizeof(protocol_frame));
                        frame->friendnumber = tun->friendnumber;
                        frame->packet_type = PACKET_TYPE_TCP;
                        frame->connid = tun->connid;
                        frame->data_length = nbytes;
                        send_frame(frame, tox_packet_buf);
                        sent_data = 1;
                    }
                }
            }
            log_printf(L_DEBUG, "Tunnel iteration done");

            LL_FOREACH_SAFE(tunnels_to_delete, tunnel_list_entry, list_tmp)
            {
                tunnel_delete(tunnel_list_entry->tun);
                LL_DELETE(tunnels_to_delete, tunnel_list_entry);
                free(tunnel_list_entry);
            }
        }

        gettimeofday(&tv_end, NULL);
        ms_start = 1000 * tv_start.tv_sec + tv_start.tv_usec/1000;
        ms_end = 1000 * tv_end.tv_sec + tv_end.tv_usec/1000;
        
        if(!sent_data && (ms_end - ms_start < tox_do_interval_ms))
        {
            /*log_printf(L_DEBUG, "Sleeping for %d ms extra to prevent high CPU usage\n", (tox_do_interval_ms - (ms_end - ms_start)));*/
            usleep((tox_do_interval_ms - (ms_end - ms_start)) * 1000);
        }
    }
}

/* Signal handler used when daemonizing */
static void child_handler(int signum)
{
    switch(signum) {
        case SIGALRM: exit(1); break;
        case SIGUSR1: exit(0); break;
        case SIGCHLD: exit(1); break;
    }
}

/* 
 * Daemonize the process if -z is set
 * Optionally drop privileges and create a lock file
 */
void do_daemonize()
{
    pid_t pid, sid, parent;
    FILE *pidf = NULL;

    /* already a daemon */
    if (getppid() == 1) 
    {
        return;
    }

    /* Drop user if there is one, and we were run as root */
    if (daemon_username && (getuid() == 0 || geteuid() == 0)) 
    {
        struct passwd *pw = getpwnam(daemon_username);

        if(pw) 
        {
            log_printf(L_DEBUG, "Setuid to user %s", daemon_username);
            setuid(pw->pw_uid);
        }
        else
        {
            char *tmp;
            int uid = 0;

            uid = strtol(daemon_username, &tmp, 10);
            if(uid)
            {
                setuid(uid);
                log_printf(L_DEBUG, "Setuid to user ID %ld", (long)uid);
            }
            else
            {
                log_printf(L_DEBUG, "Could not setuid to user %s - no pwnam (static build?) or invalid numeric UID", daemon_username);
            }
        }
    }

    /* Trap signals that we expect to recieve */
    signal(SIGCHLD,child_handler);
    signal(SIGUSR1,child_handler);
    signal(SIGALRM,child_handler);

    /* Fork off the parent process */
    pid = fork();
    if (pid < 0) 
    {
        log_printf(L_ERROR, "Unable to fork daemon, code=%d (%s)",
                errno, strerror(errno));
        exit(1);
    }
    /* If we got a good PID, then we can exit the parent process. */
    if (pid > 0) 
    {
        /* Wait for confirmation from the child via SIGTERM or SIGCHLD, or
           for two seconds to elapse (SIGALRM).  pause() should not return. */
        alarm(2);
        pause();

        exit(1);
    }

    /* At this point we are executing as the child process */
    parent = getppid();

    /* Cancel certain signals */
    signal(SIGCHLD,SIG_DFL); /* A child process dies */
    signal(SIGTSTP,SIG_IGN); /* Various TTY signals */
    signal(SIGTTOU,SIG_IGN);
    signal(SIGTTIN,SIG_IGN);
    signal(SIGHUP, SIG_IGN); /* Ignore hangup signal */
    signal(SIGTERM,SIG_DFL); /* Die on SIGTERM */

    /* Change the file mode mask */
    umask(S_IWGRP | S_IWOTH);

    /* Reinitialize the syslog connection */
    log_init();

    /* Create a new SID for the child process */
    sid = setsid();
    if (sid < 0) 
    {
        log_printf(L_ERROR, "unable to create a new session, code %d (%s)",
                errno, strerror(errno));
        exit(1);
    }

    /* Change the current working directory.  This prevents the current
       directory from being locked; hence not being able to remove it. */
    if ((chdir("/")) < 0) 
    {
        log_printf(L_ERROR, "Unable to change directory to %s, code %d (%s)",
                "/", errno, strerror(errno) );
        exit(1);
    }

    /* Redirect standard files to /dev/null */
    freopen( "/dev/null", "r", stdin);
    freopen( "/dev/null", "w", stdout);
    freopen( "/dev/null", "w", stderr);

    /* Create the pid file as the new user */
    if (pidfile && pidfile[0]) 
    {
        pidf = fopen(pidfile, "w");
        if (!pidf) 
        {
            log_printf(L_ERROR, "Unable to create PID file %s, code=%d (%s)",
                    pidfile, errno, strerror(errno));
            exit(1);
        }
        fprintf(pidf, "%ld", (long)getpid());
        fclose(pidf);
    }


    /* Tell the parent process that we are A-okay */
    kill( parent, SIGUSR1 );    
}

/* Parse the ALL_PROXY or all_proxy environment variable */
void parse_all_proxy(struct Tox_Options *tox_options)
{
    char *env;
    static char all_proxy[1024];
    int len_of_env = 0;

    /* Remote SOCKS5 proxy host/port */
    Tox_Proxy_Type proxy_type;
    char *proto_name = "";
    char *hostname;
    int remote_port;

    char *p;
    unsigned int i = 0;

    env = getenv("ALL_PROXY");
    if(!env)
    {
        env = getenv("all_proxy");
    }

    if(!env)
    {
        return;
    }

    len_of_env = strlen(env);
    if(len_of_env > 1023)
    {
        len_of_env = 1023;
    }

    for(i = 0; i < len_of_env; i++)
    {
        all_proxy[i] = tolower(env[i]);
    }
    all_proxy[len_of_env] = 0;

    if(!strncmp(all_proxy, "socks5://", strlen("socks5://")))
    {
        proxy_type = TOX_PROXY_TYPE_SOCKS5;
        proto_name = "SOCKS5";
        p = all_proxy + strlen("socks5://");
    }
    else
    {
        if(!strncmp(all_proxy, "http://", strlen("http://")))
        {
            proxy_type = TOX_PROXY_TYPE_HTTP;
            proto_name = "HTTP";
            p = all_proxy + strlen("http://");
        }
        else
        {
            log_printf(L_WARNING, "%s is not a valid SOCKS5 or HTTP proxy string", all_proxy);
            return;
        }
    }
    
    if(parse_pipe_port_forward(p, &hostname, &remote_port))
    {
        log_printf(L_WARNING, "%s is not a valid %s proxy string", all_proxy, proto_name);
        return;
    }

    log_printf(L_INFO, "Using %s proxy at %s:%d for Tox network connections", proto_name, hostname, remote_port);
    if(!client_mode)
    {
        log_printf(L_INFO, "%s proxy is not used for outgoing tunneled connections, just for Tox network traffic", proto_name);
    }

    tox_options_set_proxy_type(tox_options, proxy_type);
    tox_options_set_proxy_host(tox_options, hostname);
    tox_options_set_proxy_port(tox_options, remote_port);
    /* TODO: is this necessary? */
    tox_options_set_udp_enabled(tox_options, 0);
}

void help()
{
    fprintf(stdout, "tuntox - Forward ports over the Tox protocol\n\n");
    fprintf(stdout, "Usage:\n");
    fprintf(stdout, "  tuntox ... # starts the server\n");
    fprintf(stdout, "  tuntox -i <servertoxid> -L <localport>:<remoteaddress>:<remoteport> ... # starts the client\n\n");
    fprintf(stdout, "Options:\n");
    fprintf(stdout, "  Server:\n");
    fprintf(stdout, "    -i <toxid>  - whitelisted Tox ID (can be used multiple times)\n");
    fprintf(stdout, "    -f <file>   - only allow connections to hostname/port combinations contained\n");
    fprintf(stdout, "                  in <file>. Rules must be entered one per line with the\n");
    fprintf(stdout, "                  <hostname>:<port> format\n");
    fprintf(stdout, "  Client:\n");
    fprintf(stdout, "    -i <toxid>  - remote point Tox ID\n");
    fprintf(stdout, "    -L <localport>:<remotehostname>:<remoteport>\n");
    fprintf(stdout, "                - forward <remotehostname>:<remoteport> to 127.0.0.1:<localport>\n");
    fprintf(stdout, "    -W <remotehostname>:<remoteport> - forward <remotehostname>:<remoteport> to\n");
    fprintf(stdout, "                                       stdin/stdout (SSH ProxyCommand mode)\n");
    fprintf(stdout, "    -p          - ping the server from -i and exit\n");
    fprintf(stdout, "    -D <localport>\n");
    fprintf(stdout, "                - start a SOCKS5 server on port <localport>\n");
    fprintf(stdout, "  Common:\n");
    fprintf(stdout, "    -C <dir>    - save private key in <dir> instead of /etc/tuntox in server\n");
    fprintf(stdout, "                  mode\n");
    fprintf(stdout, "    -s <secret> - shared secret used for connection authentication (max\n");
    fprintf(stdout, "                  %u characters)\n", TOX_MAX_FRIEND_REQUEST_LENGTH-1);
    fprintf(stdout, "    -I <file>   - save local Tox ID in <file> in clear text format\n");
    fprintf(stdout, "    -t <port>   - set TCP relay port (0 disables TCP relaying)\n");
    fprintf(stdout, "    -u <port>:<port> - set Tox UDP port range\n");
    fprintf(stdout, "    -d          - debug mode (use twice to display toxcore log too)\n");
    fprintf(stdout, "    -q          - quiet mode\n");
    fprintf(stdout, "    -S          - send output to syslog instead of stdout\n");
    fprintf(stdout, "    -z          - daemonize (fork) and exit (implies -S)\n");
    fprintf(stdout, "    -F <path>   - create a PID file named <path>\n");
    fprintf(stdout, "    -U <username|userid> - drop privileges to <username> before forking. Use\n");
    fprintf(stdout, "                           numeric <userid> in static builds.\n");
    fprintf(stdout, "    -b <path>   - bootstrap from Tox nodes in a JSON file like nodes.tox.chat/json\n");
    fprintf(stdout, "    -V          - print version and exit\n");
    fprintf(stdout, "    -h          - this help message\n");
    fprintf(stdout, "Recognized environment variables:\n");
    fprintf(stdout, "  TUNTOX_SHARED_SECRET\n");
    fprintf(stdout, "  ALL_PROXY\n");
}

int main(int argc, char *argv[])
{
    unsigned char tox_id[TOX_ADDRESS_SIZE];
    unsigned char tox_printable_id[TOX_ADDRESS_SIZE * 2 + 1];
    TOX_ERR_NEW tox_new_err;
    int oc;
    size_t save_size = 0;
    uint8_t *save_data = NULL;
    char *tox_id_path = NULL;
    allowed_toxid *allowed_toxid_obj = NULL;
    local_port_forward *port_forward = NULL;
	
    srand(time(NULL));
    tcp_relay_port = 1024 + (rand() % 64511);
    udp_start_port = 1024 + (rand() % 64500);
    udp_end_port = udp_start_port + 10;

    last_forward_id = rand();

    log_init();

    while ((oc = getopt(argc, argv, "L:pi:I:C:s:f:W:dqhSF:D:zU:t:u:b:V")) != -1)
    {
        switch(oc)
        {
            case 'L':
                port_forward = local_port_forward_create();

                if(!port_forward) {
                    log_printf(L_ERROR, "Could not allocate memory for port forward\n");
                    exit(1);
                }

                /* Local port forwarding */
                client_mode = 1;
                client_local_port_mode = 1;


                if(parse_local_port_forward(optarg, &(port_forward->local_port), &(port_forward->remote_host), &(port_forward->remote_port)) < 0)
                {
                    log_printf(L_ERROR, "Invalid value for -L option - use something like -L 22:127.0.0.1:22\n");
                    exit(1);
                }

                LL_APPEND(local_port_forwards, port_forward);

                if(min_log_level == L_UNSET)
                {
                    min_log_level = L_INFO;
                }
                log_printf(L_DEBUG, "Forwarding remote port %d to local port %d\n", port_forward->remote_port, port_forward->local_port);
                break;
            case 'W':
                /* Pipe forwarding */
                port_forward = local_port_forward_create();
                client_mode = 1;
                client_pipe_mode = 1;
                if(parse_pipe_port_forward(optarg, &(port_forward->remote_host), &(port_forward->remote_port)) < 0)
                {
                    log_printf(L_ERROR, "Invalid value for -W option - use something like -W 127.0.0.1:22\n");
                    exit(1);
                }
                if(min_log_level == L_UNSET)
                {
                    min_log_level = L_ERROR;
                }
                LL_APPEND(local_port_forwards, port_forward);
                log_printf(L_INFO, "Forwarding remote port %d to stdin/out\n", port_forward->remote_port);
                break;
            case 'p':
                /* Ping */
                client_mode = 1;
                ping_mode = 1;
                if(min_log_level == L_UNSET)
                {
                    min_log_level = L_INFO;
                }
                break;
            case 'D':
                /* SOCKS5 proxy */
                client_mode = 1;
                if (optarg == NULL || *optarg == '\0') {
                    log_printf(L_ERROR, "Error: Missing or invalid argument for -D option.\n");
                    exit(1);
                }
                char *endptr;
                long int port = strtol(optarg, &endptr, 10);
                if (*endptr != '\0' || port <= 0 || port > 65535) {
                    log_printf(L_ERROR, "Error: Invalid port number for -D option.\n");
                    exit(1);
                }
                socks5_port = (int)port;
                log_printf(L_INFO, "Listening for SOCKS5 on port %d\n", socks5_port);
                break;
            case 'i':
                /* Tox ID */
                server_whitelist_mode = 1;
                log_printf(L_DEBUG, "Server whitelist mode enabled");
                allowed_toxid_obj = (allowed_toxid *)calloc(sizeof(allowed_toxid), 1);
                if(!allowed_toxid_obj)
                {
                    log_printf(L_ERROR, "Could not allocate memory for allowed_toxid");
                    exit(1);
                }
                remote_tox_id = (uint8_t *)optarg;
                if(!string_to_id(allowed_toxid_obj->toxid, (uint8_t *)optarg))
                {
                    log_printf(L_ERROR, "Invalid Tox ID");
                    exit(1);
                }
                LL_APPEND(allowed_toxids, allowed_toxid_obj);
                break;
            case 'I':
                tox_id_path = optarg;
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
                load_saved_toxid_in_client_mode = 1;
                break;
            case 'f':
                strncpy(rules_file, optarg, sizeof(rules_file) - 1);
                rules_policy = VALIDATE;
                log_printf(L_INFO, "Filter policy set to VALIDATE\n");
                break;
            case 's':
                /* Shared secret */
                use_shared_secret = 1;
                memset(shared_secret, 0, TOX_MAX_FRIEND_REQUEST_LENGTH);
                strncpy(shared_secret, optarg, TOX_MAX_FRIEND_REQUEST_LENGTH-1);
                break;
            case 'd':
                if(min_log_level == L_DEBUG2)
                {
                    log_tox_trace = 1;
                }
                if(min_log_level != L_DEBUG && min_log_level != L_DEBUG2) 
                {
                    min_log_level = L_DEBUG;
                }
                else
                {
                    min_log_level = L_DEBUG2;
                }

                break;
            case 'q':
                min_log_level = L_ERROR;
                break;
            case 'S':
                use_syslog = 1;
                break;
            case 'z':
                daemonize = 1;
                use_syslog = 1;
                break;
            case 'F':
                pidfile = optarg;
                break;
            case 'U':
                daemon_username = optarg;
                break;
            case 't':
                errno = 0;
                tcp_relay_port = strtol(optarg, NULL, 10);
                if(errno != 0 || tcp_relay_port < 0 || tcp_relay_port > 65535)
                {
                    tcp_relay_port = 1024 + (rand() % 64511);
                    log_printf(L_WARNING, "Ignored -t %s: TCP port number needs to be a number between 0 and 65535.");
                }
                break;
            case 'u':
                { /* TODO make a function in util.h */
                char *sport;
                char *eport;

                sport = strtok(optarg, ":");
                eport = strtok(NULL, ":");
                if(!sport || !eport)
                {
                    log_printf(L_WARNING, "Ignored -u %s: wrong format");
                }
                else
                {
                    errno = 0;
                    udp_start_port = strtol(sport, NULL, 10);
                    udp_end_port = strtol(eport, NULL, 10);
                    if(errno != 0 || udp_start_port < 1 || udp_start_port > 65535 || \
                       udp_end_port < 1 || udp_end_port > 65535)
                    {
                        log_printf(L_WARNING, "Ignored -u %s: ports need to be integers between 1 and 65535");
                        udp_start_port = 1024 + (rand() % 64500);
                        udp_end_port = udp_start_port + 10;
                    }

                }
                }
                break;
            case 'b':
                strncpy(boot_json, optarg, sizeof(boot_json) - 1);
                break;
            case 'V':
                print_version_stdout();
                exit(0);
            case '?':
            case 'h':
            default:
                print_version();
                help();
                exit(1);
        }
    }

    if(!client_mode && min_log_level == L_UNSET)
    {
        min_log_level = L_INFO;
    }

    if(!client_mode && server_whitelist_mode)
    {
        log_printf(L_INFO, "Server in ToxID whitelisting mode - only clients listed with -i can connect");
    }
    
    if((!client_mode) && (rules_policy != NONE))
    {
        load_rules();
    }

    /* If shared secret has not been provided via -s, read from TUNTOX_SHARED_SECRET env variable */
    if(!use_shared_secret)
    {
        if(getenv("TUNTOX_SHARED_SECRET") != NULL)
        {
            use_shared_secret = 1;
            memset(shared_secret, 0, TOX_MAX_FRIEND_REQUEST_LENGTH);
            strncpy(shared_secret, getenv("TUNTOX_SHARED_SECRET"), TOX_MAX_FRIEND_REQUEST_LENGTH-1);
        }
    }

    if(daemonize)
    {
        do_daemonize();
    }

    atexit(cleanup);

    print_version();

    /* Bootstrap tox */
    tox_options_default(&tox_options);
    if(min_log_level >= L_DEBUG2)
    {
        tox_options.log_callback = on_tox_log;
    }
    tox_options.udp_enabled = 1;
    tox_options.local_discovery_enabled = 1;
    tox_options.tcp_port = tcp_relay_port;
    tox_options.start_port = udp_start_port;
    tox_options.end_port = udp_end_port;
    tox_options.hole_punching_enabled = 1;
    parse_all_proxy(&tox_options);

    log_printf(L_INFO, "Using %d for TCP relay port and %d-%d for UDP", 
        tox_options.tcp_port,
        tox_options.start_port,
        tox_options.end_port
    );

    if((!client_mode) || load_saved_toxid_in_client_mode)
    {
        save_size = load_save(&save_data);
        if(save_data && save_size)
        {
            tox_options.savedata_type = TOX_SAVEDATA_TYPE_TOX_SAVE;
            tox_options.savedata_data = save_data;
            tox_options.savedata_length = save_size;
        }
    }

    tox = tox_new(&tox_options, &tox_new_err);
    if(tox == NULL)
    {
        log_printf(L_DEBUG, "tox_new() failed (%u) - trying without IPv6\n", tox_new_err);
        if(!tox_options.ipv6_enabled || (tox_options.ipv6_enabled = 0, (tox = tox_new(&tox_options, &tox_new_err)) == NULL))
        {
            log_printf(L_DEBUG, "tox_new() failed (%u) - trying with Tor\n", tox_new_err);
            if((tox_options.proxy_type = TOX_PROXY_TYPE_SOCKS5, tox_options.proxy_host="127.0.0.1", tox_options.proxy_port=9050, (tox = tox_new(&tox_options, &tox_new_err)) == NULL))
            {
                log_printf(L_ERROR, "tox_new() failed (%u) - exiting\n", tox_new_err);
                exit(1);
            }
        }
    }

    if(save_size && save_data)
    {
        free(save_data);
    }

    set_tox_username(tox);
    tox_callback_self_connection_status(tox, handle_connection_status_change);

    do_bootstrap(tox);
    do_bootstrap_file(tox, boot_json);

    if(client_mode)
    {
        uint8_t dht_key[TOX_PUBLIC_KEY_SIZE];
        char_t readable_dht_key[2 * TOX_PUBLIC_KEY_SIZE + 1];

        tox_self_get_address(tox, tox_id);
        id_to_string(tox_printable_id, tox_id);
        tox_printable_id[TOX_ADDRESS_SIZE * 2] = '\0';
        log_printf(L_DEBUG, "Generated Tox ID: %s\n", tox_printable_id);

        if(tox_id_path)
        {
            save_printable_tox_id(tox_printable_id, tox_id_path);
        }

        tox_self_get_dht_id(tox, dht_key);
        to_hex(readable_dht_key, dht_key, TOX_PUBLIC_KEY_SIZE);
        log_printf(L_DEBUG, "DHT key: %s\n", readable_dht_key);

        if(!remote_tox_id)
        {
            log_printf(L_ERROR, "Tox id is required in client mode. Use -i 58435984ABCDEF475...\n");
            exit(1);
        }
        do_client_loop(remote_tox_id);
    }
    else
    {
        uint8_t dht_key[TOX_PUBLIC_KEY_SIZE];
        char_t readable_dht_key[2 * TOX_PUBLIC_KEY_SIZE + 1];

        write_save(tox);

        if(!use_shared_secret)
        {
            log_printf(L_WARNING, "Shared secret authentication is not used - skilled attackers may connect to your tuntox server");
        }

        tox_self_get_address(tox, tox_id);
        memset(tox_printable_id, '\0', sizeof(tox_printable_id));
        id_to_string(tox_printable_id, tox_id);
        tox_printable_id[TOX_ADDRESS_SIZE * 2] = '\0';
        log_printf(L_INFO, "Using Tox ID: %s\n", tox_printable_id);

        if(tox_id_path)
        {
            save_printable_tox_id(tox_printable_id, tox_id_path);
        }

        tox_self_get_dht_id(tox, dht_key);
        to_hex(readable_dht_key, dht_key, TOX_PUBLIC_KEY_SIZE);
        log_printf(L_DEBUG, "DHT key: %s\n", readable_dht_key);

        tox_callback_friend_request(tox, accept_friend_request);
        do_server_loop();
        clear_rules();
    }

    return 0;
}
