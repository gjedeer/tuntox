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
#include <tox/tox.h>
#include <unistd.h>

#include "main.h"
#include "tox_bootstrap.h"

static Tox_Options tox_options;
static Tox *tox;
int client_socket = 0;

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
    char_t b, c, *end = p + size;

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

void accept_friend_request(Tox *tox, const uint8_t *public_key, const uint8_t *data, uint16_t length, void *userdata)
{
    unsigned char tox_printable_id[TOX_FRIEND_ADDRESS_SIZE * 2 + 1];

    printf("Got friend request\n");
    tox_add_friend_norequest(tox, public_key);
    id_to_string(tox_printable_id, public_key);
    printf("Accepted friend request from %s\n", tox_printable_id);
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
int get_client_socket()
{
    int sockfd, numbytes;  
    char buf[READ_BUFFER_SIZE];
    struct addrinfo hints, *servinfo, *p;
    int rv;
    char s[INET6_ADDRSTRLEN];
    int port = 22;
    char hostname[4096] = "127.0.0.1";
    char port_str[6];

    snprintf(port_str, 6, "%d", port);

    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;

    if ((rv = getaddrinfo(hostname, port_str, &hints, &servinfo)) != 0) {
        fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(rv));
	exit(1);
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

unsigned int create_packet(unsigned char *dst, unsigned char *data, int data_len, int sockfd)
{
// assert data_len < 65536
    dst[0] = 0xa2;
    dst[1] = 0x6a;
    dst[2] = sockfd >> 8;
    dst[3] = sockfd & 0xff;
    dst[4] = (data_len >> 8) & 0xff;
    dst[5] = data_len & 0xff;
    memcpy(dst+PROTOCOL_BUFFER_OFFSET, data, data_len);
    return data_len + PROTOCOL_BUFFER_OFFSET;
}

int do_loop()
{
    struct timeval tv;
    fd_set fds;
    fd_set master;
    unsigned char read_buf[READ_BUFFER_SIZE+1];
    unsigned char tox_packet_buf[PROTOCOL_MAX_PACKET_SIZE];

    tv.tv_sec = 0;
    tv.tv_usec = 20000;

    FD_ZERO(&fds);
    FD_SET(client_socket, &fds);

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
		tox_packet_length = create_packet(tox_packet_buf, read_buf, nbytes, client_socket);
		tox_send_lossless_packet(tox, 0, tox_packet_buf, tox_packet_length);
		printf("READ: %s\n", read_buf);
	    }
	}

	fds = master;
    }
}

int main(int argc, char *argv[])
{
    unsigned char tox_id[TOX_FRIEND_ADDRESS_SIZE];
    unsigned char tox_printable_id[TOX_FRIEND_ADDRESS_SIZE * 2 + 1];

    on_exit(cleanup, NULL);

    /* Bootstrap tox */
    tox_options.ipv6enabled = TOX_ENABLE_IPV6_DEFAULT;
    tox_options.udp_disabled = 0;
    tox_options.proxy_enabled = 0;

    tox = tox_new(&tox_options);

    tox_callback_friend_request(tox, accept_friend_request, NULL);

    set_tox_username(tox);

    tox_get_address(tox, tox_id);
    id_to_string(tox_printable_id, tox_id);
    tox_printable_id[TOX_FRIEND_ADDRESS_SIZE * 2] = '\0';
    printf("Generated Tox ID: %s\n", tox_printable_id);

    do_bootstrap(tox);

    /* Connect to the forwarded service */
    client_socket = get_client_socket();

    do_loop();

    return 0;
}
