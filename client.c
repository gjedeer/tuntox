#include "main.h"
#include "client.h"

/* The state machine */
int state = CLIENT_STATE_INITIAL;

/* Used in ping mode */
struct timespec ping_sent_time;

/* Client mode tunnel */
tunnel client_tunnel;

fd_set client_master_fdset;

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

int local_bind(tunnel *tun)
{
    struct addrinfo hints, *res;
    int sockfd;
    char port[6];
    int yes = 1;

    /* accept() variables - TODO they should not be there */
    int newfd;
    struct sockaddr_storage remoteaddr; // client address
    socklen_t addrlen;

    snprintf(port, 6, "%d", local_port);

    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_UNSPEC;  // use IPv4 or IPv6, whichever
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_PASSIVE;     // fill in my IP for me

    getaddrinfo(NULL, port, &hints, &res);

    sockfd = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
    if(sockfd < 0)
    {
        fprintf(stderr, "Could not create a socket for local listening\n");
        exit(1);
    }

    setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(int));

    if(bind(sockfd, res->ai_addr, res->ai_addrlen) < 0)
    {
        fprintf(stderr, "Bind to port %d failed: %s", local_port, strerror(errno));
        close(sockfd);
        exit(1);
    }

    if(listen(sockfd, 1) < 0)
    {
        fprintf(stderr, "Listening on port %d failed: %s", local_port, strerror(errno));
        close(sockfd);
        exit(1);
    }

    // TODO return sockfd

    /* TODO: make a proper accept loop and track tunnels, to handle more than 1 connection */
    addrlen = sizeof(remoteaddr);
    newfd = accept(sockfd, 
            (struct sockaddr *)&remoteaddr,
            &addrlen);

    if(newfd < 0)
    {
        fprintf(stderr, "Error when accepting a local connection: %s\n", strerror(errno));
        close(sockfd);
        exit(0);
    }

//    TODO close(sockfd);

    return newfd;
}

int handle_acktunnel_frame(protocol_frame *rcvd_frame)
{
    if(!client_mode)
    {
        fprintf(stderr, "Got ACK tunnel frame when not in client mode!?\n");
        return -1;
    }

    client_tunnel.connid = rcvd_frame->connid;
    client_tunnel.friendnumber = rcvd_frame->friendnumber;
    // TODO open local port and fill client_tunnel.sockfd
    printf("New tunnel ID: %d\n", client_tunnel.connid);

    if(client_local_port_mode)
    {
        client_tunnel.sockfd = local_bind(&client_tunnel);
        update_select_nfds(client_tunnel.sockfd);
        FD_SET(client_tunnel.sockfd, &client_master_fdset);
        fprintf(stderr, "Accepting connections on port %d\n", local_port);
        state = CLIENT_STATE_FORWARDING;
    }
    else
    {
        fprintf(stderr, "This tunnel mode is not supported yet");
        exit(1);
    }
}

/* Handle a TCP frame received from server */
int handle_server_tcp_frame(protocol_frame *rcvd_frame)
{
    /* TODO find tunnel basing on ID */
    int offset = 0;
    tunnel *tun = &client_tunnel;

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

/* Main loop for the client */
int do_client_loop(char *tox_id_str)
{
    unsigned char tox_packet_buf[PROTOCOL_MAX_PACKET_SIZE];
    unsigned char tox_id[TOX_FRIEND_ADDRESS_SIZE];
    uint32_t friendnumber;
    struct timeval tv;
    fd_set fds;

    client_tunnel.sockfd = 0;
    FD_ZERO(&client_master_fdset);

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
            case CLIENT_STATE_FORWARDING:
                {
                    tv.tv_sec = 0;
                    tv.tv_usec = 20000;
                    fds = client_master_fdset;

                    select(select_nfds, &fds, NULL, NULL, &tv);
                    
                    if(FD_ISSET(client_tunnel.sockfd, &fds))
                    {
                        int nbytes = recv(client_tunnel.sockfd, 
                                tox_packet_buf + PROTOCOL_BUFFER_OFFSET, 
                                READ_BUFFER_SIZE, 0);

                        /* Check if connection closed */
                        if(nbytes == 0)
                        {
                            char data[PROTOCOL_BUFFER_OFFSET];
                            protocol_frame frame_st, *frame;

                            fprintf(stderr, "Connection closed\n");

                            frame = &frame_st;
                            memset(frame, 0, sizeof(protocol_frame));
                            frame->friendnumber = client_tunnel.friendnumber;
                            frame->packet_type = PACKET_TYPE_TCP_FIN;
                            frame->connid = client_tunnel.connid;
                            frame->data_length = 0;
                            send_frame(frame, data);

                            state = CLIENT_STATE_SHUTDOWN;

//                            exit(1); // TODO handle it in a smarter way (accept() again?)
                        }
                        else
                        {
                            protocol_frame frame_st, *frame;

                            frame = &frame_st;
                            memset(frame, 0, sizeof(protocol_frame));
                            frame->friendnumber = client_tunnel.friendnumber;
                            frame->packet_type = PACKET_TYPE_TCP;
                            frame->connid = client_tunnel.connid;
                            frame->data_length = nbytes;
                            send_frame(frame, tox_packet_buf);
                        }
                    }

                    fds = client_master_fdset;
                }
                break;
            case CLIENT_STATE_SHUTDOWN:
                exit(0);
                break;
        }

        usleep(tox_do_interval(tox) * 1000);
    }
}

