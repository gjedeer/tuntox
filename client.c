#include "main.h"
#include "client.h"

/* The state machine */
int state = CLIENT_STATE_INITIAL;

/* Used in ping mode */
struct timespec ping_sent_time;

/* Client mode tunnel */
tunnel client_tunnel;

/* Sock representing the local port - call accept() on it */
int bind_sockfd;

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

int local_bind()
{
    struct addrinfo hints, *res;
    char port[6];
    int yes = 1;
    int flags;

    snprintf(port, 6, "%d", local_port);

    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_UNSPEC;  // use IPv4 or IPv6, whichever
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_PASSIVE;     // fill in my IP for me

    getaddrinfo(NULL, port, &hints, &res);

    bind_sockfd = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
    if(bind_sockfd < 0)
    {
        fprintf(stderr, "Could not create a socket for local listening: %s\n", strerror(errno));
        exit(1);
    }

    setsockopt(bind_sockfd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(int));

    /* Set O_NONBLOCK to make accept() non-blocking */
    if (-1 == (flags = fcntl(bind_sockfd, F_GETFL, 0)))
    {
        flags = 0;
    }
    fcntl(bind_sockfd, F_SETFL, flags | O_NONBLOCK);

    if(bind(bind_sockfd, res->ai_addr, res->ai_addrlen) < 0)
    {
        fprintf(stderr, "Bind to port %d failed: %s\n", local_port, strerror(errno));
        close(bind_sockfd);
        exit(1);
    }

    if(listen(bind_sockfd, 1) < 0)
    {
        fprintf(stderr, "Listening on port %d failed: %s\n", local_port, strerror(errno));
        close(bind_sockfd);
        exit(1);
    }

    fprintf(stderr, "Bound to local port %d\n", local_port);
}

/* Bind the client.sockfd to a tunnel */
int handle_acktunnel_frame(protocol_frame *rcvd_frame)
{
    tunnel *tun;

    if(!client_mode)
    {
        fprintf(stderr, "Got ACK tunnel frame when not in client mode!?\n");
        return -1;
    }

    tun = tunnel_create(
            client_tunnel.sockfd,
            rcvd_frame->connid,
            rcvd_frame->friendnumber
    );

    /* Mark that we can accept() another connection */
    client_tunnel.sockfd = -1;

    printf("New tunnel ID: %d\n", tun->connid);

    if(client_local_port_mode)
    {
        update_select_nfds(tun->sockfd);
        FD_SET(tun->sockfd, &client_master_fdset);
        fprintf(stderr, "Accepted a new connection on port %d\n", local_port);
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
    int offset = 0;
    tunnel *tun = NULL;
    int tun_id = rcvd_frame->connid;

    HASH_FIND_INT(by_id, &tun_id, tun);

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
                MSG_NOSIGNAL
        );

        if(sent_bytes < 0)
        {
            char data[PROTOCOL_BUFFER_OFFSET];
            protocol_frame frame_st, *frame;

            fprintf(stderr, "Could not write to socket %d: %s\n", tun->sockfd, strerror(errno));

            frame = &frame_st;
            memset(frame, 0, sizeof(protocol_frame));
            frame->friendnumber = tun->friendnumber;
            frame->packet_type = PACKET_TYPE_TCP_FIN;
            frame->connid = tun->connid;
            frame->data_length = 0;
            send_frame(frame, data);
            tunnel_delete(tun);

            return -1;
        }

        offset += sent_bytes;
    }

    printf("Got %d bytes from server - wrote to fd %d\n", rcvd_frame->data_length, tun->sockfd);

    return 0;
}

/* Handle close-tunnel frame recived from the server */
int handle_server_tcp_fin_frame(protocol_frame *rcvd_frame)
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
        fprintf(stderr, "Friend #%d tried to close tunnel while server is #%d\n", rcvd_frame->friendnumber, tun->friendnumber);
        return -1;
    }
    
    tunnel_delete(tun);
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

    if(!ping_mode) /* TODO handle pipe mode */
    {
        local_bind();
        signal(SIGPIPE, SIG_IGN);
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
                    state = CLIENT_STATE_BIND_PORT;
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

            case CLIENT_STATE_BIND_PORT:
                if(bind_sockfd < 0)
                {
                    fprintf(stderr, "Shutting down - could not bind to listening port\n");
                    state = CLIENT_STATE_SHUTDOWN;
                }
                else
                {
                    state = CLIENT_STATE_FORWARDING;
                }
                break;
            case CLIENT_STATE_REQUEST_TUNNEL:
                send_tunnel_request_packet(
                        remote_host,
                        remote_port,
                        friendnumber
                );
                state = CLIENT_STATE_WAIT_FOR_ACKTUNNEL;
                break;
            case CLIENT_STATE_WAIT_FOR_ACKTUNNEL:
                break;
            case CLIENT_STATE_FORWARDING:
                {
                    int accept_fd = 0;
                    tunnel *tmp = NULL;
                    tunnel *tun = NULL;

                    tv.tv_sec = 0;
                    tv.tv_usec = 20000;
                    fds = client_master_fdset;
                    
                    /* Handle accepting new connections */
                    if(client_tunnel.sockfd <= 0) /* Don't accept if we're already waiting to establish a tunnel */
                    {
                        accept_fd = accept(bind_sockfd, NULL, NULL);
                        if(accept_fd != -1)
                        {
                            fprintf(stderr, "Accepting a new connection - requesting tunnel...\n");

                            /* Open a new tunnel for this FD */
                            client_tunnel.sockfd = accept_fd;
                            send_tunnel_request_packet(
                                    remote_host,
                                    remote_port,
                                    friendnumber
                            );
                        }
                    }

                    /* Handle reading from sockets */
                    select(select_nfds, &fds, NULL, NULL, &tv);
                    HASH_ITER(hh, by_id, tun, tmp)
                    {
                        if(FD_ISSET(tun->sockfd, &fds))
                        {
                            int nbytes = recv(tun->sockfd, 
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
                                frame->friendnumber = tun->friendnumber;
                                frame->packet_type = PACKET_TYPE_TCP_FIN;
                                frame->connid = tun->connid;
                                frame->data_length = 0;
                                send_frame(frame, data);
                                tunnel_delete(tun);
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

                                printf("Wrote %d bytes from sock %d to tunnel %d\n", nbytes, tun->sockfd, tun->connid);
                            }
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

