#include <time.h>

/* MacOS related */
#ifdef __MACH__
#include "mach.h"
#endif

#include "log.h"
#include "main.h"
#include "client.h"

/* The state machine */
int state = CLIENT_STATE_INITIAL;

/* Used in ping mode */
struct timespec ping_sent_time;

fd_set client_master_fdset;
int client_select_nfds;

int handle_pong_frame()
{
    struct timespec pong_rcvd_time;
    double secs1, secs2;

    clock_gettime(CLOCK_MONOTONIC, &pong_rcvd_time);

    secs1 = (1.0 * ping_sent_time.tv_sec) + (1e-9 * ping_sent_time.tv_nsec);
    secs2 = (1.0 * pong_rcvd_time.tv_sec) + (1e-9 * pong_rcvd_time.tv_nsec);

    log_printf(L_INFO, "GOT PONG! Time = %.3fs\n", secs2-secs1);

    if(ping_mode)
    {
        state = CLIENT_STATE_SEND_PING;
    }
    return 0;
}

int local_bind_one(local_port_forward *port_forward)
{
    struct addrinfo hints, *res;
    char port[6];
    int yes = 1;
    int flags;
    int gai_status;
    int setsockopt_status;

    snprintf(port, 6, "%d", port_forward->local_port);

    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_UNSPEC;  // use IPv4 or IPv6, whichever
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_PASSIVE;     // fill in my IP for me

    gai_status = getaddrinfo(NULL, port, &hints, &res);
    if(gai_status != 0)
    {
        log_printf(L_ERROR, "getaddrinfo: %s\n", gai_strerror(gai_status));
        exit(1);
    }

    port_forward->bind_sockfd = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
    if(port_forward->bind_sockfd < 0)
    {
        log_printf(L_ERROR, "Could not create a socket for local listening: %s\n", strerror(errno));
        freeaddrinfo(res);
        exit(1);
    }

    setsockopt_status = setsockopt(port_forward->bind_sockfd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(int));
    if(setsockopt_status < 0)
    {
        log_printf(L_ERROR, "Could not set socket options: %s\n", 
                strerror(errno));
        freeaddrinfo(res);
        exit(1);
    }

    /* Set O_NONBLOCK to make accept() non-blocking */
    if (-1 == (flags = fcntl(port_forward->bind_sockfd, F_GETFL, 0)))
    {
        flags = 0;
    }
    if(fcntl(port_forward->bind_sockfd, F_SETFL, flags | O_NONBLOCK) < 0)
    {
        log_printf(L_ERROR, "Could not make the socket non-blocking: %s\n", strerror(errno));
        freeaddrinfo(res);
        exit(1);
    }

    if(bind(port_forward->bind_sockfd, res->ai_addr, res->ai_addrlen) < 0)
    {
        log_printf(L_ERROR, "Bind to port %d failed: %s\n", port_forward->local_port, strerror(errno));
        freeaddrinfo(res);
        close(port_forward->bind_sockfd);
        exit(1);
    }

    freeaddrinfo(res);

    if(listen(port_forward->bind_sockfd, 1) < 0)
    {
        log_printf(L_ERROR, "Listening on port %d failed: %s\n", port_forward->local_port, strerror(errno));
        close(port_forward->bind_sockfd);
        exit(1);
    }

    log_printf(L_DEBUG, "Bound to local port %d sockfd %d\n", port_forward->local_port, port_forward->bind_sockfd);

    return 0;
}

void local_bind() {
    local_port_forward *port_forward;

    LL_FOREACH(local_port_forwards, port_forward)
    {
        local_bind_one(port_forward);
    }
}

/* Bind the client.sockfd to a tunnel */
int handle_acktunnel_frame(protocol_frame *rcvd_frame)
{
    uint32_t local_forward_id;
    local_port_forward *forward;
    tunnel *tun;

    if(!client_mode)
    {
        log_printf(L_WARNING, "Got ACK tunnel frame when not in client mode!?\n");
        return -1;
    }

    if(rcvd_frame->data_length < 3)
    {
        log_printf(L_WARNING, "Got ACK tunnel frame with not enough data");
        return -1;
    }

    if(rcvd_frame->data_length > PROTOCOL_MAX_PACKET_SIZE) {
        log_printf(L_WARNING, "Got ACK tunnel with wrong data length");
        return -1;
    }

    local_forward_id = INT32_AT((rcvd_frame->data), 0);

    log_printf(L_DEBUG2, "Got ACK tunnel frame for local forward %ld", local_forward_id);

    forward = find_pending_forward_by_id(local_forward_id);
    if(!forward)
    {
        log_printf(L_WARNING, "Got ACK tunnel with wrong forward ID %ld", local_forward_id);
        return -1;
    }

    tun = tunnel_create(
            forward->accept_sockfd, /* sockfd */
            rcvd_frame->connid,
            rcvd_frame->friendnumber
    );

    /* Mark that we can accept() another connection */
    forward->accept_sockfd = -1;

    if(client_local_port_mode || client_pipe_mode)
    {
        FD_SET(tun->sockfd, &client_master_fdset);
        update_select_nfds(tun->sockfd, &client_master_fdset, &client_select_nfds);
        if(client_local_port_mode)
        {
            log_printf(L_INFO, "Accepted a new connection on port %d sockfd %d connid %d\n", forward->local_port, tun->sockfd, tun->connid);
        }
    }
    else
    {
        log_printf(L_ERROR, "This tunnel mode is not supported yet\n");
        exit(1);
    }

    return 0;
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
        log_printf(L_WARNING, "Got TCP frame with unknown tunnel ID %d\n", rcvd_frame->connid);
        return -1;
    }

    while(offset < rcvd_frame->data_length)
    {
        int sent_bytes;

        if(client_pipe_mode)
        {
            sent_bytes = write(
                    1, /* STDOUT */
                    rcvd_frame->data + offset,
                    rcvd_frame->data_length - offset
            );
        }
        else
        {
            sent_bytes = send(
                    tun->sockfd, 
                    rcvd_frame->data + offset,
                    rcvd_frame->data_length - offset,
                    MSG_NOSIGNAL
            );
        }


        if(sent_bytes < 0)
        {
            uint8_t data[PROTOCOL_BUFFER_OFFSET];
            protocol_frame frame_st, *frame;

            log_printf(L_INFO, "Could not write to socket: %s\n", strerror(errno));

            frame = &frame_st;
            memset(frame, 0, sizeof(protocol_frame));
            frame->friendnumber = tun->friendnumber;
            frame->packet_type = PACKET_TYPE_TCP_FIN;
            frame->connid = tun->connid;
            frame->data_length = 0;
            send_frame(frame, data);
            if(tun->sockfd)
            {
                FD_CLR(tun->sockfd, &client_master_fdset);
            }
            tunnel_delete(tun);

            return -1;
        }

        offset += sent_bytes;
    }

//    printf("Got %d bytes from server - wrote to fd %d\n", rcvd_frame->data_length, tun->sockfd);

    return 0;
}

/* Delete tunnel and clear client-side fdset */
void client_close_tunnel(tunnel *tun) 
{
    if(tun->sockfd)
    {
        FD_CLR(tun->sockfd, &client_master_fdset);
    }

    tunnel_delete(tun);
}

/* Handle close-tunnel frame recived from the server */
int handle_server_tcp_fin_frame(protocol_frame *rcvd_frame)
{
    tunnel *tun=NULL;
    int connid = rcvd_frame->connid;

    HASH_FIND_INT(by_id, &connid, tun);

    if(!tun)
    {
        log_printf(L_WARNING, "Got TCP FIN frame with unknown tunnel ID %d\n", rcvd_frame->connid);
        return -1;
    }

    if(tun->friendnumber != rcvd_frame->friendnumber)
    {
        log_printf(L_WARNING, "Friend #%d tried to close tunnel while server is #%d\n", rcvd_frame->friendnumber, tun->friendnumber);
        return -1;
    }

    client_close_tunnel(tun);

    return 0;
}

/* Close and delete all tunnels (when server went offline) */
void client_close_all_connections()
{
    tunnel *tmp = NULL;
    tunnel *tun = NULL;

    HASH_ITER(hh, by_id, tun, tmp)
    {
        client_close_tunnel(tun);
    }
}

void on_friend_connection_status_changed(Tox *tox, uint32_t friend_number, Tox_Connection connection_status,
        void *user_data)
{
    const char* status = readable_connection_status(connection_status);
    log_printf(L_INFO, "Friend connection status changed to: %s (%d)\n", status, connection_status);

    if(connection_status == TOX_CONNECTION_NONE)
    {
        state = CLIENT_STATE_CONNECTION_LOST;
    }
}


/* Main loop for the client */
int do_client_loop(uint8_t *tox_id_str)
{
    unsigned char tox_packet_buf[PROTOCOL_MAX_PACKET_SIZE];
    unsigned char tox_id[TOX_ADDRESS_SIZE];
    uint32_t friendnumber = 0;
    struct timeval tv;
    fd_set fds;
    static time_t invitation_sent_time = 0;
    uint32_t invitations_sent = 0;
    TOX_ERR_FRIEND_QUERY friend_query_error;
    TOX_ERR_FRIEND_CUSTOM_PACKET custom_packet_error;
    local_port_forward *port_forward;

    FD_ZERO(&client_master_fdset);

    tox_callback_friend_lossless_packet(tox, parse_lossless_packet);
    tox_callback_friend_connection_status(tox, on_friend_connection_status_changed);

    if(!string_to_id(tox_id, tox_id_str))
    {
        log_printf(L_ERROR, "Invalid Tox ID");
        exit(1);
    }

    if(!ping_mode && !client_pipe_mode)
    {
        local_bind();
        signal(SIGPIPE, SIG_IGN);
    }

    log_printf(L_INFO, "Connecting to Tox...\n");

    while(1)
    {
        /* Let tox do its stuff */
        tox_iterate(tox, NULL);

        switch(state)
        {
            /* 
             * Send friend request
             */
            case CLIENT_STATE_INITIAL:
                if(connection_status != TOX_CONNECTION_NONE)
                {
                    state = CLIENT_STATE_CONNECTED;
                    log_printf(L_DEBUG2, "Entered CLIENT_STATE_CONNECTED");
                }
                break;
            case CLIENT_STATE_CONNECTED:
                {
                    uint8_t* data = (uint8_t *)"Hi, fellow tuntox instance!";
                    uint16_t length = sizeof(data);
                    /* https://github.com/TokTok/c-toxcore/blob/acb6b2d8543c8f2ea0c2e60dc046767cf5cc0de8/toxcore/tox.h#L1168 */
                    TOX_ERR_FRIEND_ADD add_error;

                    if(use_shared_secret)
                    {
                        data = (uint8_t *)shared_secret;
                        data[TOX_MAX_FRIEND_REQUEST_LENGTH-1] = '\0';
                        length = strlen((char *)data)+1;
                        log_printf(L_DEBUG, "Sent shared secret of length %u\n", length);
                    }

                    if(invitations_sent == 0)
                    {
                        log_printf(L_INFO, "Connected. Sending friend request.\n");
                    }
                    else
                    {
                        log_printf(L_INFO, "Sending another friend request.\n");
                    }

                    friendnumber = tox_friend_add(
                            tox,
                            tox_id,
                            data,
                            length,
                            &add_error
                    );

                    if(add_error != TOX_ERR_FRIEND_ADD_OK)
                    {
                        unsigned char tox_printable_id[TOX_ADDRESS_SIZE * 2 + 1];
                        id_to_string(tox_printable_id, tox_id);
                        log_printf(L_ERROR, "Error %u adding friend %s\n", add_error, tox_printable_id);
                        exit(-1);
                    }

                    invitation_sent_time = time(NULL);
                    invitations_sent++;
                    state = CLIENT_STATE_SENTREQUEST;
                    log_printf(L_DEBUG2, "Entered CLIENT_STATE_SENTREQUEST");
                    log_printf(L_INFO, "Waiting for friend to accept us...\n");
                }
                break;
            case CLIENT_STATE_SENTREQUEST:
                {
                    TOX_CONNECTION friend_connection_status;
                    friend_connection_status = tox_friend_get_connection_status(tox, friendnumber, &friend_query_error);
                    if(friend_query_error != TOX_ERR_FRIEND_QUERY_OK)
                    {
                        log_printf(L_DEBUG, "tox_friend_get_connection_status: error %u", friend_query_error);
                    }
                    else
                    {
                        if(friend_connection_status != TOX_CONNECTION_NONE)
                        {
                            const char* status = readable_connection_status(friend_connection_status);
                            log_printf(L_INFO, "Friend request accepted (%s)!\n", status);
                            state = CLIENT_STATE_REQUEST_ACCEPTED;
                            log_printf(L_DEBUG2, "Entered CLIENT_STATE_REQUEST_ACCEPTED");
                        }
                        else
                        {
                            if(1 && (time(NULL) - invitation_sent_time > 45))
                            {
                                TOX_ERR_FRIEND_DELETE error = 0;

                                log_printf(L_INFO, "Sending another friend request...");
                                tox_friend_delete(
                                        tox,
                                        friendnumber,
                                        &error);
                                if(error != TOX_ERR_FRIEND_DELETE_OK)
                                {
                                    log_printf(L_ERROR, "Error %u deleting friend before reconnection\n", error);
                                    exit(-1);
                                }

                                state = CLIENT_STATE_CONNECTED;
                                log_printf(L_DEBUG2, "Entered CLIENT_STATE_CONNECTED");
                            }
                        }
                    }
                    break;
                }
            case CLIENT_STATE_REQUEST_ACCEPTED:
                if(ping_mode)
                {
                    state = CLIENT_STATE_SEND_PING;
                    log_printf(L_DEBUG2, "Entered CLIENT_STATE_SEND_PING");
                }
                else if(client_pipe_mode)
                {
                    state = CLIENT_STATE_SETUP_PIPE;
                    log_printf(L_DEBUG2, "Entered CLIENT_STATE_SETUP_PIPE");
                }
                else
                {
                    state = CLIENT_STATE_BIND_PORT;
                    log_printf(L_DEBUG2, "Entered CLIENT_STATE_BIND_PORT");
                }
                break;
            case CLIENT_STATE_SEND_PING:
                /* Send the ping packet */
                {
                    uint8_t data[] = {
                        0xa2, 0x6b, 0x01, 0x08, 0x00, 0x00, 0x00, 0x05, 
                        0x48, 0x65, 0x6c, 0x6c, 0x6f
                    };

                    clock_gettime(CLOCK_MONOTONIC, &ping_sent_time);
                    tox_friend_send_lossless_packet(
                            tox,
                            friendnumber,
                            data,
                            sizeof(data),
                            &custom_packet_error
                    );
                }
                if(custom_packet_error == TOX_ERR_FRIEND_CUSTOM_PACKET_OK)
                {
                    state = CLIENT_STATE_PING_SENT;
                    log_printf(L_DEBUG2, "Entered CLIENT_STATE_PING_SENT");
                }
                else
                {
                    log_printf(L_WARNING, "When sending ping packet: %u", custom_packet_error);
                }
                break;
            case CLIENT_STATE_PING_SENT:
                /* Just sit there and wait for pong */
                break;

            case CLIENT_STATE_BIND_PORT:
                LL_FOREACH(local_port_forwards, port_forward)
                {
                    log_printf(L_DEBUG2, "Processing local port %d", port_forward->local_port);
                    if(port_forward->bind_sockfd < 0)
                    {
                        log_printf(L_ERROR, "Shutting down - could not bind to listening port %d\n", port_forward->local_port);
                        state = CLIENT_STATE_SHUTDOWN;
                        log_printf(L_DEBUG2, "Entered CLIENT_STATE_SHUTDOWN");
                        break;
                    }
                    else
                    {
                        state = CLIENT_STATE_FORWARDING;
                        log_printf(L_DEBUG2, "Entered CLIENT_STATE_FORWARDING");
                    }
                }
                break;
            case CLIENT_STATE_SETUP_PIPE:
                LL_FOREACH(local_port_forwards, port_forward)
                {
                    send_tunnel_request_packet(
                            port_forward->remote_host,
                            port_forward->remote_port,
                            port_forward->forward_id,
                            friendnumber
                    );
                }
                state = CLIENT_STATE_FORWARDING;
                log_printf(L_DEBUG2, "Entered CLIENT_STATE_FORWARDING");
                break;
            case CLIENT_STATE_REQUEST_TUNNEL:
                LL_FOREACH(local_port_forwards, port_forward)
                {
                    send_tunnel_request_packet(
                            port_forward->remote_host,
                            port_forward->remote_port,
                            port_forward->forward_id,
                            friendnumber
                    );
                }
                state = CLIENT_STATE_WAIT_FOR_ACKTUNNEL;
                break;
            case CLIENT_STATE_WAIT_FOR_ACKTUNNEL:
                LL_FOREACH(local_port_forwards, port_forward)
                {
                    port_forward->accept_sockfd = 0;
                    send_tunnel_request_packet(
                            port_forward->remote_host,
                            port_forward->remote_port,
                            port_forward->forward_id,
                            friendnumber
                    );
                }
                break;
            case CLIENT_STATE_FORWARDING:
                {
                    int accept_fd = 0;
                    int select_rv = 0;
                    tunnel *tmp = NULL;
                    tunnel *tun = NULL;
                    local_port_forward *port_forward;

                    tv.tv_sec = 0;
                    tv.tv_usec = 20000;
                    fds = client_master_fdset;

                    /* Handle accepting new connections */
                    LL_FOREACH(local_port_forwards, port_forward)
                    {
                        if(!client_pipe_mode &&
                            port_forward->accept_sockfd <= 0) /* Don't accept if we're already waiting to establish a tunnel */
                        {
                            //log_printf(L_DEBUG2, "FORWARDING: checking fd %d for local port %d", port_forward->bind_sockfd, port_forward->local_port);
                            accept_fd = accept(port_forward->bind_sockfd, NULL, NULL);
                            if(accept_fd != -1)
                            {
                                log_printf(L_INFO, "Accepting a new connection - requesting tunnel...\n");

                                /* Open a new tunnel for this FD */
                                port_forward->accept_sockfd = accept_fd;
                                send_tunnel_request_packet(
                                        port_forward->remote_host,
                                        port_forward->remote_port,
                                        port_forward->forward_id,
                                        friendnumber
                                );
                            }
                            else
                            {
                                if(errno != EAGAIN && errno != EWOULDBLOCK) 
                                {
                                    log_printf(L_DEBUG, "Accept failed: code=%d (%s)\n", errno, strerror(errno));
                                } 
                                else 
                                {
                                    log_printf(L_DEBUG2, "Accept would block, no incoming connection right now\n");
                                }
                            }
                        }
                    }

                    /* Handle reading from sockets */
                    select_rv = select(client_select_nfds, &fds, NULL, NULL, &tv);
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
                        HASH_ITER(hh, by_id, tun, tmp)
                        {
                            if(FD_ISSET(tun->sockfd, &fds))
                            {
                                int nbytes;
                                if(client_local_port_mode)
                                {
                                    nbytes = recv(tun->sockfd, 
                                            tox_packet_buf + PROTOCOL_BUFFER_OFFSET, 
                                            READ_BUFFER_SIZE, 0);
                                }
                                else
                                {
                                    nbytes = read(tun->sockfd,
                                            tox_packet_buf + PROTOCOL_BUFFER_OFFSET, 
                                            READ_BUFFER_SIZE
                                    );
                                }

                                /* Check if connection closed */
                                if(nbytes == 0)
                                {
                                    uint8_t data[PROTOCOL_BUFFER_OFFSET];
                                    protocol_frame frame_st, *frame;

                                    log_printf(L_INFO, "Connection closed\n");

                                    frame = &frame_st;
                                    memset(frame, 0, sizeof(protocol_frame));
                                    frame->friendnumber = tun->friendnumber;
                                    frame->packet_type = PACKET_TYPE_TCP_FIN;
                                    frame->connid = tun->connid;
                                    frame->data_length = 0;
                                    send_frame(frame, data);
                                    if(tun->sockfd)
                                    {
                                        FD_CLR(tun->sockfd, &client_master_fdset);
                                    }
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

                                    log_printf(L_DEBUG2, "Wrote %d bytes from sock %d to tunnel %d\n", nbytes, tun->sockfd, tun->connid);
                                }
                            }
                        }
                    }

                    fds = client_master_fdset;
                }
                break;
            case CLIENT_STATE_CONNECTION_LOST:
                {
                    TOX_CONNECTION friend_connection_status;
                    friend_connection_status = tox_friend_get_connection_status(tox, friendnumber, &friend_query_error);
                    if(friend_query_error != TOX_ERR_FRIEND_QUERY_OK)
                    {
                        log_printf(L_DEBUG, "tox_friend_get_connection_status: error %u\n", friend_query_error);
                    }
                    else
                    {
                        if(friend_connection_status == TOX_CONNECTION_NONE)
                        {
                            /* https://github.com/TokTok/c-toxcore/blob/acb6b2d8543c8f2ea0c2e60dc046767cf5cc0de8/toxcore/tox.h#L1267 */
                            TOX_ERR_FRIEND_DELETE tox_delete_error;

                            log_printf(L_WARNING, "Lost connection to server, closing all tunnels and re-adding friend\n");
                            client_close_all_connections();
                            tox_friend_delete(tox, friendnumber, &tox_delete_error);
                            if(tox_delete_error)
                            {
                                log_printf(L_ERROR, "Error when deleting server from friend list: %d\n", tox_delete_error);
                            }
                            state = CLIENT_STATE_INITIAL;
                        }
                        else
                        {
                            state = CLIENT_STATE_FORWARDING;
                            log_printf(L_DEBUG2, "Entered CLIENT_STATE_FORWARDING");
                        }
                    }
                }
                break;
            case 0xffffffff:
                log_printf(L_ERROR, "You forgot a break statement\n");
                exit(0);
                break;
            case CLIENT_STATE_SHUTDOWN:
                exit(0);
                break;
        }

        usleep(tox_iteration_interval(tox) * 1000);
    }
}

