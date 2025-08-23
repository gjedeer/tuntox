#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>

#include "log.h"
#include "socks5.h"

#define SOCKS_VERSION 5
#define SOCKS_CMD_CONNECT 1
#define SOCKS_ATYP_IPV4 1
#define SOCKS_ATYP_DOMAINNAME 3
#define SOCKS_ATYP_IPV6 4

int start_socks5_server(int port) {
    int sockfd;
    struct sockaddr_in serv_addr;
    int yes = 1;

    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) {
        log_printf(L_ERROR, "SOCKS5: Failed to create socket: %s\n", strerror(errno));
        return -1;
    }

    if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(int)) < 0) {
        log_printf(L_ERROR, "SOCKS5: Failed to set SO_REUSEADDR: %s\n", strerror(errno));
        close(sockfd);
        return -1;
    }

    memset(&serv_addr, 0, sizeof(serv_addr));
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_addr.s_addr = INADDR_ANY;
    serv_addr.sin_port = htons(port);

    if (bind(sockfd, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0) {
        log_printf(L_ERROR, "SOCKS5: Failed to bind to port %d: %s\n", port, strerror(errno));
        close(sockfd);
        return -1;
    }

    if (listen(sockfd, 10) < 0) {
        log_printf(L_ERROR, "SOCKS5: Failed to listen on port %d: %s\n", port, strerror(errno));
        close(sockfd);
        return -1;
    }

    log_printf(L_INFO, "SOCKS5: Listening on port %d\n", port);
    return sockfd;
}

int handle_socks5_connection(int accept_fd, char **remote_host, int *remote_port) {
    unsigned char buf[257];
    ssize_t len;

    log_printf(L_DEBUG2, "SOCKS5: Starting handshake on fd %d", accept_fd);

    // 1. GREETING
    // Read VER and NMETHODS
    len = recv(accept_fd, buf, 2, MSG_WAITALL);
    if (len != 2 || buf[0] != SOCKS_VERSION) {
        log_printf(L_WARNING, "SOCKS5: Invalid greeting (len=%zd, ver=%02x)\n", len, buf[0]);
        if (len > 0) {
            log_printf(L_DEBUG2, "SOCKS5: Received greeting data: %02x %02x\n", buf[0], buf[1]);
        }
        return -1;
    }

    int nmethods = buf[1];
    if (nmethods <= 0) {
        log_printf(L_WARNING, "SOCKS5: Invalid number of methods: %d\n", nmethods);
        return -1;
    }

    len = recv(accept_fd, buf, nmethods, MSG_WAITALL);
    if (len != nmethods) {
        log_printf(L_WARNING, "SOCKS5: Did not receive all methods\n");
        return -1;
    }

    // We only support NO AUTHENTICATION REQUIRED (0x00)
    bool no_auth_found = false;
    for (int i=0; i < nmethods; i++) {
        if (buf[i] == 0x00) {
            no_auth_found = true;
            break;
        }
    }

    if (!no_auth_found) {
        log_printf(L_WARNING, "SOCKS5: Client does not support NO AUTH method\n");
        // No acceptable methods
        buf[0] = SOCKS_VERSION;
        buf[1] = 0xFF;
        send(accept_fd, buf, 2, 0);
        return -1;
    }

    // Send server choice: NO AUTH
    buf[0] = SOCKS_VERSION;
    buf[1] = 0x00;
    if (send(accept_fd, buf, 2, 0) != 2) {
        log_printf(L_WARNING, "SOCKS5: Failed to send auth response: %s\n", strerror(errno));
        return -1;
    }

    // 2. REQUEST
    log_printf(L_DEBUG2, "SOCKS5: Auth successful, waiting for request...");
    len = recv(accept_fd, buf, 4, MSG_WAITALL);
    if (len != 4 || buf[0] != SOCKS_VERSION || buf[1] != SOCKS_CMD_CONNECT) {
        log_printf(L_WARNING, "SOCKS5: Invalid request (len=%zd, ver=%02x, cmd=%02x)\n", len, buf[0], buf[1]);
        if (len > 0) {
            log_printf(L_DEBUG2, "SOCKS5: Received request data: %02x %02x %02x %02x\n", buf[0], buf[1], buf[2], buf[3]);
        }
        return -1;
    }

    // 3. ADDRESS
    int atyp = buf[3];
    int host_len = 0;

    if (atyp == SOCKS_ATYP_DOMAINNAME) {
        len = recv(accept_fd, buf, 1, MSG_WAITALL);
        if (len != 1) return -1;
        host_len = buf[0];
        len = recv(accept_fd, buf, host_len, MSG_WAITALL);
        if (len != host_len) return -1;
        buf[len] = '\0';
        *remote_host = strdup((char*)buf);
    } else if (atyp == SOCKS_ATYP_IPV4) {
        unsigned char addr[4];
        len = recv(accept_fd, addr, 4, MSG_WAITALL);
        if (len != 4) return -1;
        char *ip_str = malloc(INET_ADDRSTRLEN);
        if (!ip_str) return -1;
        inet_ntop(AF_INET, addr, ip_str, INET_ADDRSTRLEN);
        *remote_host = ip_str;
    } else if (atyp == SOCKS_ATYP_IPV6) {
        unsigned char addr[16];
        len = recv(accept_fd, addr, 16, MSG_WAITALL);
        if (len != 16) return -1;
        char *ip_str = malloc(INET6_ADDRSTRLEN);
        if (!ip_str) return -1;
        inet_ntop(AF_INET6, addr, ip_str, INET6_ADDRSTRLEN);
        *remote_host = ip_str;
    } else {
        log_printf(L_WARNING, "SOCKS5: Unsupported address type %d\n", atyp);
        return -1;
    }
    
    len = recv(accept_fd, buf, 2, MSG_WAITALL);
    if (len != 2) return -1;
    *remote_port = (buf[0] << 8) | buf[1];

    log_printf(L_DEBUG2, "SOCKS5: Parsed request for %s:%d", *remote_host, *remote_port);

    return 0;
}


int send_socks5_success_reply(int sockfd) {
    unsigned char reply[10] = {SOCKS_VERSION, 0x00, 0x00, SOCKS_ATYP_IPV4, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
    if (send(sockfd, reply, sizeof(reply), 0) != sizeof(reply)) {
        log_printf(L_WARNING, "SOCKS5: Failed to send success reply: %s\n", strerror(errno));
        return -1;
    }
    return 0;
}
