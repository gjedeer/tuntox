#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <stdbool.h>

#include "log.h"
#include "socks5.h"

#define SOCKS_VERSION 5
#define SOCKS_CMD_CONNECT 1
#define SOCKS_ATYP_IPV4 1
#define SOCKS_ATYP_DOMAINNAME 3
#define SOCKS_ATYP_IPV6 4

// Helper function to safely receive exact number of bytes
static int safe_recv(int sockfd, void *buf, size_t len) {
    char *ptr = (char *)buf;
    size_t remaining = len;
    
    while (remaining > 0) {
        ssize_t received = recv(sockfd, ptr, remaining, 0);
        if (received < 0) {
            if (errno == EINTR) {
                continue;
            }
            return -1;  // Error
        } else if (received == 0) {
            return -2;  // Connection closed
        }
        ptr += received;
        remaining -= received;
    }
    return 0;  // Success
}

// Helper function to safely send exact number of bytes
static int safe_send(int sockfd, const void *buf, size_t len) {
    const char *ptr = (const char *)buf;
    size_t remaining = len;
    
    while (remaining > 0) {
        ssize_t sent = send(sockfd, ptr, remaining, 0);
        if (sent < 0) {
            if (errno == EINTR) {
                continue;
            }
            return -1;  // Error
        } else if (sent == 0) {
            return -2;  // Connection closed
        }
        ptr += sent;
        remaining -= sent;
    }
    return 0;  // Success
}

// Helper function to validate domain name (no embedded nulls)
static bool is_valid_domain_name(const unsigned char *name, int len) {
    for (int i = 0; i < len; i++) {
        if (name[i] == '\0') {
            return false;  // Embedded null byte found
        }
    }
    return true;
}

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

    if (listen(sockfd, SOMAXCONN) < 0) {
        log_printf(L_ERROR, "SOCKS5: Failed to listen on port %d: %s\n", port, strerror(errno));
        close(sockfd);
        return -1;
    }

    log_printf(L_INFO, "SOCKS5: Listening on port %d\n", port);
    return sockfd;
}

int handle_socks5_connection(int accept_fd, char **remote_host, int *remote_port) {
    unsigned char buf[257];
    int result;
    
    // Initialize output parameters
    *remote_host = NULL;
    *remote_port = 0;

    log_printf(L_DEBUG2, "SOCKS5: Starting handshake on fd %d", accept_fd);

    // 1. GREETING - Read VER and NMETHODS
    result = safe_recv(accept_fd, buf, 2);
    if (result != 0) {
        if (result == -2) {
            log_printf(L_WARNING, "SOCKS5: Connection closed during greeting\n");
        } else {
            log_printf(L_WARNING, "SOCKS5: Error receiving greeting: %s\n", strerror(errno));
        }
        return -1;
    }

    // Validate version
    if (buf[0] != SOCKS_VERSION) {
        log_printf(L_WARNING, "SOCKS5: Invalid SOCKS version: %02x\n", buf[0]);
        return -1;
    }

    // Validate NMETHODS (must be 1-255, not 0)
    unsigned int nmethods = buf[1];  // Use unsigned to avoid sign issues
    if (nmethods == 0 || nmethods > 255) {
        log_printf(L_WARNING, "SOCKS5: Invalid number of methods: %u\n", nmethods);
        return -1;
    }

    // Read authentication methods
    result = safe_recv(accept_fd, buf, nmethods);
    if (result != 0) {
        if (result == -2) {
            log_printf(L_WARNING, "SOCKS5: Connection closed while reading methods\n");
        } else {
            log_printf(L_WARNING, "SOCKS5: Error receiving methods: %s\n", strerror(errno));
        }
        return -1;
    }

    // Check if NO AUTHENTICATION (0x00) is supported
    bool no_auth_found = false;
    for (unsigned int i = 0; i < nmethods; i++) {
        if (buf[i] == 0x00) {
            no_auth_found = true;
            break;
        }
    }

    if (!no_auth_found) {
        log_printf(L_WARNING, "SOCKS5: Client does not support NO AUTH method\n");
        // Send "no acceptable methods" response
        buf[0] = SOCKS_VERSION;
        buf[1] = 0xFF;
        safe_send(accept_fd, buf, 2);  // Ignore send errors here since we're failing anyway
        return -1;
    }

    // Send server choice: NO AUTH
    buf[0] = SOCKS_VERSION;
    buf[1] = 0x00;
    result = safe_send(accept_fd, buf, 2);
    if (result != 0) {
        log_printf(L_WARNING, "SOCKS5: Failed to send auth response: %s\n", strerror(errno));
        return -1;
    }

    // 2. REQUEST - Read VER, CMD, RSV, ATYP
    log_printf(L_DEBUG2, "SOCKS5: Auth successful, waiting for request...");
    result = safe_recv(accept_fd, buf, 4);
    if (result != 0) {
        if (result == -2) {
            log_printf(L_WARNING, "SOCKS5: Connection closed during request\n");
        } else {
            log_printf(L_WARNING, "SOCKS5: Error receiving request: %s\n", strerror(errno));
        }
        return -1;
    }

    // Validate request fields
    if (buf[0] != SOCKS_VERSION) {
        log_printf(L_WARNING, "SOCKS5: Invalid SOCKS version in request: %02x\n", buf[0]);
        return -1;
    }
    if (buf[1] != SOCKS_CMD_CONNECT) {
        log_printf(L_WARNING, "SOCKS5: Unsupported command: %02x\n", buf[1]);
        return -1;
    }
    if (buf[2] != 0x00) {
        log_printf(L_WARNING, "SOCKS5: Invalid reserved field: %02x\n", buf[2]);
        return -1;
    }

    // 3. ADDRESS - Handle based on address type
    int atyp = buf[3];
    
    // Validate ATYP
    if (atyp != SOCKS_ATYP_IPV4 && atyp != SOCKS_ATYP_DOMAINNAME && atyp != SOCKS_ATYP_IPV6) {
        log_printf(L_WARNING, "SOCKS5: Unsupported address type: %d\n", atyp);
        return -1;
    }

    if (atyp == SOCKS_ATYP_DOMAINNAME) {
        // Read domain name length
        result = safe_recv(accept_fd, buf, 1);
        if (result != 0) {
            if (result == -2) {
                log_printf(L_WARNING, "SOCKS5: Connection closed while reading domain length\n");
            } else {
                log_printf(L_WARNING, "SOCKS5: Error receiving domain length: %s\n", strerror(errno));
            }
            return -1;
        }
        
        unsigned int host_len = buf[0];
        if (host_len == 0 || host_len > 255) {
            log_printf(L_WARNING, "SOCKS5: Invalid domain name length: %u\n", host_len);
            return -1;
        }
        
        // Read domain name
        result = safe_recv(accept_fd, buf, host_len);
        if (result != 0) {
            if (result == -2) {
                log_printf(L_WARNING, "SOCKS5: Connection closed while reading domain name\n");
            } else {
                log_printf(L_WARNING, "SOCKS5: Error receiving domain name: %s\n", strerror(errno));
            }
            return -1;
        }
        
        // Validate domain name (no embedded nulls)
        if (!is_valid_domain_name(buf, host_len)) {
            log_printf(L_WARNING, "SOCKS5: Domain name contains embedded null bytes\n");
            return -1;
        }
        
        // Allocate and copy domain name
        *remote_host = malloc(host_len + 1);
        if (!*remote_host) {
            log_printf(L_ERROR, "SOCKS5: Memory allocation failed for domain name\n");
            return -1;
        }
        memcpy(*remote_host, buf, host_len);
        (*remote_host)[host_len] = '\0';
        
    } else if (atyp == SOCKS_ATYP_IPV4) {
        unsigned char addr[4];
        result = safe_recv(accept_fd, addr, 4);
        if (result != 0) {
            if (result == -2) {
                log_printf(L_WARNING, "SOCKS5: Connection closed while reading IPv4 address\n");
            } else {
                log_printf(L_WARNING, "SOCKS5: Error receiving IPv4 address: %s\n", strerror(errno));
            }
            return -1;
        }
        
        *remote_host = malloc(INET_ADDRSTRLEN + 1);  // +1 for safety
        if (!*remote_host) {
            log_printf(L_ERROR, "SOCKS5: Memory allocation failed for IPv4 address\n");
            return -1;
        }
        
        if (inet_ntop(AF_INET, addr, *remote_host, INET_ADDRSTRLEN + 1) == NULL) {
            log_printf(L_WARNING, "SOCKS5: Failed to convert IPv4 address\n");
            free(*remote_host);
            *remote_host = NULL;
            return -1;
        }
        
    } else if (atyp == SOCKS_ATYP_IPV6) {
        unsigned char addr[16];
        result = safe_recv(accept_fd, addr, 16);
        if (result != 0) {
            if (result == -2) {
                log_printf(L_WARNING, "SOCKS5: Connection closed while reading IPv6 address\n");
            } else {
                log_printf(L_WARNING, "SOCKS5: Error receiving IPv6 address: %s\n", strerror(errno));
            }
            return -1;
        }
        
        *remote_host = malloc(INET6_ADDRSTRLEN + 1);  // +1 for safety
        if (!*remote_host) {
            log_printf(L_ERROR, "SOCKS5: Memory allocation failed for IPv6 address\n");
            return -1;
        }
        
        if (inet_ntop(AF_INET6, addr, *remote_host, INET6_ADDRSTRLEN + 1) == NULL) {
            log_printf(L_WARNING, "SOCKS5: Failed to convert IPv6 address\n");
            free(*remote_host);
            *remote_host = NULL;
            return -1;
        }
    }

    // Read port number
    result = safe_recv(accept_fd, buf, 2);
    if (result != 0) {
        if (result == -2) {
            log_printf(L_WARNING, "SOCKS5: Connection closed while reading port\n");
        } else {
            log_printf(L_WARNING, "SOCKS5: Error receiving port: %s\n", strerror(errno));
        }
        // Clean up allocated memory on error
        if (*remote_host) {
            free(*remote_host);
            *remote_host = NULL;
        }
        return -1;
    }
    
    *remote_port = (buf[0] << 8) | buf[1];

    log_printf(L_DEBUG2, "SOCKS5: Parsed request for %s:%d", *remote_host, *remote_port);
    return 0;
}


int send_socks5_success_reply(int sockfd) {
    unsigned char reply[10] = {SOCKS_VERSION, 0x00, 0x00, SOCKS_ATYP_IPV4, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
    int result = safe_send(sockfd, reply, sizeof(reply));
    if (result != 0) {
        if (result == -2) {
            log_printf(L_WARNING, "SOCKS5: Connection closed while sending success reply\n");
        } else {
            log_printf(L_WARNING, "SOCKS5: Failed to send success reply: %s\n", strerror(errno));
        }
        return -1;
    }
    return 0;
}
