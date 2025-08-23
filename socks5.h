#ifndef SOCKS5_H
#define SOCKS5_H

#include "main.h"

int start_socks5_server(int port);
int handle_socks5_connection(int accept_fd, char **remote_host, int *remote_port);
int send_socks5_success_reply(int sockfd);

#endif /* SOCKS5_H */
