#ifndef _UTIL_H
#define _UTIL_H

#include <unistd.h>
#include <stdint.h>
#include <tox/tox.h>
#define countof(x) (sizeof(x)/sizeof(*(x)))
#define char_t unsigned char

void writechecksum(uint8_t *address);
void to_hex(char_t *a, const char_t *p, int size);
void id_to_string(char_t *dest, const char_t *src);
int string_to_id(char_t *w, char_t *a);
void* file_raw(char *path, uint32_t *size);
const char *readable_connection_status(TOX_CONNECTION status);
int parse_local_port_forward(char *string, int *local_port, char **hostname, int *remote_port);
int parse_pipe_port_forward(char *string, char **hostname, int *remote_port);
size_t hex_string_to_bin(const char *hex_string, size_t hex_len, uint8_t *bytes);
bool is_valid_ipv4(const char *ip_address);
bool is_valid_ipv6(const char *ip_address);

#endif
