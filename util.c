#include "util.h"
#include <string.h>
#include <tox/tox.h>

void writechecksum(uint8_t *address)
{
    uint8_t *checksum = address + 36;
    uint32_t i;

    for (i = 0; i < 36; ++i)
	checksum[i % 2] ^= address[i];
}

/* From utox/util.c */
void to_hex(char_t *a, const char_t *p, int size)
{
    char_t b, c;
    const char_t *end = p + size;

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

/* From utox/util.c */
int string_to_id(char_t *w, char_t *a)
{
    char_t *end = w + TOX_FRIEND_ADDRESS_SIZE;
    while(w != end) {
        char_t c, v;

        c = *a++;
        if(c >= '0' && c <= '9') {
            v = (c - '0') << 4;
        } else if(c >= 'A' && c <= 'F') {
            v = (c - 'A' + 10) << 4;
        } else if(c >= 'a' && c <= 'f') {
            v = (c - 'a' + 10) << 4;
        } else {
            return 0;
        }

        c = *a++;
        if(c >= '0' && c <= '9') {
            v |= (c - '0');
        } else if(c >= 'A' && c <= 'F') {
            v |= (c - 'A' + 10);
        } else if(c >= 'a' && c <= 'f') {
            v |= (c - 'a' + 10);
        } else {
            return 0;
        }

        *w++ = v;
    }

    return 1;
}

/* 0 = success */
int parse_local_port_forward(char *string, int *local_port, char **hostname, int *remote_port)
{
    char *lport;
    char *host;
    char *rport;
    
    lport = strtok(string, ":");
    host = strtok(NULL, ":");
    rport = strtok(NULL, ":");

    if(!lport || !host || !rport)
    {
        return -1;
    }

    *local_port = atoi(lport);
    *hostname = host;
    *remote_port = atoi(rport);

    return 0;
}
