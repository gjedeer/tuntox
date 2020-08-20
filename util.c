#include "log.h"
#include "util.h"
#include <string.h>
#include <tox/tox.h>
#include <stdio.h>
#include <stdlib.h>

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
    *a = '\0';
}

/* From utox/util.c */
void id_to_string(char_t *dest, const char_t *src)
{
    to_hex(dest, src, TOX_ADDRESS_SIZE);
}

/* From utox/util.c */
int string_to_id(char_t *w, char_t *a)
{
    char_t *end = w + TOX_ADDRESS_SIZE;
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

/* Parse the -L parameter */
/* 0 = success */
int parse_local_port_forward(char *string, int *local_port, char **hostname, int *remote_port)
{
    char *lport;
    char *host;
    char *rport;

    /* First replace all @ with :, ':' is forbidden in some environments */
    char *p = string;
    while(*p)
    {
        if(*p == '@') *p = ':';
        p++;
    }

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

/* Parse the -W parameter */
/* 0 = success */
int parse_pipe_port_forward(char *string, char **hostname, int *remote_port)
{
    char *host;
    char *rport;

    /* First replace all @ with :, ':' is forbidden in some environments */
    char *p = string;
    while(*p)
    {
        if(*p == '@') *p = ':';
        p++;
    }

    host = strtok(string, ":");
    rport = strtok(NULL, ":");

    if(!host || !rport)
    {
        return -1;
    }

    *hostname = host;
    *remote_port = atoi(rport);

    return 0;
}

void* file_raw(char *path, uint32_t *size)
{
    FILE *file;
    char *data;
    int len;

    file = fopen(path, "rb");
    if(!file) {
        log_printf(L_WARNING, "File not found (%s)\n", path);
        return NULL;
    }

    fseek(file, 0, SEEK_END);
    len = ftell(file);
    if(len <= 0)
    {
        fclose(file);
        return NULL;
    }
    data = malloc(len);
    if(!data) {
        fclose(file);
        return NULL;
    }

    fseek(file, 0, SEEK_SET);

    if(fread(data, len, 1, file) != 1) {
        log_printf(L_WARNING, "Read error (%s)\n", path);
        fclose(file);
        free(data);
        return NULL;
    }

    fclose(file);

    log_printf(L_DEBUG, "Read %u bytes (%s)\n", len, path);

    if(size) {
        *size = len;
    }
    return data;
}

const char *readable_connection_status(TOX_CONNECTION status)
{
    switch(status)
    {
        case TOX_CONNECTION_NONE:
            return "There is no connection";
        case TOX_CONNECTION_TCP:
            return "A TCP connection has been established (via TCP relay)";
        case TOX_CONNECTION_UDP:
            return "An UDP connection has been established";
        default:
            log_printf(L_WARNING, "Received unknown connection status %d\n", (int)status);
            return "Unknown connection status";
    }
}
