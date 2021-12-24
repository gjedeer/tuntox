#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <tox/tox.h>

#include "cJSON.h"
#include "log.h"

/* From https://github.com/TokTok/c-toxcore/blob/master/other/fun/cracker.c */
static size_t hex_string_to_bin(const char *hex_string, size_t hex_len, uint8_t *bytes)
{
    size_t i;
    const char *pos = hex_string;
    // make even
    for (i = 0; i < hex_len / 2; ++i, pos += 2) {
        uint8_t val;
        if (sscanf(pos, "%02hhx", &val) != 1) {
            return 0;
        }
        bytes[i] = val;
    }
    if (i * 2 < hex_len) {
        uint8_t val;
        if (sscanf(pos, "%hhx", &val) != 1) {
            return 0;
        }
        bytes[i] = (uint8_t)(val << 4);
        ++i;
    }
    return i;
}

/* Very stupid test to filter out hostnames */
static bool isValidIPv4(const char *ip_address)
{
   unsigned int a,b,c,d;
   return sscanf(ip_address,"%u.%u.%u.%u", &a, &b, &c, &d) == 4;
}

void do_bootstrap_file(Tox *tox, const char * json_file)
{
    char * buffer = NULL;
    long length;

    const cJSON *node = NULL;
    const cJSON *nodes = NULL;
    const cJSON *tcp_ports = NULL;
    const cJSON *tcp_port = NULL;
    unsigned char key_bin[TOX_PUBLIC_KEY_SIZE];

    FILE * f = fopen (json_file, "rb");

    if (f) {
        fseek (f, 0, SEEK_END);
        length = ftell (f);
        fseek (f, 0, SEEK_SET);
        buffer = malloc (length);
        if (buffer) {
            fread (buffer, 1, length, f);
        }
        fclose (f);
    } else {
        log_printf(L_INFO, "Could not find Tox bootstrap nodes. Using hardcoded.\n");
        return;
    }

    if (!buffer) {
        log_printf(L_WARNING, "Could not read Tox bootstrap nodes.");
        return;
    }

    cJSON *nodes_json = cJSON_Parse(buffer);
    if (nodes_json == NULL) {
        const char *error_ptr = cJSON_GetErrorPtr();
        if (error_ptr != NULL) {
            log_printf(L_WARNING, "Error reading JSON before: %s\n", error_ptr);
        }
        goto end;
    }

    nodes = cJSON_GetObjectItemCaseSensitive(nodes_json, "nodes");
    cJSON_ArrayForEach(node, nodes) {
        cJSON *port = cJSON_GetObjectItemCaseSensitive(node, "port");
        cJSON *ipv4 = cJSON_GetObjectItemCaseSensitive(node, "ipv4");
        cJSON *ipv6 = cJSON_GetObjectItemCaseSensitive(node, "ipv6");
        cJSON *pk   = cJSON_GetObjectItemCaseSensitive(node, "public_key");

        if (!cJSON_IsNumber(port) || !cJSON_IsString(ipv4) ||
            !cJSON_IsString(ipv6) || !cJSON_IsString(pk) ) {
            continue;
        }

        if (!isValidIPv4(ipv4->valuestring)) {
            log_printf(L_INFO, "Skipping \"%s:%d\" %s\n", ipv4->valuestring, port->valueint, pk->valuestring);
            continue;
        }

        log_printf(L_INFO, "Bootstrapping from \"%s:%d\" %s\n", ipv4->valuestring, port->valueint, pk->valuestring);

        /* Could have used sodium here, but did not want to change dependencies. Alternative is:
            sodium_hex2bin(key_bin, sizeof(key_bin), pk->valuestring, sizeof(pk->valuestring)-1, NULL, NULL, NULL);
        */
        hex_string_to_bin(pk->valuestring, sizeof(pk->valuestring)-1, key_bin);

        tox_bootstrap(tox, ipv4->valuestring, port->valueint, key_bin, NULL);

        tcp_ports = cJSON_GetObjectItemCaseSensitive(node, "tcp_ports");
        cJSON_ArrayForEach(tcp_port, tcp_ports) {
            if (cJSON_IsNumber(tcp_port)) {
                log_printf(L_INFO, "   Also adding TCP-realy %d\n", tcp_port->valueint);
                tox_add_tcp_relay(tox, ipv4->valuestring, tcp_port->valueint, key_bin, 0);
            }
        }
    }
end:
    cJSON_Delete(nodes_json);
    free(buffer);
}
