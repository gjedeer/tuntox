#!/usr/bin/python3
# pip3 install requests

import datetime
import json
import requests
import socket
from string import Template

json_url = 'https://nodes.tox.chat/json'

# --- Templates ---

main_template = Template("""\
/*
 * Generated with generate_tox_bootstrap.py by GDR!
 * from $json_url on $now
 */
struct bootstrap_node {
    char *address;
    uint16_t port;
    uint8_t key[32];
} bootstrap_nodes[] = {
$bootstrap_nodes
};

struct bootstrap_node tcp_relays[] = {
$tcp_relays
};
""")

node_template = Template("""    {
        "$ip",
        $port,
        {
            $keybytes
        }
    }""")

# --- Helpers ---

def toxtoc(value):
    """
    Convert a 64-char hex string into two lines of C bytes.
    """
    def get_16_bytes(value):
        if len(value) != 32:
            raise ValueError('%r is not a 32-char string' % value)
        rv = ""
        for i in range(16):
            rv += "0x%s" % value[2*i : 2*i+2]
            if i < 15:
                rv += ", "
        return rv

    return get_16_bytes(value[:32]) + \
           ",\n" + (12*' ') + \
           get_16_bytes(value[32:])

# --- Main ---

if __name__ == "__main__":
    r = requests.get(json_url)
    data = r.json()
    if 'nodes' not in data:
        raise ValueError('nodes element not in JSON')

    nodes = []
    tcp_relays = []

    for elem in data['nodes']:
        node = {}
        if ('ipv4' not in elem and 'ipv6' not in elem) or 'port' not in elem or 'public_key' not in elem:
            print("SKIPPING", elem)
            continue
        
        if len(elem['public_key']) != 64:
            print("Bad public key %s, skipping!" % elem['public_key'])
            continue

        node['port'] = int(elem['port'])
        node['public_key'] = elem['public_key']

        for addr, family in (
                (elem.get('ipv4', ''), socket.AF_INET),
                (elem.get('ipv6', ''), socket.AF_INET6),
                ):
            if not addr.strip() or addr == '-':
                continue
            try:
                socket.inet_pton(family, addr)
                node['ip'] = addr
            except socket.error:
                try:
                    print("RESOLVING", addr)
                    node['ip'] = socket.gethostbyname(addr)
                except socket.error:
                    print("Could not resolve ip: %s, skipping!" % addr)
                    continue

            if 'status_udp' in elem and elem['status_udp']:
                nodes.append(dict(node))  # copy

            if 'tcp_ports' in elem and elem['tcp_ports'] and \
               'status_tcp' in elem and elem['status_tcp']:
                for port in elem['tcp_ports']:
                    relay = dict(node)
                    try:
                        relay['port'] = int(port)
                    except ValueError:
                        continue
                    tcp_relays.append(relay)

    # Build loops using node_template
    node_entries = []
    for n in nodes:
        node_entries.append(node_template.substitute(
            ip=n['ip'],
            port=n['port'],
            keybytes=toxtoc(n['public_key'])
        ))
    relay_entries = []
    for rnode in tcp_relays:
        relay_entries.append(node_template.substitute(
            ip=rnode['ip'],
            port=rnode['port'],
            keybytes=toxtoc(rnode['public_key'])
        ))

    # Join with commas
    bootstrap_nodes_str = ",\n".join(node_entries)
    tcp_relays_str = ",\n".join(relay_entries)

    # Final render
    tox_bootstrap_h = main_template.substitute(
        json_url=json_url,
        now=datetime.datetime.now(),
        bootstrap_nodes=bootstrap_nodes_str,
        tcp_relays=tcp_relays_str
    )

    open('tox_bootstrap.h', 'w').write(tox_bootstrap_h)