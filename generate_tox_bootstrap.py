#!/usr/bin/python3
# pip3 install jinja2 requests

import datetime
import jinja2
import json
import requests
import socket

json_url = 'https://nodes.tox.chat/json'

tox_bootstrap_template = """
/*
 * Generated with generate_tox_bootstrap.py by GDR!
 * from {{ json_url }} on {{ now }}
 */
struct bootstrap_node {
    char *address;
    uint16_t port;
    uint8_t key[32];
} bootstrap_nodes[] = {
{% for node in nodes %}
    {
        "{{ node.ipv4 }}",
        {{ node.port }},
        {
            {{ node.public_key|toxtoc }}
        }
    },
{% endfor %}
};

struct bootstrap_node tcp_relays[] = {
{% for node in relays %}
    {
        "{{ node.ipv4 }}",
        {{ node.port }},
        {
            {{ node.public_key|toxtoc }}
        }
    },
{% endfor %}
};
"""

def toxtoc(value):
    """
    A Jinja2 filter to turn a ToxID into two lines of C bytes
    """
    def get_16_bytes(value):
        """
        Generate 1 line of C code - 16 bytes
        @param value a hex string of length 32 (32 hex chars)
        """
        if len(value) != 32:
            raise ValueError('%r is not a 32-char string')

        rv = ""

        for i in range(16):
            rv += "0x%s" % value[2*i : 2*i+2]
            if i < 15:
                rv += ", "

        return rv

    rv = get_16_bytes(value[:32]) + \
         ",\n" + (12*' ') + \
         get_16_bytes(value[32:])

    return rv

class Loader(jinja2.BaseLoader):
    def get_source(self, environment, template):
        return tox_bootstrap_template, 'tox_bootstrap_template', True

if __name__ == "__main__":
    r = requests.get(json_url)
    data = r.json()
    if 'nodes' not in data:
        raise ValueError('nodes element not in JSON')

    nodes = []
    tcp_relays = []

    for elem in data['nodes']:
        node = {}
        if 'ipv4' not in elem or 'port' not in elem or 'public_key' not in elem:
            print("SKIPPING", elem)
            continue
        
        if len(elem['public_key']) != 64:
            print("Bad public key %s, skipping!" % elem['public_key'])
            continue

        node['port'] = int(elem['port'])
        node['public_key'] = elem['public_key']

        try:
            socket.inet_aton(elem['ipv4'])
            node['ipv4'] = elem['ipv4']
        except socket.error:
            # IPv4 is not numeric, let's try resolving
            try:
                print("RESOLVING", elem['ipv4'])
                node['ipv4'] = socket.gethostbyname(elem['ipv4'])
            except socket.error:
                print("Could not resolve ipv4: %s, skipping!" % elem['ipv4'])
                continue

        if 'status_udp' in elem and elem['status_udp']:
            nodes.append(node)

        if 'tcp_ports' in elem and elem['tcp_ports'] and \
           'status_tcp' in elem and elem['status_tcp']:
            for port in elem['tcp_ports']:
                relay = dict(node)
                try:
                    relay['port'] = int(port)
                except ValueError:
                    continue

                tcp_relays.append(relay)

    env = jinja2.Environment(loader=Loader())
    env.filters['toxtoc'] = toxtoc
    template = env.get_template('tox_bootstrap_template')
    tox_bootstrap_h = template.render(nodes=nodes, now=datetime.datetime.now(), json_url=json_url, relays=tcp_relays)
    open('tox_bootstrap.h', 'w').write(tox_bootstrap_h)

