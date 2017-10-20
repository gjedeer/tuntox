## How to make a point-to-point VPN

Socat is a powerful tool which can work together with Tuntox.

On the server (where tuntox is already running):

    socat -d -d 'TCP-LISTEN:9876' 'TUN:10.20.30.41/24,up'

On the client:

    socat -d -d TUN:10.20.30.40/24,up 'SYSTEM:./tuntox -W 127.0.0.1@9876 -i 86e70ffe9f835b12667d296f2df9c307ba1aff06'

Viola, you have a point-to-point VPN. On client:

    # ping 10.20.30.41
    PING 10.20.30.41 (10.20.30.41) 56(84) bytes of data.
    64 bytes from 10.20.30.41: icmp_seq=1 ttl=64 time=138 ms
    64 bytes from 10.20.30.41: icmp_seq=2 ttl=64 time=169 ms
    64 bytes from 10.20.30.41: icmp_seq=3 ttl=64 time=130 ms
    64 bytes from 10.20.30.41: icmp_seq=4 ttl=64 time=90.8 ms
    64 bytes from 10.20.30.41: icmp_seq=5 ttl=64 time=50.7 ms

## Full madness mode: tunnelling VPN over SSH over Tox

No need to log in run and run socat on the server.

Also: inefficient, insecure (requires PermitRootLogin yes on server).

On the client:

    socat -d -d TUN:10.20.30.40/24,up 'SYSTEM:ssh root@localhost -o ProxyCommand=\"./tuntox -W "127.0.0.1:22" -d -i 86e70ffe9f835b12667d296f2df9c307ba1aff06\" socat -d -d  - "TUN:10.20.30.41/24,up"'

    # ping 10.20.30.41
    PING 10.20.30.41 (10.20.30.41) 56(84) bytes of data.
    64 bytes from 10.20.30.41: icmp_seq=1 ttl=64 time=50.6 ms
    64 bytes from 10.20.30.41: icmp_seq=2 ttl=64 time=81.2 ms
    64 bytes from 10.20.30.41: icmp_seq=3 ttl=64 time=50.3 ms
    64 bytes from 10.20.30.41: icmp_seq=4 ttl=64 time=151 ms
    64 bytes from 10.20.30.41: icmp_seq=5 ttl=64 time=50.3 ms

Based on [Ben Martin's article](https://www.linux.com/news/software/developer/17942-socat-the-general-bidirectional-pipe-handler)

I've also heard about a new program called [ToxVPN](https://github.com/cleverca22/toxvpn), who knows - maybe it does a better job? And more recently someone created [toxtun](http://toxtun.jschwab.org/), slowclap.gif for the creative choice of name.
