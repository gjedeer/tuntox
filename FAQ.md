## How to report crash issues?

* [Learn to use GDB](https://wiki.ubuntu.com/Backtrace#Generation) (or see [Arch Wiki](https://wiki.archlinux.org/index.php/Debug_-_Getting_Traces#Getting_the_trace) if you can't stand seeing the Ubuntu logo)
* Preferably, [build tuntox and c-toxcore from source](BUILD.md)
* run tuntox with `-d -d -d` switch (yes, three times) on both sides (client and server)
* Try reproducing the problem
* Type `backtrace full` in gdb console when it crashes
* Paste full debug output including gdb output in your issue. Don't forget to paste log from the other side (eg. from a client when you're reporting a server crash).
* Describe exactly how you reproduced the problem. Preferably try reproducing it again.

## How to report non-crash issues?

* Make sure you're running the latest version
* run tuntox with `-d -d -d` switch (yes, three times):

```
tuntox -d -d -d -i ABDE4CF4541C27DBE36A812FF6752F71A9F44D1CF917CE489B30CC3D742500039B86C14F85F9
```

* Try reproducing the problem and note approximate date/time of the problem, so that logs can be cross-referenced
* Depending on the nature of the problem, logs from both server and client may be needed
* Describe exactly how you reproduced the problem. Preferably try reproducing it again.

## Why is my connection slow?

The actual p2p connection is made by the [c-toxcore](https://github.com/TokTok/c-toxcore) library. The way it works is: it tries to establish a direct connection between peers and falls back to [TCP relays](https://nodes.tox.chat/) if that's impossible.

The direct connection code doesn't see much work and c-toxcore sometimes uses a TCP relay even when both peers have a public IP address and can reach each other directly. 

Also please note that sometimes the connection improves after a few minutes as the peers discover each other.

You're going to get the best connection if you see the following message on the client:

```
2018-03-24 08:59:21: [INFO]     Friend request accepted (An UDP connection has been established)!
```

The connection is likely to have worse latency when you see the following:

```
2018-03-24 08:57:21: [INFO]     Friend request accepted (A TCP connection has been established (via TCP relay))!
```

There's, however, a chance that it will upgrade to UDP after a few minutes:

```
2018-03-24 10:17:06: [INFO]     Friend connection status changed to: An UDP connection has been established
```

## I have a direct UDP connection. Why isn't my connection faster?

Wait until https://github.com/gjedeer/tuntox/issues/41 is implemented. This change should improve speed and latency in the 10 Mbit/s+ range.

## How do I run over proxy/Tor?

tuntox honors the `ALL_PROXY` environment variable when connecting to the Tox network. HTTP and SOCKS5 proxies are supported. In server mode, it does not use the proxy for tunneled connections - just for tox protocol. If that's important for you that tunelled connections use a proxy, use proxychains, torify or a similar tool.

```
ALL_PROXY=socks5://127.0.0.1:9050 ./tuntox
ALL_PROXY=http://42.3.182.149:80 ./tuntox -i ABCD123 -p
```

## Are there distribution packages?

In repos:

* [Arch](https://www.archlinux.org/packages/community/x86_64/tuntox/)

Work in progress:
* [Debian](https://bitbucket.org/gjedeer/tuntox/downloads/)
* [NixOS](https://github.com/NixOS/nixpkgs/pull/32823)

## Can I run it with Docker?

ATTENTION - DOCKER IMAGE MOVED FROM GITLAB TO DOCKERHUB ON 2020-08-15

I've made a [Docker image](https://hub.docker.com/r/gdr1/tuntox) by bundling a static build with Alpine Linux, it's built automatically by Dockerhub every time I push code to Github. There's a [Dockerfile](Dockerfile) and [docker-compose.yaml](scripts/docker-compose.yaml) if you want to build the image yourself.

The tox config is stored in `/data` and that's where you want to attach your volumes.

```
docker run -e 'TUNTOX_SHARED_SECRET=myassfeelsweird' -v /tmp/tt:/data -it gdr1/tuntox:latest
```

The binary is in `/usr/bin/tuntox` (and `/usr/bin/tokssh`):
```
docker run -e 'TUNTOX_SHARED_SECRET=myassfeelsweird' -it gdr1/tuntox:latest /usr/bin/tuntox -i 1234abc -p
```

## Can I run it on Windows?

There's no native Windows version but, in the spirit of "just use Wine" answers, try the following:

* Why don't you install [Docker for Windows](https://docs.docker.com/docker-for-windows/install/) and use the Docker image in Linux Containers mode?
* [Windows Subsystem for Linux](https://docs.microsoft.com/en-us/windows/wsl/install-win10) works with tuntox binaries too (see Releases tab on Github). To use the smallest amount of disk space, use Alpine Linux instead of Ubuntu (but it works on both). [screenshot](screenshots/wsl.png)

## Is your website a joke?

You're a joke for not using NoScript. Just disable JS if you don't like the scroller.
