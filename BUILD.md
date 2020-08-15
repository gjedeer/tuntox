* Install c-toxcore (libtoxav and the DNS client are not required) https://github.com/TokTok/c-toxcore/blob/master/INSTALL.md#build-manually
* git clone https://github.com/gjedeer/tuntox.git
* cd tuntox
* make

The makefile creates a static binary by default. If you're not a fan of static binaries, `make tuntox_nostatic`. 

One reason to do so may be if you'd like to resolve hostnames on the tuntox server (invoke client with `-L 80:reddit.com:80` instead of `-L 80:198.41.208.138:80`). 

Static linking breaks hostname resolution, but IMHO the pros overweight the cons.

c-toxcore is the only direct dependency. c-toxcore requires libsodium and libevent_pthreads at the time of writing this, please refer to their install instructions for the current dependencies. Also pkg-config is required.

## Debian sid

In Debian sid, toxcore is in the main repos so it's very easy to build a deb package.

```
apt install pkg-config build-essential make libtoxcore-dev dh-make git python3-jinja2 python3-requests
git clone https://github.com/gjedeer/tuntox.git
cd tuntox
dh_make --createorig -s
dpkg-buildpackage -us -uc
```

It's even easier to just build the binary:
```
apt install pkg-config build-essential make libtoxcore-dev git python3-jinja2 python3-requests
git clone https://github.com/gjedeer/tuntox.git
cd tuntox
make
```

## MacOS build
Basically the same as above but:

* static compiling is removed - you can't do this on MacOS platform (no, just don't)
* because of removed `-static` you can't resolve hostnames (you can always put it into `hosts` file in your system)

If you'd like to build on Mac do: `make -f Makefile.mac`

