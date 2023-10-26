# FreeBSD Port Maintainer Wanted

I wrote a Makefile for FreeBSD ports but don't feel like becoming an official maintainer. If you feel like maintaining it, just see how lethargic the development of tuntox is, it will take an hour of two of your time per year. Chance is that all you're going to do is bump version numbers.

```
mkdir /usr/ports/net-p2p/tuntox/
cd /usr/ports/net-p2p/tuntox/
wget https://github.com/gjedeer/tuntox/raw/master/freebsd/distinfo
wget https://github.com/gjedeer/tuntox/raw/master/freebsd/Makefile
wget https://github.com/gjedeer/tuntox/raw/master/freebsd/pkg-descr
make
```
