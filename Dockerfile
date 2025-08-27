FROM alpine:edge AS builder
ARG TARGETPLATFORM
ARG BUILDPLATFORM
WORKDIR /
RUN uname -a && echo http://dl-cdn.alpinelinux.org/alpine/edge/testing >> /etc/apk/repositories && apk add gcc g++ git make musl-dev cmake linux-headers libsodium-dev libsodium-static && git clone https://github.com/TokTok/c-toxcore.git /c-toxcore && cd /c-toxcore/ && git submodule update --init && cd /c-toxcore/build/ && cmake .. -DBUILD_TOXAV=OFF -DBOOTSTRAP_DAEMON=off -DBUILD_AV_TEST=off -DFULLY_STATIC=on && make && make install
COPY . /tuntox 
RUN cd /tuntox && make tuntox

FROM alpine:latest

COPY scripts/tokssh /usr/bin/tokssh
COPY --from=0 /tuntox/tuntox /usr/bin/tuntox

RUN chmod +x /usr/bin/tuntox  /usr/bin/tokssh && \
	mkdir /data

EXPOSE 33446/tcp
EXPOSE 33446:33447/udp

CMD ["/usr/bin/tuntox", "-C", "/data", "-t", "33446", "-u", "33446:33447", "-d"]
