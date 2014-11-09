SOURCES = main.c
DEPS=
CC=gcc
CFLAGS=-g
OBJECTS=$(SOURCES:.c=.o)

.c.o:
	$(CC) $(CFLAGS) $< -c -o $@

tuntox: $(OBJECTS)
	$(CC) --static -o $@ -ltoxcore $^ $(CFLAGS) /usr/local/lib/libsodium.a

all: tuntox

