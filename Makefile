SOURCES = $(wildcard *.c)
DEPS=libtoxcore
CC=gcc
CFLAGS=-g #-std=c99
CFLAGS += $(shell pkg-config --cflags $(DEPS))
LDFLAGS=-g -pthread -lm -static
LDFLAGS += $(shell pkg-config --libs $(DEPS))
OBJECTS=$(SOURCES:.c=.o)
INCLUDES = $(wildcard *.h)

.c.o: $(INCLUDES)
	$(CC) $(CFLAGS) $< -c -o $@

tuntox: $(OBJECTS) $(INCLUDES)
	$(CC) -o $@ $(OBJECTS) -ltoxcore -lpthread $(LDFLAGS) /usr/local/lib/libsodium.a /usr/local/lib/libtoxcore.a

cscope.out:
	cscope -bv ./*.[ch] 

all: cscope.out tuntox
