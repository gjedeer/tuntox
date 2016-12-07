SOURCES = $(wildcard *.c)
DEPS=libsodium toxcore
CC=gcc
CFLAGS=-g #-std=c99
CFLAGS += $(shell pkg-config --cflags $(DEPS))
LDFLAGS=-g -pthread -lm -static -lrt
LDFLAGS += $(shell pkg-config --static --libs $(DEPS))
DSO_LDFLAGS=-g -pthread -lm -lrt
DSO_LDFLAGS += $(shell pkg-config --libs $(DEPS))
OBJECTS=$(SOURCES:.c=.o)
INCLUDES = $(wildcard *.h)

all: cscope.out tuntox 

gitversion.h: .git/HEAD .git/index
	echo "#define GITVERSION \"$(shell git rev-parse HEAD)\"" > $@

gitversion.c: gitversion.h

.c.o: $(INCLUDES)
	$(CC) $(CFLAGS) $< -c -o $@

tuntox: $(OBJECTS) $(INCLUDES)
	$(CC) -o $@ $(OBJECTS) -lpthread $(LDFLAGS) /usr/local/lib/libtoxmessenger.a /usr/local/lib/libtoxcore.a

tuntox_nostatic: $(OBJECTS) $(INCLUDES)
	$(CC) -o $@ $(OBJECTS) -lpthread $(DSO_LDFLAGS) 

cscope.out:
	cscope -bv ./*.[ch] 

clean:
	rm -rf *.o tuntox gitversion.h
