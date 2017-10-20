SOURCES = $(wildcard *.c)
DEPS=libtoxcore libsodium libevent_pthreads
CC=gcc
CFLAGS=-g -Wall #-std=c99
CFLAGS += $(shell pkg-config --cflags $(DEPS))
LDFLAGS=-g -pthread -lm -static -lrt
LDFLAGS += $(shell pkg-config --static --libs $(DEPS))
DSO_LDFLAGS=-g -pthread -lm -lrt
DSO_LDFLAGS += $(shell pkg-config --libs $(DEPS))
OBJECTS=$(SOURCES:.c=.o)
INCLUDES = $(wildcard *.h)


# Targets
all: tuntox

gitversion.h: .git/HEAD .git/index
	@echo "  GEN   $@"
	@echo "#define GITVERSION \"$(shell git rev-parse HEAD)\"" > $@

tox_bootstrap.h: 
	python generate_tox_bootstrap.py 

%.o: %.c $(INCLUDES) gitversion.h tox_bootstrap.h
	@echo "  CC    $@"
	@$(CC) -c $(CFLAGS) $< -o $@

tuntox: $(OBJECTS) $(INCLUDES)
	$(CC) -o $@ $(OBJECTS) -lpthread $(LDFLAGS) 

tuntox_nostatic: $(OBJECTS) $(INCLUDES)
	$(CC) -o $@ $(OBJECTS) -lpthread $(DSO_LDFLAGS) 

cscope.out:
	@echo "  GEN   $@"
	@cscope -bv ./*.[ch] &> /dev/null

clean:
	rm -f *.o tuntox cscope.out gitversion.h tox_bootstrap.h

.PHONY: all clean tuntox
