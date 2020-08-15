SOURCES = $(wildcard *.c)
DEPS=toxcore
CC=gcc
CFLAGS=-g -Wall #-std=c99
CFLAGS += $(shell pkg-config --cflags $(DEPS))
LDFLAGS=-g -pthread -lm -static -lrt
LDFLAGS += $(shell pkg-config --static --libs $(DEPS))
DSO_LDFLAGS=-g -pthread -lm -lrt
DSO_LDFLAGS += $(shell pkg-config --libs $(DEPS))
OBJECTS=$(SOURCES:.c=.o)
INCLUDES = $(wildcard *.h)
PYTHON = /usr/bin/env python3
INSTALL = install -C
INSTALL_MKDIR = $(INSTALL) -d -m 755

prefix ?= /usr
bindir ?= $(prefix)/bin

# Targets
all: tuntox tuntox_nostatic

gitversion.h: FORCE
	@if [ -f .git/HEAD ] ; then echo "  GEN   $@"; echo "#define GITVERSION \"$(shell git rev-parse HEAD)\"" > $@; fi

FORCE:

tox_bootstrap.h: 
	$(PYTHON) generate_tox_bootstrap.py 

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

install: tuntox_nostatic
	$(INSTALL_MKDIR) -d $(DESTDIR)$(bindir)
	cp tuntox_nostatic $(DESTDIR)$(bindir)/tuntox

.PHONY: all clean tuntox
