SOURCES = $(wildcard *.c)
DEPS=toxcore
CC?=$(CC)
CFLAGS=-g -Wall #-std=c99
CFLAGS += $(shell pkg-config --cflags $(DEPS))
LDFLAGS=-g -pthread -lm -static
LDFLAGS += $(shell pkg-config --static --libs $(DEPS))
DSO_LDFLAGS=-g -pthread -lm
DSO_LDFLAGS += $(shell pkg-config --libs $(DEPS))
OBJECTS=$(SOURCES:.c=.o)
INCLUDES = $(wildcard *.h)
PYTHON = /usr/bin/env python3
INSTALL = install -C
INSTALL_MKDIR = $(INSTALL) -d -m 755
OS=$(shell uname)

ifneq ($(OS),Darwin)
	LDFLAGS += -lrt
	DSO_LDFLAGS += -lrt
endif

PREFIX ?= /usr
BINDIR ?= $(PREFIX)/bin

# Targets
all: tuntox tuntox_nostatic

gitversion.h: FORCE
	@if [ -d .git ]; then \
		echo "  GEN   $@"; \
		echo "#define GITVERSION \"$(shell git rev-parse HEAD)\"" > $@; \
	fi


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
	$(RM) *.o tuntox cscope.out gitversion.h tox_bootstrap.h

install: tuntox_nostatic
	$(INSTALL_MKDIR) -d $(DESTDIR)$(BINDIR)
	$(INSTALL) tuntox_nostatic $(DESTDIR)$(BINDIR)/tuntox

.PHONY: all clean tuntox
