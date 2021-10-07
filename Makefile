SOURCES = client.c gitversion.c log.c mach.c main.c util.c
OBJECTS=$(SOURCES:.c=.o)
INCLUDES = client.h gitversion.h log.h mach.h main.h tox_bootstrap.h utarray.h uthash.h util.h utlist.h utstring.h
DEPS=toxcore
CC=gcc
CFLAGS=-g -Wall #-std=c99
CFLAGS += $(shell pkg-config --cflags $(DEPS))
LDFLAGS=-g -pthread -lm -static -lrt
LDFLAGS += $(shell pkg-config --static --libs $(DEPS))
DSO_LDFLAGS=-g -pthread -lm -lrt
DSO_LDFLAGS += $(shell pkg-config --libs $(DEPS))
PYTHON = /usr/bin/env python3
INSTALL = install -C
INSTALL_MKDIR = $(INSTALL) -d -m 755

prefix ?= /usr
bindir ?= $(prefix)/bin
etcdir ?= /etc

# Targets
all: tuntox tuntox_nostatic

gitversion != printf %s $$(git rev-parse HEAD) && (git diff --quiet || printf %s -dirty)
gitversion_on_disk != read _ _ v < gitversion.h; echo $$v
ifneq ("$(gitversion)", $(gitversion_on_disk))
.PHONY: gitversion.h
endif

gitversion.h:
	echo '#define GITVERSION "$(gitversion)"' > $@

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
	install -d -m755 $(DESTDIR)$(bindir) $(DESTDIR)$(etcdir)
	install -d -m700 $(DESTDIR)$(etcdir)/tuntox
	install -D -T tuntox_nostatic $(DESTDIR)$(bindir)/tuntox
	install -D scripts/tokssh -t $(DESTDIR)$(bindir)/
	install -m0644 -D -t $(DESTDIR)$(etcdir)/systemd/system scripts/tuntox.service
ifeq ($(SKIP_SYSTEMCTL),)
	systemctl daemon-reload
	systemctl restart tuntox
	systemctl status tuntox
endif

debs = ../tuntox_0.0.9-1_amd64.deb ../tuntox-dbgsym_0.0.9-1_amd64.deb
.PHONY: install-debs debs
install-debs: $(debs)
	$(shell [ "$$(id -u)" = 0 ] || echo sudo) dpkg -i $(debs)
$(debs) debs:
	fakeroot -- sh -c 'SKIP_SYSTEMCTL=y ./debian/rules binary'

.PHONY: all clean tuntox
