SOURCES = client.c gitversion.c log.c mach.c main.c util.c
OBJECTS = $(SOURCES:.c=.o)
EXECUTABLES = tuntox tuntox_nostatic
DEB_VERSION = 0.0.9-1
DEB_ARCH = amd64
DEBS = ../tuntox_$(DEB_VERSION)_$(DEB_ARCH).deb ../tuntox-dbgsym_$(DEB_VERSION)_$(DEB_ARCH).deb
INCLUDES = client.h gitversion.h log.h mach.h main.h tox_bootstrap.h utarray.h uthash.h util.h utlist.h utstring.h
DEPS = toxcore
CC = gcc
CFLAGS = -g -Wall #-std=c99
CFLAGS += $(shell pkg-config --cflags $(DEPS))
LDFLAGS = -g -pthread -lm -static -lrt
LDFLAGS += $(shell pkg-config --static --libs $(DEPS))
DSO_LDFLAGS = -g -pthread -lm -lrt
DSO_LDFLAGS += $(shell pkg-config --libs $(DEPS))
PYTHON = /usr/bin/env python3
INSTALL = install -C
INSTALL_MKDIR = $(INSTALL) -d -m 755

prefix ?= /usr
bindir ?= $(prefix)/bin
etcdir ?= /etc

# Targets
.PHONY: all clean
all: $(EXECUTABLES)

gitversion != printf %s $$(git rev-parse HEAD) && (git diff --quiet || printf %s -dirty)
gitversion_on_disk != 2>/dev/null read _ _ v < gitversion.h && echo $$v || true
ifneq ("$(gitversion)", $(gitversion_on_disk))
.PHONY: gitversion.h
endif

gitversion.h:
	echo '#define GITVERSION "$(gitversion)"' > $@

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
	rm -f $(OBJECTS) $(EXECUTABLES) cscope.out gitversion.h tox_bootstrap.h

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

.PHONY: install-debs debs
install-debs: $(DEBS)
	$(shell [ "$$(id -u)" = 0 ] || echo sudo) dpkg -i $(DEBS)
$(DEBS) debs:
	fakeroot -- sh -c 'SKIP_SYSTEMCTL=y ./debian/rules binary'
