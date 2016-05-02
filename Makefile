SOURCES = $(wildcard *.c)
INCLUDES = $(wildcard *.h) gitversion.h
OBJECTS = $(SOURCES:.c=.o)
DEPS = libtoxcore

CFLAGS = $(shell pkg-config --cflags $(DEPS))
LDFLAGS = $(shell pkg-config --libs $(DEPS))
LDFLAGS_STATIC = -static -pthread


# Check on what platform we are running
UNAME_M = $(shell uname -m)
ifeq ($(UNAME_M), x86_64)
    TOXCORE_STATIC_LIB = /usr/local/lib64/libtoxcore.a
    SODIUM_STATIC_LIB = /usr/local/lib64/libsodium.a
endif
ifneq ($(filter %86, $(UNAME_M)),)
    TOXCORE_STATIC_LIB = /usr/local/lib/libtoxcore.a
    SODIUM_STATIC_LIB = /usr/local/lib/libsodium.a
endif


# Targets
all: tuntox

gitversion.h: .git/HEAD .git/index
	@echo "  GEN   $@"
	@echo "#define GITVERSION \"$(shell git rev-parse HEAD)\"" > $@

%.o: %.c $(INCLUDES)
	@echo "  CC    $@"
	@$(CC) -c $(CFLAGS) $< -o $@

tuntox: $(OBJECTS) $(INCLUDES)
	@echo "  LD    $@"
	@$(CC) $(LDFLAGS) $(OBJECTS) -o $@

tuntox_static: $(OBJECTS) $(INCLUDES)
	@echo "  LD    tuntox"
	@$(CC) $(LDFLAGS_STATIC) $(OBJECTS) -o tuntox $(TOXCORE_STATIC_LIB) $(SODIUM_STATIC_LIB)

cscope.out:
	@echo "  GEN   $@"
	@cscope -bv ./*.[ch]

clean:
	rm -f *.o tuntox gitversion.h

.PHONY: all clean tuntox_static
