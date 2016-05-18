SOURCES = $(wildcard *.c)
INCLUDES = $(wildcard *.h) gitversion.h
OBJECTS = $(SOURCES:.c=.o)
DEPS = libtoxcore

CFLAGS += -Wall -Wextra
CFLAGS += $(shell pkg-config --cflags $(DEPS))
LDFLAGS += $(shell pkg-config --libs $(DEPS))
LDFLAGS_STATIC += -static -pthread -Wl,-Bstatic $(LDFLAGS)


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
	@$(CC) $(OBJECTS) $(LDFLAGS_STATIC) -o tuntox

cscope.out:
	@echo "  GEN   $@"
	@cscope -bv ./*.[ch] &> /dev/null

clean:
	rm -f *.o tuntox cscope.out gitversion.h

.PHONY: all clean tuntox_static
