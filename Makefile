# webos-ds5-raw-acl
#
#   make                                  native build (read/test the reference tools)
#   make CC=arm-webos-linux-gnueabi-gcc   cross-compile the daemon for the TV
#
# The client/ files are drop-in source for your app, not built here. `make
# client-check` syntax-checks them.

CC      ?= cc
CFLAGS  ?= -O2 -Wall -Wextra
LDLIBS_DAEMON = -lpthread

BIN = ds5_txd ds5_aclre ds5_aclinject

all: $(BIN)

ds5_txd: daemon/ds5_txd.c
	$(CC) $(CFLAGS) $< -o $@ $(LDLIBS_DAEMON)

ds5_aclre: reference/ds5_aclre.c
	$(CC) $(CFLAGS) $< -o $@

ds5_aclinject: reference/ds5_aclinject.c
	$(CC) $(CFLAGS) $< -o $@

client-check:
	$(CC) $(CFLAGS) -fsyntax-only client/ds5_acl_tx.c
	$(CC) $(CFLAGS) -fsyntax-only client/ds5_hidfd.c

clean:
	rm -f $(BIN)

.PHONY: all client-check clean
