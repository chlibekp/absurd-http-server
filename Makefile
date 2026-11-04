#   make                    native static build (x86_64 or arm64), with TLS
#   make NO_TLS=1           without OpenSSL
#   make cross-arm64        cross-compile for arm64 into build/arm64 (Debian/Ubuntu: gcc-aarch64-linux-gnu
#                           and libssl-dev:arm64, or add NO_TLS=1)
CC      ?= cc
BUILD   ?= build
CFLAGS  ?= -O2
CFLAGS  += -std=gnu11 -Wall -Wextra -Wshadow -Wno-unused-parameter -fstack-protector-strong -D_FORTIFY_SOURCE=2
LDFLAGS += -static
LIBS     = -lpthread

ifdef NO_TLS
CFLAGS  += -DNO_TLS
else
LIBS    := -lssl -lcrypto $(LIBS)
endif

SRC = $(wildcard src/*.c)
OBJ = $(SRC:src/%.c=$(BUILD)/%.o)

$(BUILD)/absurd: $(OBJ)
	$(CC) $(LDFLAGS) -o $@ $(OBJ) $(LIBS)

$(BUILD)/%.o: src/%.c src/absurd.h | $(BUILD)
	$(CC) $(CFLAGS) -c -o $@ $<

$(BUILD):
	mkdir -p $(BUILD)

# multiarch OpenSSL keeps opensslconf.h under /usr/include/aarch64-linux-gnu
cross-arm64:
	mkdir -p build/arm64/inc
	ln -sfn /usr/include/openssl build/arm64/inc/openssl
	$(MAKE) BUILD=build/arm64 CC=aarch64-linux-gnu-gcc \
	    CFLAGS="$(CFLAGS) -isystem /usr/include/aarch64-linux-gnu -idirafter build/arm64/inc"

test: build/absurd
	python3 test/run.py

clean:
	rm -rf build

.PHONY: clean test cross-arm64
