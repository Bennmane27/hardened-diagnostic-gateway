# Hardened Diagnostic Gateway
#
# Build minimal, sans dependance externe.
#
#   make          -> construit build/ecu et build/tester
#   make clean    -> supprime build/
#
# _DEFAULT_SOURCE est requis : en -std=c11 strict, la glibc masque
# struct ifreq (definie dans net/if.h sous __USE_MISC).

CC      := gcc
CFLAGS  := -Wall -Wextra -std=c11 -D_DEFAULT_SOURCE -Isrc/isotp
BUILD   := build

ISOTP   := src/isotp/isotp.c

all: $(BUILD)/ecu $(BUILD)/tester

$(BUILD)/ecu: src/ecu/ecu.c $(ISOTP) src/isotp/isotp.h | $(BUILD)
	$(CC) $(CFLAGS) src/ecu/ecu.c $(ISOTP) -o $@

$(BUILD)/tester: src/tester/tester.c $(ISOTP) src/isotp/isotp.h | $(BUILD)
	$(CC) $(CFLAGS) src/tester/tester.c $(ISOTP) -o $@

$(BUILD):
	mkdir -p $(BUILD)

clean:
	rm -rf $(BUILD)

.PHONY: all clean
