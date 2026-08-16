# Hardened Diagnostic Gateway
#
# Build minimal, sans dependance externe.
#
#   make          -> construit build/ecu et build/tester
#   make test     -> construit et lance les tests unitaires (ASan + UBSan)
#   make clean    -> supprime build/
#
# _DEFAULT_SOURCE est requis : en -std=c11 strict, la glibc masque
# struct ifreq (definie dans net/if.h sous __USE_MISC).

CC      := gcc
CFLAGS  := -Wall -Wextra -std=c11 -D_DEFAULT_SOURCE -Isrc/isotp
BUILD   := build

ISOTP   := src/isotp/isotp.c

# Les tests sont construits avec les sanitizers. Ils n'ont pas besoin de
# _DEFAULT_SOURCE : ils ne touchent ni SocketCAN ni struct ifreq, ce qui
# est precisement la preuve que la couche ISO-TP est independante de Linux.
TEST_CFLAGS := -Wall -Wextra -std=c11 -g -fsanitize=address,undefined -Isrc/isotp

all: $(BUILD)/ecu $(BUILD)/tester

$(BUILD)/ecu: src/ecu/ecu.c $(ISOTP) src/isotp/isotp.h | $(BUILD)
	$(CC) $(CFLAGS) src/ecu/ecu.c $(ISOTP) -o $@

$(BUILD)/tester: src/tester/tester.c $(ISOTP) src/isotp/isotp.h | $(BUILD)
	$(CC) $(CFLAGS) src/tester/tester.c $(ISOTP) -o $@

$(BUILD)/test_isotp: tests/test_isotp.c $(ISOTP) src/isotp/isotp.h | $(BUILD)
	$(CC) $(TEST_CFLAGS) tests/test_isotp.c $(ISOTP) -o $@

test: $(BUILD)/test_isotp
	./$(BUILD)/test_isotp

$(BUILD):
	mkdir -p $(BUILD)

clean:
	rm -rf $(BUILD)

.PHONY: all test clean
