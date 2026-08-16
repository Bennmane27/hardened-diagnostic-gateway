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
INCLUDES := -Isrc/isotp -Isrc/uds -Isrc/ecu
CFLAGS  := -Wall -Wextra -std=c11 -D_DEFAULT_SOURCE $(INCLUDES)
BUILD   := build

ISOTP    := src/isotp/isotp.c
UDS      := src/uds/uds.c
ECU_DATA := src/ecu/ecu_data.c
CORE     := $(ISOTP) $(UDS) $(ECU_DATA)
HEADERS  := src/isotp/isotp.h src/uds/uds.h src/ecu/ecu_data.h

# Les tests sont construits avec les sanitizers. Ils n'ont pas besoin de
# _DEFAULT_SOURCE : ils ne touchent ni SocketCAN ni struct ifreq, ce qui
# est precisement la preuve que les couches protocole sont independantes
# de Linux.
TEST_CFLAGS := -Wall -Wextra -std=c11 -g -fsanitize=address,undefined $(INCLUDES)

all: $(BUILD)/ecu $(BUILD)/tester

$(BUILD)/ecu: src/ecu/ecu.c $(CORE) $(HEADERS) | $(BUILD)
	$(CC) $(CFLAGS) src/ecu/ecu.c $(CORE) -o $@

$(BUILD)/tester: src/tester/tester.c $(CORE) $(HEADERS) | $(BUILD)
	$(CC) $(CFLAGS) src/tester/tester.c $(CORE) -o $@

$(BUILD)/test_isotp: tests/test_isotp.c $(ISOTP) src/isotp/isotp.h | $(BUILD)
	$(CC) $(TEST_CFLAGS) tests/test_isotp.c $(ISOTP) -o $@

$(BUILD)/test_uds: tests/test_uds.c $(UDS) src/uds/uds.h | $(BUILD)
	$(CC) $(TEST_CFLAGS) tests/test_uds.c $(UDS) -o $@

$(BUILD)/test_ecu_data: tests/test_ecu_data.c $(ECU_DATA) $(UDS) $(HEADERS) | $(BUILD)
	$(CC) $(TEST_CFLAGS) tests/test_ecu_data.c $(ECU_DATA) $(UDS) -o $@

test: $(BUILD)/test_isotp $(BUILD)/test_uds $(BUILD)/test_ecu_data
	./$(BUILD)/test_isotp
	@echo ""
	./$(BUILD)/test_uds
	@echo ""
	./$(BUILD)/test_ecu_data

$(BUILD):
	mkdir -p $(BUILD)

clean:
	rm -rf $(BUILD)

.PHONY: all test clean
