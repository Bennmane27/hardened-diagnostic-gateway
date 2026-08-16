# Hardened Diagnostic Gateway
#
# Build minimal, sans dependance externe.
#
#   make                     -> construit build/ecu et build/tester
#   make test                -> tests unitaires (ASan + UBSan)
#   make fuzz                -> campagne de fuzzing des analyseurs
#   make check-portability   -> verifie les invariants I1 et I2
#   make clean               -> supprime build/
#
# _DEFAULT_SOURCE est requis : en -std=c11 strict, la glibc masque
# struct ifreq (definie dans net/if.h sous __USE_MISC).

CC      := gcc
INCLUDES := -Isrc/isotp -Isrc/uds -Isrc/ecu -Isrc/platform -Isrc/platform/socketcan
CFLAGS  := -Wall -Wextra -std=c11 -D_DEFAULT_SOURCE $(INCLUDES)
BUILD   := build

ISOTP    := src/isotp/isotp.c src/isotp/isotp_rx.c src/isotp/isotp_tx.c
UDS      := src/uds/uds.c
ECU_DATA := src/ecu/ecu_data.c
PLATFORM := src/platform/socketcan/can_socket.c src/platform/diag_link.c
CORE     := $(ISOTP) $(UDS) $(ECU_DATA)
HEADERS  := src/isotp/isotp.h src/uds/uds.h src/ecu/ecu_data.h \
            src/platform/diag_link.h src/platform/socketcan/can_socket.h

# Les tests sont construits avec les sanitizers. Ils n'ont pas besoin de
# _DEFAULT_SOURCE : ils ne touchent ni SocketCAN ni struct ifreq, ce qui
# est precisement la preuve que les couches protocole sont independantes
# de Linux.
TEST_CFLAGS := -Wall -Wextra -std=c11 -g -fsanitize=address,undefined $(INCLUDES)

all: $(BUILD)/ecu $(BUILD)/tester $(BUILD)/fuzz_bus

$(BUILD)/ecu: src/ecu/ecu.c $(CORE) $(PLATFORM) $(HEADERS) | $(BUILD)
	$(CC) $(CFLAGS) src/ecu/ecu.c $(CORE) $(PLATFORM) -o $@

$(BUILD)/tester: src/tester/tester.c $(CORE) $(PLATFORM) $(HEADERS) | $(BUILD)
	$(CC) $(CFLAGS) src/tester/tester.c $(CORE) $(PLATFORM) -o $@

$(BUILD)/test_isotp: tests/test_isotp.c $(ISOTP) src/isotp/isotp.h | $(BUILD)
	$(CC) $(TEST_CFLAGS) tests/test_isotp.c $(ISOTP) -o $@

$(BUILD)/test_isotp_multiframe: tests/test_isotp_multiframe.c $(ISOTP) src/isotp/isotp.h | $(BUILD)
	$(CC) $(TEST_CFLAGS) tests/test_isotp_multiframe.c $(ISOTP) -o $@

$(BUILD)/test_uds: tests/test_uds.c $(UDS) src/uds/uds.h | $(BUILD)
	$(CC) $(TEST_CFLAGS) tests/test_uds.c $(UDS) -o $@

$(BUILD)/test_ecu_data: tests/test_ecu_data.c $(ECU_DATA) $(UDS) $(HEADERS) | $(BUILD)
	$(CC) $(TEST_CFLAGS) tests/test_ecu_data.c $(ECU_DATA) $(UDS) -o $@

test: $(BUILD)/test_isotp $(BUILD)/test_isotp_multiframe \
      $(BUILD)/test_uds $(BUILD)/test_ecu_data
	./$(BUILD)/test_isotp
	@echo ""
	./$(BUILD)/test_isotp_multiframe
	@echo ""
	./$(BUILD)/test_uds
	@echo ""
	./$(BUILD)/test_ecu_data

$(BUILD)/fuzz_bus: tools/fuzzer/fuzz_bus.c $(CORE) $(PLATFORM) $(HEADERS) | $(BUILD)
	$(CC) $(CFLAGS) tools/fuzzer/fuzz_bus.c $(ISOTP) $(UDS) $(PLATFORM) -o $@

$(BUILD)/fuzz_parser: fuzz/fuzz_parser.c $(ISOTP) $(UDS) $(HEADERS) | $(BUILD)
	$(CC) $(TEST_CFLAGS) fuzz/fuzz_parser.c $(ISOTP) $(UDS) -o $@

# Campagne courte par defaut : elle doit rester utilisable en CI.
# Pour une campagne longue : ./build/fuzz_parser 5000000 0x1234
fuzz: $(BUILD)/fuzz_parser
	./$(BUILD)/fuzz_parser 200000 0xC0FFEE

$(BUILD):
	mkdir -p $(BUILD)

# --------------------------------------------------------------------
# Invariants d'architecture, verifies mecaniquement.
#
# I1 : les couches protocole n'incluent aucun header systeme.
# I2 : aucune allocation dynamique dans src/.
#
# Ces deux regles sont ce qui rendra le portage microcontroleur
# possible. Une verification automatique vaut mieux qu'une intention.
# --------------------------------------------------------------------
PORTABLE_SRC := src/isotp src/uds

check-portability:
	@echo "== I1 : aucun header systeme dans les couches protocole =="
	@if grep -rn '#include[[:space:]]*<' $(PORTABLE_SRC) \
	     | grep -vE '<(stdint|stddef|string)\.h>'; then \
	    echo "ECHEC : header systeme interdit ci-dessus"; exit 1; \
	 else echo "OK"; fi
	@echo "== I2 : aucune allocation dynamique dans src/ =="
	@if grep -rnE '\b(malloc|calloc|realloc|free)[[:space:]]*\(' src/; then \
	    echo "ECHEC : allocation dynamique ci-dessus"; exit 1; \
	 else echo "OK"; fi
	@echo "== I1bis : les couches protocole compilent hors contexte Linux =="
	@for f in $(ISOTP) $(UDS); do \
	    $(CC) -Wall -Wextra -Werror -std=c11 -pedantic $(INCLUDES) \
	        -c $$f -o /dev/null || exit 1; \
	 done
	@echo "OK"
	@echo "== I1ter : couches protocole sous -Wconversion et -Wshadow =="
	@for f in $(ISOTP) $(UDS); do \
	    $(CC) -Wall -Wextra -Werror -Wconversion -Wshadow -Wpedantic \
	        -std=c11 $(INCLUDES) -c $$f -o /dev/null || exit 1; \
	 done
	@echo "OK"
	@echo "== I2bis : aucun symbole d'allocation dans les binaires =="
	@$(MAKE) --no-print-directory $(BUILD)/ecu $(BUILD)/tester >/dev/null
	@for b in $(BUILD)/ecu $(BUILD)/tester; do \
	    if nm -u $$b 2>/dev/null | grep -qE '\b(malloc|calloc|realloc|free)$$'; then \
	        echo "ECHEC : $$b reference l'allocateur"; exit 1; \
	    fi; \
	 done
	@echo "OK"

clean:
	rm -rf $(BUILD)

.PHONY: all test fuzz check-portability clean
