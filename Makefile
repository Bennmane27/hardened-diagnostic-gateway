# Hardened Diagnostic Gateway
#
# Build minimal, sans dependance externe.
#
#   make                     -> construit build/ecu et build/tester
#   make test                -> tests unitaires (ASan + UBSan)
#   make check-portability   -> verifie les invariants I1 et I2
#   make clean               -> supprime build/
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
	@if grep -rnw -e malloc -e calloc -e realloc -e free src/; then \
	    echo "ECHEC : allocation dynamique ci-dessus"; exit 1; \
	 else echo "OK"; fi
	@echo "== I1bis : les couches protocole compilent hors contexte Linux =="
	@$(CC) -Wall -Wextra -Werror -std=c11 -pedantic $(INCLUDES) \
	    -c $(ISOTP) -o /dev/null
	@$(CC) -Wall -Wextra -Werror -std=c11 -pedantic $(INCLUDES) \
	    -c $(UDS) -o /dev/null
	@echo "OK"

clean:
	rm -rf $(BUILD)

.PHONY: all test check-portability clean
