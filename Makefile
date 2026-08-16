# Hardened Diagnostic Gateway
#
# Build minimal, sans dependance externe.
#
#   make                     -> construit ecu, tester, fuzz_bus, fuzz_parser
#   make test                -> tests unitaires (ASan + UBSan)
#   make fuzz                -> campagne de fuzzing des analyseurs
#   make explore             -> exploration adversariale des invariants UDS
#   make frames              -> exploration adversariale au niveau des trames CAN
#   make bench               -> banc de comparaison S0 / S1 / S2
#   make demo                -> rejoue et reenregistre la demonstration
#   make web                 -> console web sur http://127.0.0.1:8800
#   make gwdemo              -> demo passerelle en ligne (vcan0 <-> vcan1)
#   make setup               -> rappelle comment rendre vcan0 permanente
#   make check-portability   -> verifie les invariants d architecture
#   tests/interop/crossvalidate.sh -> validation croisee contre le noyau
#   make clean               -> supprime build/
#
# _DEFAULT_SOURCE est requis : en -std=c11 strict, la glibc masque
# struct ifreq (definie dans net/if.h sous __USE_MISC).

CC      := gcc
INCLUDES := -Isrc/isotp -Isrc/uds -Isrc/ecu -Isrc/gateway -Isrc/platform -Isrc/platform/socketcan
CFLAGS  := -Wall -Wextra -std=c11 -D_DEFAULT_SOURCE $(INCLUDES)
BUILD   := build

ISOTP    := src/isotp/isotp.c src/isotp/isotp_rx.c src/isotp/isotp_tx.c
UDS      := src/uds/uds.c
ECU_DATA := src/ecu/ecu_data.c
GATEWAY  := src/gateway/gateway.c
PLATFORM := src/platform/socketcan/can_socket.c src/platform/diag_link.c
CORE     := $(ISOTP) $(UDS) $(ECU_DATA)
HEADERS  := src/isotp/isotp.h src/uds/uds.h src/ecu/ecu_data.h \
            src/platform/diag_link.h src/platform/socketcan/can_socket.h

# Les tests sont construits avec les sanitizers. Ils n'ont pas besoin de
# _DEFAULT_SOURCE : ils ne touchent ni SocketCAN ni struct ifreq, ce qui
# est precisement la preuve que les couches protocole sont independantes
# de Linux.
TEST_CFLAGS := -Wall -Wextra -std=c11 -g -fsanitize=address,undefined $(INCLUDES)

all: $(BUILD)/ecu $(BUILD)/tester $(BUILD)/diagcli $(BUILD)/gateway \
     $(BUILD)/fuzz_bus $(BUILD)/fuzz_parser $(BUILD)/ahdg_explore \
     $(BUILD)/ahdg_frames $(BUILD)/bench

$(BUILD)/ecu: src/ecu/ecu.c $(CORE) $(PLATFORM) $(HEADERS) | $(BUILD)
	$(CC) $(CFLAGS) src/ecu/ecu.c $(CORE) $(PLATFORM) -o $@

$(BUILD)/tester: src/tester/tester.c $(CORE) $(PLATFORM) $(HEADERS) | $(BUILD)
	$(CC) $(CFLAGS) src/tester/tester.c $(CORE) $(PLATFORM) -o $@

$(BUILD)/diagcli: src/tester/diagcli.c $(CORE) $(PLATFORM) $(HEADERS) | $(BUILD)
	$(CC) $(CFLAGS) src/tester/diagcli.c $(CORE) $(PLATFORM) -o $@

$(BUILD)/gateway: src/gateway/gateway_main.c $(CORE) $(GATEWAY) $(PLATFORM) \
                 $(HEADERS) src/gateway/gateway.h | $(BUILD)
	$(CC) $(CFLAGS) src/gateway/gateway_main.c $(CORE) $(GATEWAY) $(PLATFORM) -o $@

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

$(BUILD)/ahdg_explore: fuzz/ahdg_explore.c $(UDS) src/uds/uds.h \
                      src/gateway/invariants.h | $(BUILD)
	$(CC) $(TEST_CFLAGS) fuzz/ahdg_explore.c $(UDS) -o $@

# Explorateur adversarial de l'espace d'etats UDS. Code de sortie non nul
# si un contre-exemple non couvert par une regression apparait : la CI en
# fait un critere de reussite.
explore: $(BUILD)/ahdg_explore
	./$(BUILD)/ahdg_explore 500000 0xA11CE

ISOTP_C := src/isotp/isotp.c src/isotp/isotp_rx.c src/isotp/isotp_tx.c

$(BUILD)/ahdg_frames: fuzz/ahdg_frames.c $(ISOTP_C) $(UDS) $(ECU_DATA) \
                     $(HEADERS) src/gateway/invariants.h | $(BUILD)
	$(CC) $(TEST_CFLAGS) fuzz/ahdg_frames.c $(ISOTP_C) $(UDS) $(ECU_DATA) -o $@

# Explorateur adversarial au niveau des trames CAN : cherche une confusion
# cross-layer ou une atteinte a la disponibilite dans le vrai pipeline
# isotp_rx + uds. Sortie non nulle si un contre-exemple apparait.
frames: $(BUILD)/ahdg_frames
	./$(BUILD)/ahdg_frames 300000 0xF00D

$(BUILD)/bench: bench/bench.c $(UDS) $(GATEWAY) src/uds/uds.h \
               src/gateway/gateway.h src/gateway/invariants.h | $(BUILD)
	$(CC) $(TEST_CFLAGS) bench/bench.c $(UDS) $(GATEWAY) -o $@

# Banc S0 / S1 / S2 : la gateway d'admission comparee a un ECU seul et a
# un filtre sans etat, sur le meme corpus d'attaques.
bench: $(BUILD)/bench
	./$(BUILD)/bench 200000 0xB0A7

# Rejoue la demonstration, la reenregistre et regenere le SVG anime du
# README. Necessite asciinema.
demo: all
	@command -v asciinema >/dev/null 2>&1 || \
	    { echo "asciinema absent : sudo apt install asciinema"; exit 1; }
	DEMO_PACE=0.6 asciinema rec --overwrite --rows 34 --cols 100 \
	    -c tools/demo/demo.sh docs/media/demo.cast
	tools/demo/cast2svg.py docs/media/demo.cast docs/media/demo.svg \
	    --rows 30 --fps 1.4

# Console web : plusieurs terminaux dans le navigateur, pilotage des
# binaires et scenario automatise. Outil de demonstration, sans lien de
# compilation avec src/.
web: all
	tools/webdemo/server.py

# Demonstration de la passerelle en ligne entre deux bus (vcan0 <-> vcan1).
gwdemo: all
	tools/demo/gateway_demo.sh

# vcan0 disparait a chaque redemarrage de WSL. L'unite systemd installee
# ici la recree automatiquement. Le make ne peut pas elever ses droits :
# il affiche la commande a lancer.
setup:
	@echo "Pour rendre vcan0 permanente (une seule fois) :"
	@echo ""
	@echo "    sudo tools/setup/install.sh"
	@echo ""
	@echo "Etat actuel :"
	@ip -brief link show vcan0 2>/dev/null || echo "    vcan0 absente"

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
	@for f in $(ISOTP) $(UDS) $(GATEWAY); do \
	    $(CC) -Wall -Wextra -Werror -std=c11 -pedantic $(INCLUDES) \
	        -c $$f -o /dev/null || exit 1; \
	 done
	@echo "OK"
	@echo "== I1ter : couches protocole sous -Wconversion et -Wshadow =="
	@for f in $(ISOTP) $(UDS) $(GATEWAY); do \
	    $(CC) -Wall -Wextra -Werror -Wconversion -Wshadow -Wpedantic \
	        -std=c11 $(INCLUDES) -c $$f -o /dev/null || exit 1; \
	 done
	@echo "OK"
	@echo "== I1quater : couches protocole compilables sans libc ni OS =="
	@for f in $(ISOTP) $(UDS) $(GATEWAY); do \
	    $(CC) -Wall -Wextra -Werror -std=c11 -pedantic \
	        -ffreestanding -nostdinc \
	        -isystem "$$($(CC) -print-file-name=include)" \
	        $(INCLUDES) -c $$f -o /dev/null || exit 1; \
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

.PHONY: all test fuzz explore frames bench demo web gwdemo setup check-portability clean
