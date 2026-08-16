#!/usr/bin/env bash
#
# gateway_demo.sh
#
# Demonstration de la passerelle AHDG EN LIGNE, entre deux bus CAN.
#
#     Testeur ── vcan0 ──► [ GATEWAY ] ──► vcan1 ── ECU
#
# Le point demontre : l'enforcement a lieu AVANT l'ECU. Une meme attaque
# (ECUReset sans deverrouillage) est bloquee a la passerelle ; le bus de
# confiance vcan1 ne la voit jamais. Un flux legitime passe intact.
#
# Usage : tools/demo/gateway_demo.sh

set -u
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT"
SP="$(mktemp -d)"
PIDS=()

cleanup() {
    for p in "${PIDS[@]:-}"; do kill "$p" 2>/dev/null; done
    pkill -x ecu 2>/dev/null; pkill -x gateway 2>/dev/null
    rm -rf "$SP"
}
trap cleanup EXIT

echo "=== Passerelle AHDG — demonstration deux bus ==="

# Les deux bus virtuels.
"$ROOT/tools/setup/ensure-vcan.sh" vcan0 || exit 1
"$ROOT/tools/setup/ensure-vcan.sh" vcan1 || exit 1

make -C "$ROOT" >/dev/null 2>&1 || { echo "compilation echouee"; exit 1; }

# ECU sur le bus de confiance.
HDG_IFACE=vcan1 stdbuf -oL "$ROOT/build/ecu" -q >/dev/null 2>&1 &
PIDS+=($!)
# Temoin : tout ce qui atteint reellement l'ECU.
stdbuf -oL candump vcan1 > "$SP/vcan1.log" 2>&1 &
PIDS+=($!)
# La passerelle.
HDG_IFACE_EXT=vcan0 HDG_IFACE_ECU=vcan1 stdbuf -oL "$ROOT/build/gateway" \
    > "$SP/gw.log" 2>&1 &
PIDS+=($!)
sleep 2

echo
echo "--- Le testeur (derriere la passerelle) joue :"
echo "    1. session etendue"
echo "    2. ECU reset          <- ATTAQUE : sans deverrouillage"
echo "    3. seed / key         <- deverrouillage legitime"
echo "    4. ECU reset          <- legitime cette fois"
echo
sleep 1

printf 'session extended\nreset\nseed\nkey\nreset\nquit\n' \
    | HDG_IFACE=vcan0 "$ROOT/build/diagcli" 2>&1 \
    | grep -E '>|REFUS|OK |DEVERROUILLE|reinitialise' | sed 's/^/  /'

sleep 1
pkill -x ecu 2>/dev/null; pkill -x gateway 2>/dev/null
sleep 0.5

echo
echo "--- Journal de la passerelle (decisions) :"
grep -E 'ALLOW|DROP' "$SP/gw.log" | sed 's/^/  /'

echo
echo "--- Ce qui a REELLEMENT atteint l'ECU sur le bus de confiance vcan1 :"
grep '7E0' "$SP/vcan1.log" | sed 's/^/  /'
echo
echo "  Note : l'ECUReset NON autorise (02 11 01 juste apres 02 10 03)"
echo "         est ABSENT de vcan1 — la passerelle l'a arrete avant l'ECU."
echo "         Seul le reset legitime, apres 27 02, y figure."
