#!/usr/bin/env bash
#
# demo.sh
#
# Deroule la demonstration complete. C'est ce script que l'on
# enregistre : il lance l'ECU, joue le scenario dans le client
# interactif, puis bombarde le meme ECU avec l'injecteur de fautes.
#
# Le rythme est ralenti volontairement pour qu'un spectateur puisse
# suivre. DEMO_PACE regle l'ecart entre deux commandes.
#
# Usage :
#   tools/demo/demo.sh
#   DEMO_PACE=0.2 tools/demo/demo.sh     (rapide, pour verifier)

set -u

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
PACE="${DEMO_PACE:-1.1}"
ECU_PID=""

cleanup() { [ -n "$ECU_PID" ] && kill "$ECU_PID" 2>/dev/null; }
trap cleanup EXIT

banner()
{
    echo
    echo "════════════════════════════════════════════════════════════"
    echo "  $1"
    echo "════════════════════════════════════════════════════════════"
    sleep 1.2
}

# Envoie un fichier de commandes ligne par ligne, avec une pause.
pace()
{
    while IFS= read -r line; do
        printf '%s\n' "$line"
        sleep "$PACE"
    done < "$1"
    sleep 1.5
}

if ! ip link show vcan0 >/dev/null 2>&1; then
    echo "vcan0 absent. Lancez :"
    echo "  sudo modprobe vcan"
    echo "  sudo ip link add dev vcan0 type vcan"
    echo "  sudo ip link set up vcan0"
    exit 1
fi

cd "$ROOT"

banner "Hardened Diagnostic Gateway — demonstration"
echo "  Pile de diagnostic automobile en C : ISO-TP, UDS, ECU virtuel."
echo "  Bus CAN virtuel : vcan0"
sleep 2

banner "1. Les tests"
make test 2>&1 | grep -E 'Tests|verifications' | sed 's/^/  /'
sleep 2

banner "2. Les invariants d'architecture"
make check-portability 2>&1 | sed 's/^/  /'
sleep 2.5

banner "3. Dialogue avec l'ECU virtuel"
stdbuf -oL ./build/ecu -q >/dev/null 2>&1 &
ECU_PID=$!
sleep 1.5
pace tools/demo/scenario.txt | ./build/diagcli

banner "4. Injection de fautes"
echo "  Onze scenarios cibles. Toutes les 25 attaques, une requete"
echo "  parfaitement valide doit obtenir la reponse exacte attendue."
sleep 2.5
./build/fuzz_bus 100 0xBADC0DE 2>&1 | sed 's/^/  /'

kill "$ECU_PID" 2>/dev/null; ECU_PID=""
sleep 1

banner "5. Validation croisee contre la pile ISO-TP du noyau Linux"
echo "  Nos tests prouvent que notre emetteur et notre recepteur"
echo "  se comprennent. Le noyau est un arbitre independant."
sleep 2.5
./tests/interop/crossvalidate.sh 2>&1 | sed 's/^/  /'
sleep 2

banner "6. Fuzzing des analyseurs, en memoire"
./build/fuzz_parser 300000 0xC0FFEE 2>&1 | sed 's/^/  /'
sleep 2

banner "Fin"
echo "  github.com/Bennmane27/hardened-diagnostic-gateway"
sleep 2
