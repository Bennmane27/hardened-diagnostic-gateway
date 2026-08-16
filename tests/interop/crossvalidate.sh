#!/usr/bin/env bash
#
# crossvalidate.sh
#
# Validation croisee contre la pile ISO-TP du noyau Linux.
#
# Pourquoi ce test vaut plus que tous les autres reunis :
#
#   nos tests unitaires verifient que notre emetteur et notre recepteur
#   se comprennent. Si les deux partagent la meme erreur d'interpretation
#   de la norme, ils se comprendront parfaitement et tous les tests
#   passeront au vert. Confronter notre pile a une implementation
#   independante et largement deployee est le seul moyen de detecter ce
#   piege.
#
# Prerequis :
#   - vcan0 actif
#   - module noyau can-isotp disponible (il se charge a la demande)
#   - can-utils installe (isotpsend, isotprecv)
#   - make
#
# Usage :
#   tests/interop/crossvalidate.sh

set -u

IFACE="${IFACE:-vcan0}"
TESTER_ID=7E0
ECU_ID=7E8

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
TMP="$(mktemp -d)"
ECU_PID=""

failures=0
checks=0

cleanup()
{
    [ -n "$ECU_PID" ] && kill "$ECU_PID" 2>/dev/null
    rm -rf "$TMP"
}
trap cleanup EXIT

say()  { printf '%s\n' "$*"; }
pass() { checks=$((checks+1)); printf '  OK     %s\n' "$1"; }
fail() { checks=$((checks+1)); failures=$((failures+1));
         printf '  ECHEC  %s\n' "$1"
         printf '         attendu : %s\n' "$2"
         printf '         obtenu  : %s\n' "$3"; }

# Compare deux suites d'octets en ignorant les espaces de bord.
compare()
{
    local label="$1" expected="$2" actual="$3"
    expected="$(echo "$expected" | tr -s ' ' | sed 's/^ *//;s/ *$//')"
    actual="$(echo "$actual" | tr -s ' ' | sed 's/^ *//;s/ *$//')"

    if [ "$expected" = "$actual" ]; then
        pass "$label"
    else
        fail "$label" "$expected" "$actual"
    fi
}

say "============================================="
say " Validation croisee contre ISO-TP du noyau"
say "============================================="
say " interface : $IFACE"
say ""

# --- Verifications prealables ---------------------------------------

if ! ip link show "$IFACE" >/dev/null 2>&1; then
    say "ECHEC : l'interface $IFACE n'existe pas."
    say "        sudo modprobe vcan"
    say "        sudo ip link add dev $IFACE type vcan"
    say "        sudo ip link set up $IFACE"
    exit 1
fi

for tool in isotpsend isotprecv; do
    if ! command -v "$tool" >/dev/null 2>&1; then
        say "ECHEC : $tool introuvable (paquet can-utils)."
        exit 1
    fi
done

# Un aller-retour noyau-vers-noyau valide l'environnement avant de
# mettre en cause notre pile.
( timeout 3 isotprecv -s "$ECU_ID" -d "$TESTER_ID" "$IFACE" \
    > "$TMP/selftest" 2>&1 & )
sleep 0.4
echo "AA BB" | timeout 2 isotpsend -s "$TESTER_ID" -d "$ECU_ID" "$IFACE" \
    >/dev/null 2>&1
sleep 1
if ! grep -qi 'AA BB' "$TMP/selftest"; then
    say "ECHEC : la pile ISO-TP du noyau ne repond pas."
    say "        sudo modprobe can-isotp"
    exit 1
fi
say "Pile noyau operationnelle."

make -C "$ROOT" >/dev/null 2>&1 || { say "ECHEC : compilation."; exit 1; }

# stdbuf -oL : sans lui, la sortie de l'ECU est bufferisee par blocs
# quand elle est redirigee, et le test 3 lirait un fichier vide.
stdbuf -oL "$ROOT/build/ecu" -q >"$TMP/ecu.log" 2>&1 &
ECU_PID=$!
sleep 1.5

if ! kill -0 "$ECU_PID" 2>/dev/null; then
    say "ECHEC : l'ECU n'a pas demarre."
    exit 1
fi
say "ECU virtuel demarre (pid $ECU_PID)."
say ""

# --- Test 1 : requete courte, aller-retour complet ------------------

say "[1] Requete Single Frame emise par le noyau"

( timeout 6 isotprecv -s "$TESTER_ID" -d "$ECU_ID" "$IFACE" \
    > "$TMP/rx1" 2>&1 & )
sleep 0.4
echo "10 03" | timeout 4 isotpsend -s "$TESTER_ID" -d "$ECU_ID" "$IFACE" \
    >/dev/null 2>&1
sleep 2

compare "DiagnosticSessionControl : 50 03 + sessionParameterRecord" \
        "50 03 00 32 01 F4" \
        "$(cat "$TMP/rx1")"

# --- Test 2 : notre reponse multi-trames, reassemblee par le noyau --

say ""
say "[2] Reponse multi-trames de notre ECU, reassemblee par le noyau"

( timeout 8 isotprecv -s "$TESTER_ID" -d "$ECU_ID" "$IFACE" \
    > "$TMP/rx2" 2>&1 & )
sleep 0.4
echo "22 F1 90" | timeout 5 isotpsend -s "$TESTER_ID" -d "$ECU_ID" "$IFACE" \
    >/dev/null 2>&1
sleep 3

# 62 F1 90 suivi du VIN "VF1HDG2AX47129305" en ASCII : 20 octets au total.
VIN_HEX="56 46 31 48 44 47 32 41 58 34 37 31 32 39 33 30 35"
compare "ReadDataByIdentifier VIN : 20 octets sur plusieurs trames" \
        "62 F1 90 $VIN_HEX" \
        "$(cat "$TMP/rx2")"

# --- Test 3 : message multi-trames emis par le noyau ----------------

say ""
say "[3] Message multi-trames emis par le noyau, reassemble par nous"

LONG="22 F1 89 AA BB CC DD EE FF 11 22 33 44 55 66 77 88 99 00 AB CD EF 12 34 56 78 9A BC DE F0"
LONG_LEN=$(echo "$LONG" | wc -w)

before=$(grep -c 'requete' "$TMP/ecu.log" 2>/dev/null || echo 0)
echo "$LONG" | timeout 5 isotpsend -s "$TESTER_ID" -d "$ECU_ID" "$IFACE" \
    >/dev/null 2>&1
sleep 2

got_len="$(grep 'requete' "$TMP/ecu.log" | tail -1 | \
           sed -n 's/.*\[requete \([0-9]*\) octets\].*/\1/p')"

if [ "$got_len" = "$LONG_LEN" ]; then
    pass "les $LONG_LEN octets emis par le noyau sont reassembles"
else
    fail "reassemblage d'un message noyau" "$LONG_LEN octets" \
         "${got_len:-aucune requete recue}"
fi

# La requete est volontairement trop longue pour 0x22 : notre serveur
# doit la reassembler correctement PUIS la refuser au niveau UDS.
if grep -q 'incorrectMessageLength' "$TMP/ecu.log"; then
    pass "refus UDS apres reassemblage (NRC 0x13)"
else
    fail "refus UDS attendu" "incorrectMessageLength" \
         "$(grep 'UDS' "$TMP/ecu.log" | tail -1)"
fi

# --- Test 4 : requete inconnue, reponse negative ---------------------

say ""
say "[4] Reponse negative transportee jusqu'au noyau"

( timeout 6 isotprecv -s "$TESTER_ID" -d "$ECU_ID" "$IFACE" \
    > "$TMP/rx4" 2>&1 & )
sleep 0.4
echo "99 00" | timeout 4 isotpsend -s "$TESTER_ID" -d "$ECU_ID" "$IFACE" \
    >/dev/null 2>&1
sleep 2

compare "service inconnu : 7F 99 11" \
        "7F 99 11" \
        "$(cat "$TMP/rx4")"

# --- Bilan ----------------------------------------------------------

say ""
say "============================================="
say " $checks verification(s), $failures echec(s)"
say "============================================="

if ! kill -0 "$ECU_PID" 2>/dev/null; then
    say "ATTENTION : l'ECU s'est arrete pendant la campagne."
    failures=$((failures+1))
fi

exit $(( failures == 0 ? 0 : 1 ))
