#!/usr/bin/env bash
#
# ensure-vcan.sh
#
# Garantit que vcan0 existe, sans jamais bloquer sur une demande de mot
# de passe.
#
# Appele au debut des scripts du projet. Trois cas :
#
#   1. l'interface existe deja            -> ne fait rien
#   2. la regle sudoers est installee      -> la cree silencieusement
#   3. rien n'est installe                 -> explique quoi lancer
#
# Le "sudo -n" est ce qui evite le blocage : il echoue immediatement si
# un mot de passe est requis, au lieu d'attendre une saisie qui ne
# viendra jamais dans un script.

IFACE="${1:-vcan0}"
SBIN=/usr/local/sbin/vcan-up

if ip link show "$IFACE" >/dev/null 2>&1; then
    exit 0
fi

if [ -x "$SBIN" ] && sudo -n "$SBIN" "$IFACE" 2>/dev/null; then
    exit 0
fi

cat >&2 <<EOF

L'interface $IFACE n'existe pas.

Pour la creer une fois pour toutes, y compris apres chaque redemarrage
de WSL, lancez :

    sudo tools/setup/install.sh

Ou, juste pour cette session :

    sudo modprobe vcan
    sudo ip link add dev $IFACE type vcan
    sudo ip link set up $IFACE

EOF
exit 1
