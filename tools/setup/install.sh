#!/usr/bin/env bash
#
# install.sh
#
# Rend l'interface vcan0 permanente : elle sera recreee a chaque
# demarrage de WSL, sans intervention.
#
# A lancer UNE FOIS :
#     sudo tools/setup/install.sh
#
# Ce que le script installe :
#
#   /usr/local/sbin/vcan-up          script idempotent de creation
#   /etc/systemd/system/vcan.service unite lancee au demarrage
#   /etc/sudoers.d/vcan              regle sans mot de passe, en secours
#
# La regle sudoers est volontairement etroite : elle n'autorise que
# l'execution de ce script precis, rien d'autre. Elle sert de filet si
# systemd n'est pas actif dans une future configuration.
#
# Pour tout retirer :
#     sudo tools/setup/install.sh --uninstall

set -euo pipefail

SBIN=/usr/local/sbin/vcan-up
UNIT=/etc/systemd/system/vcan.service
SUDOERS=/etc/sudoers.d/vcan

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

if [ "$(id -u)" -ne 0 ]; then
    echo "Ce script doit etre lance avec sudo :"
    echo "    sudo tools/setup/install.sh"
    exit 1
fi

# --- Desinstallation ------------------------------------------------

if [ "${1:-}" = "--uninstall" ]; then
    systemctl disable --now vcan.service 2>/dev/null || true
    rm -f "$UNIT" "$SBIN" "$SUDOERS"
    systemctl daemon-reload 2>/dev/null || true
    echo "Desinstalle. vcan0 ne sera plus recree au demarrage."
    exit 0
fi

# --- Installation ---------------------------------------------------

echo "== Installation du script de creation =="
install -m 0755 "$HERE/vcan-up" "$SBIN"
echo "   $SBIN"

echo "== Regle sudoers restreinte =="
# Le fichier autorise l'utilisateur courant a lancer CE script sans mot
# de passe. %sudo plutot qu'un nom en dur : cela reste valable si le
# compte change.
cat > "$SUDOERS" <<EOF
# Cree par tools/setup/install.sh du projet hardened-diagnostic-gateway.
# Autorise uniquement la creation de l'interface CAN virtuelle.
%sudo ALL=(root) NOPASSWD: $SBIN
EOF
chmod 0440 "$SUDOERS"

# visudo -c refuse un fichier mal forme : on verifie avant de laisser
# une regle cassee qui bloquerait sudo entierement.
if ! visudo -c -f "$SUDOERS" >/dev/null 2>&1; then
    rm -f "$SUDOERS"
    echo "   regle sudoers invalide, annulee"
else
    echo "   $SUDOERS"
fi

# --- systemd --------------------------------------------------------

if [ -d /run/systemd/system ]; then
    echo "== Unite systemd =="
    install -m 0644 "$HERE/vcan.service" "$UNIT"
    systemctl daemon-reload
    systemctl enable vcan.service >/dev/null
    systemctl restart vcan.service
    echo "   $UNIT (activee)"
else
    echo "== systemd absent =="
    echo "   Ajoutez ceci a /etc/wsl.conf puis 'wsl --shutdown' :"
    echo ""
    echo "   [boot]"
    echo "   command = $SBIN vcan0"
    echo ""
    "$SBIN" vcan0
fi

# --- Verification ---------------------------------------------------

echo ""
if ip link show vcan0 >/dev/null 2>&1; then
    ip -brief link show vcan0
    echo ""
    echo "vcan0 est active et sera recreee a chaque demarrage de WSL."
else
    echo "ECHEC : vcan0 n'a pas pu etre creee."
    exit 1
fi
