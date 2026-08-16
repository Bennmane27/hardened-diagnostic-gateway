#!/usr/bin/env bash
#
# build.sh
#
# Compile le vrai stack C (uds, isotp, ecu, explorateur adversarial) vers
# WebAssembly avec emscripten. Produit web/ahdg.js + web/ahdg.wasm, charges
# par web/index.html.
#
# En local (si emscripten est installe) :
#   web/build.sh
#
# En CI, l'image officielle emscripten/emsdk fournit emcc :
#   docker run --rm -v "$PWD":/src -w /src emscripten/emsdk bash web/build.sh

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

if ! command -v emcc >/dev/null 2>&1; then
    echo "emcc introuvable."
    echo "  local : installez emscripten (https://emscripten.org)"
    echo "  ou     : docker run --rm -v \"\$PWD\":/src -w /src emscripten/emsdk \\"
    echo "                bash web/build.sh"
    exit 1
fi

SRC="web/wasm/ahdg_wasm.c \
     src/uds/uds.c \
     src/isotp/isotp.c src/isotp/isotp_rx.c src/isotp/isotp_tx.c \
     src/ecu/ecu_data.c"

# Fonctions C exposees au JavaScript. Le prefixe underscore est la
# convention de nommage d'emscripten.
EXPORTS='["_ahdg_version","_ahdg_reset","_ahdg_state","_ahdg_request","_ahdg_isotp_decode","_ahdg_isotp_encode","_ahdg_explore","_ahdg_invariants"]'

emcc $SRC \
    -Isrc/isotp -Isrc/uds -Isrc/ecu -Isrc/gateway -Ifuzz \
    -O2 \
    -sMODULARIZE=1 \
    -sEXPORT_NAME=createAHDG \
    -sEXPORTED_FUNCTIONS="$EXPORTS" \
    -sEXPORTED_RUNTIME_METHODS='["ccall","cwrap","UTF8ToString"]' \
    -sALLOW_MEMORY_GROWTH=1 \
    -sENVIRONMENT=web \
    -sINITIAL_MEMORY=33554432 \
    -o web/ahdg.js

echo "OK : web/ahdg.js + web/ahdg.wasm generes"
ls -la web/ahdg.js web/ahdg.wasm
