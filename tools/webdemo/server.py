#!/usr/bin/env python3
"""
server.py

Console web du Hardened Diagnostic Gateway.

Sert une page unique qui affiche plusieurs terminaux cote a cote et
pilote les binaires du projet : ECU virtuel, client de diagnostic,
trafic du bus, tests, fuzzers.

C'est un OUTIL DE DEMONSTRATION, pas un morceau de la pile de
diagnostic. Il vit dans tools/ et n'est jamais compile ni lie avec
src/. La pile reste du C sans dependance ; ce serveur n'utilise que la
bibliotheque standard de Python, donc rien a installer non plus.

Deux choix de conception qui meritent d'etre expliques :

  - Le serveur n'ecoute que sur 127.0.0.1. Il expose le droit de lancer
    des processus ; le rendre accessible depuis le reseau serait une
    porte ouverte.

  - Le navigateur ne transmet jamais de ligne de commande. Il demande un
    identifiant de preset, et le serveur choisit la commande dans une
    table figee. Sans cela, une page malveillante ouverte dans le meme
    navigateur pourrait faire executer n'importe quoi.

Usage :
    tools/webdemo/server.py            puis http://127.0.0.1:8800
    tools/webdemo/server.py --port 9000
"""

import argparse
import json
import os
import shutil
import signal
import subprocess
import sys
import threading
import time
import webbrowser
from collections import deque
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlparse, parse_qs

ROOT = Path(__file__).resolve().parents[2]
HERE = Path(__file__).resolve().parent

# Nombre de lignes conservees par terminal. Un fuzzer bavard ne doit pas
# faire enfler la memoire du serveur indefiniment.
SCROLLBACK = 4000


# ---------------------------------------------------------------- presets

def _b(name):
    return str(ROOT / "build" / name)


PRESETS = {
    "ecu": {
        "label": "ECU virtuel",
        "cmd": [_b("ecu")],
        "pane": "ecu",
        "long_running": True,
    },
    "diagcli": {
        "label": "Client de diagnostic",
        "cmd": [_b("diagcli")],
        "pane": "cli",
        "long_running": True,
        "stdin": True,
    },
    "candump": {
        "label": "Trafic du bus",
        "cmd": ["candump", "-t", "d", "vcan0"],
        "pane": "bus",
        "long_running": True,
    },
    "tester": {
        "label": "Scenario automatique",
        "cmd": [_b("tester")],
        "pane": "run",
    },
    "tests": {
        "label": "Tests unitaires",
        "cmd": ["make", "-s", "test"],
        "pane": "run",
    },
    "invariants": {
        "label": "Invariants d'architecture",
        "cmd": ["make", "-s", "check-portability"],
        "pane": "run",
    },
    "fuzz_bus": {
        "label": "Injection de fautes",
        "cmd": [_b("fuzz_bus"), "200", "0xBADC0DE"],
        "pane": "run",
    },
    "fuzz_parser": {
        "label": "Fuzzing des analyseurs",
        "cmd": [_b("fuzz_parser"), "300000", "0xC0FFEE"],
        "pane": "run",
    },
    "crossvalidate": {
        "label": "Validation croisee noyau",
        "cmd": [str(ROOT / "tests/interop/crossvalidate.sh")],
        "pane": "run",
    },
    "build": {
        "label": "Compilation",
        "cmd": ["make", "-s"],
        "pane": "run",
    },
}

PANES = ("ecu", "cli", "bus", "run")


# ------------------------------------------------------------------ panes

class Pane:
    """Un terminal : un processus, son historique, son entree."""

    def __init__(self, name):
        self.name = name
        self.lock = threading.Lock()
        self.lines = deque(maxlen=SCROLLBACK)
        self.first_index = 0          # index absolu de lines[0]
        self.next_index = 0           # index absolu de la prochaine ligne
        self.process = None
        self.preset = None
        self.reader = None

    # -- ecriture ----------------------------------------------------

    def emit(self, text, kind="out"):
        with self.lock:
            self.lines.append({"i": self.next_index, "k": kind, "t": text})
            self.next_index += 1
            if len(self.lines) == self.lines.maxlen:
                self.first_index = self.lines[0]["i"]

    def clear(self):
        with self.lock:
            self.lines.clear()
            self.first_index = self.next_index

    # -- lecture -----------------------------------------------------

    def since(self, index):
        with self.lock:
            if index < self.first_index:
                index = self.first_index
            out = [item for item in self.lines if item["i"] >= index]
            return out, self.next_index

    # -- processus ---------------------------------------------------

    def running(self):
        return self.process is not None and self.process.poll() is None

    def start(self, key):
        if self.running():
            self.stop()

        preset = PRESETS[key]
        cmd = list(preset["cmd"])

        # stdbuf : sans lui la sortie d'un programme redirige vers un
        # tube est bufferisee par blocs, et le terminal web resterait
        # vide jusqu'a la fin du processus.
        if shutil.which("stdbuf"):
            cmd = ["stdbuf", "-oL", "-eL"] + cmd

        self.preset = key
        self.emit(f"$ {' '.join(preset['cmd'])}", kind="cmd")

        try:
            self.process = subprocess.Popen(
                cmd,
                cwd=str(ROOT),
                stdin=subprocess.PIPE if preset.get("stdin") else subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                bufsize=1,
                start_new_session=True,
            )
        except FileNotFoundError as exc:
            self.emit(f"introuvable : {exc.filename}", kind="err")
            self.process = None
            return False

        self.reader = threading.Thread(target=self._pump, daemon=True)
        self.reader.start()
        return True

    def _pump(self):
        process = self.process
        try:
            for line in process.stdout:
                self.emit(line.rstrip("\n"))
        except Exception:
            pass
        finally:
            code = process.wait()
            if code == 0:
                self.emit("[termine]", kind="done")
            else:
                self.emit(f"[termine, code {code}]", kind="err")

    def send(self, text):
        if not self.running() or self.process.stdin is None:
            return False
        try:
            self.process.stdin.write(text + "\n")
            self.process.stdin.flush()
            return True
        except (BrokenPipeError, ValueError):
            return False

    def stop(self):
        if self.process is None:
            return
        if self.process.poll() is None:
            try:
                # Le groupe entier : un script shell laisse sinon ses
                # enfants derriere lui.
                os.killpg(os.getpgid(self.process.pid), signal.SIGTERM)
            except (ProcessLookupError, PermissionError):
                self.process.terminate()
            try:
                self.process.wait(timeout=3)
            except subprocess.TimeoutExpired:
                try:
                    os.killpg(os.getpgid(self.process.pid), signal.SIGKILL)
                except (ProcessLookupError, PermissionError):
                    self.process.kill()
        self.process = None


PANE_BY_NAME = {name: Pane(name) for name in PANES}


# --------------------------------------------------------------- scenario

SCENARIO = [
    ("say", "La session par defaut ne donne acces a rien de sensible"),
    ("cmd", "present"),
    ("cmd", "reset"),
    ("say", "On ouvre la session etendue"),
    ("cmd", "session extended"),
    ("cmd", "read sw"),
    ("cmd", "read rpm"),
    ("say", "Le VIN fait 17 octets : ISO-TP le decoupe en plusieurs trames"),
    ("cmd", "read vin"),
    ("cmd", "dtc"),
    ("say", "Session ouverte, mais la commande sensible reste verrouillee"),
    ("cmd", "reset"),
    ("say", "SecurityAccess : graine, mauvaise cle, nouvelle graine, bonne cle"),
    ("cmd", "seed"),
    ("cmd", "key DEADBEEF"),
    ("cmd", "seed"),
    ("cmd", "key"),
    ("say", "Rejeu immediat de la meme cle : la graine a ete consommee"),
    ("cmd", "key"),
    ("say", "Operations desormais autorisees"),
    ("cmd", "clear"),
    ("cmd", "dtc"),
    ("cmd", "reset"),
    ("say", "Le reset a tout reverrouille"),
    ("cmd", "reset"),
    ("cmd", "stats"),
]

_scenario_lock = threading.Lock()
_scenario_thread = None
_scenario_cancel = threading.Event()


def scenario_running():
    """
    Etat derive du thread lui-meme, jamais d'un drapeau separe.

    Un booleen mis a jour a la main finit toujours par mentir : il suffit
    qu'un chemin de sortie oublie de le remettre a zero pour que
    l'interface reste bloquee sur "en cours" alors que plus rien ne
    tourne. Interroger le thread ne peut pas se desynchroniser.
    """
    return _scenario_thread is not None and _scenario_thread.is_alive()


def stop_scenario():
    _scenario_cancel.set()


def run_scenario(pace):
    global _scenario_thread

    with _scenario_lock:
        if scenario_running():
            return False
        _scenario_cancel.clear()

        def worker():
            cli = PANE_BY_NAME["cli"]
            ecu = PANE_BY_NAME["ecu"]

            def wait(seconds):
                """Attente interruptible : renvoie False si on annule."""
                return not _scenario_cancel.wait(seconds)

            if not ecu.running():
                ecu.start("ecu")
                if not wait(1.5):
                    return
            if not cli.running():
                cli.start("diagcli")
                if not wait(1.0):
                    return

            for kind, text in SCENARIO:
                if _scenario_cancel.is_set():
                    return

                # Le client a disparu : poursuivre enverrait des
                # commandes dans le vide et desynchroniserait l'affichage.
                if not cli.running():
                    cli.emit("[scenario interrompu : client arrete]",
                             kind="err")
                    return

                if kind == "say":
                    cli.emit("", kind="out")
                    cli.emit(f"--- {text} ---", kind="note")
                    if not wait(pace * 0.8):
                        return
                else:
                    if not cli.send(text):
                        cli.emit("[scenario interrompu : envoi impossible]",
                                 kind="err")
                        return
                    if not wait(pace):
                        return

            cli.emit("", kind="out")
            cli.emit("--- scenario termine ---", kind="done")

        _scenario_thread = threading.Thread(target=worker, daemon=True)
        _scenario_thread.start()
        return True


# ----------------------------------------------------------------- status

def vcan_state():
    try:
        out = subprocess.run(["ip", "-brief", "link", "show", "vcan0"],
                             capture_output=True, text=True, timeout=3)
        if out.returncode != 0:
            return {"present": False, "detail": "interface absente"}
        return {"present": True, "detail": " ".join(out.stdout.split())}
    except Exception as exc:
        return {"present": False, "detail": str(exc)}


def status():
    binaries = ["ecu", "tester", "diagcli", "fuzz_bus", "fuzz_parser"]
    return {
        "vcan": vcan_state(),
        "binaries": {name: (ROOT / "build" / name).exists()
                     for name in binaries},
        "panes": {
            name: {
                "running": pane.running(),
                "preset": pane.preset,
                "label": PRESETS[pane.preset]["label"] if pane.preset else None,
            }
            for name, pane in PANE_BY_NAME.items()
        },
        "scenario": scenario_running(),
        "presets": {k: {"label": v["label"], "pane": v["pane"]}
                    for k, v in PRESETS.items()},
    }


# ---------------------------------------------------------------- handler

class Handler(BaseHTTPRequestHandler):
    server_version = "HDGConsole/1.0"

    def log_message(self, fmt, *args):
        pass          # le terminal du serveur reste lisible

    # -- utilitaires -------------------------------------------------

    def _send(self, code, body, ctype="application/json; charset=utf-8"):
        if isinstance(body, (dict, list)):
            body = json.dumps(body).encode("utf-8")
        elif isinstance(body, str):
            body = body.encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def _body(self):
        length = int(self.headers.get("Content-Length") or 0)
        if length == 0:
            return {}
        try:
            return json.loads(self.rfile.read(length))
        except json.JSONDecodeError:
            return {}

    # -- GET ---------------------------------------------------------

    def do_GET(self):
        url = urlparse(self.path)
        query = parse_qs(url.query)

        if url.path in ("/", "/index.html"):
            page = HERE / "index.html"
            return self._send(200, page.read_text(encoding="utf-8"),
                              "text/html; charset=utf-8")

        if url.path == "/demo.svg":
            svg = ROOT / "docs/media/demo.svg"
            if svg.exists():
                return self._send(200, svg.read_text(encoding="utf-8"),
                                  "image/svg+xml")
            return self._send(404, {"error": "demo.svg absent"})

        if url.path == "/api/status":
            return self._send(200, status())

        if url.path == "/api/output":
            name = (query.get("pane") or [""])[0]
            if name not in PANE_BY_NAME:
                return self._send(404, {"error": "terminal inconnu"})
            since = int((query.get("since") or ["0"])[0])
            lines, nxt = PANE_BY_NAME[name].since(since)
            return self._send(200, {
                "lines": lines,
                "next": nxt,
                "running": PANE_BY_NAME[name].running(),
            })

        return self._send(404, {"error": "chemin inconnu"})

    # -- POST --------------------------------------------------------

    def do_POST(self):
        url = urlparse(self.path)
        body = self._body()

        if url.path == "/api/start":
            key = body.get("preset")
            if key not in PRESETS:
                return self._send(400, {"error": "preset inconnu"})
            pane = PANE_BY_NAME[PRESETS[key]["pane"]]
            ok = pane.start(key)
            return self._send(200, {"ok": ok, "pane": pane.name})

        if url.path == "/api/stop":
            name = body.get("pane")
            if name not in PANE_BY_NAME:
                return self._send(400, {"error": "terminal inconnu"})
            PANE_BY_NAME[name].stop()
            return self._send(200, {"ok": True})

        if url.path == "/api/clear":
            name = body.get("pane")
            if name not in PANE_BY_NAME:
                return self._send(400, {"error": "terminal inconnu"})
            PANE_BY_NAME[name].clear()
            return self._send(200, {"ok": True})

        if url.path == "/api/input":
            name = body.get("pane", "cli")
            text = body.get("text", "")
            if name not in PANE_BY_NAME:
                return self._send(400, {"error": "terminal inconnu"})
            ok = PANE_BY_NAME[name].send(text)
            return self._send(200, {"ok": ok})

        if url.path == "/api/scenario":
            pace = float(body.get("pace", 1.0))
            pace = min(max(pace, 0.1), 5.0)
            return self._send(200, {"ok": run_scenario(pace)})

        if url.path == "/api/scenario/stop":
            stop_scenario()
            return self._send(200, {"ok": True})

        if url.path == "/api/stopall":
            stop_scenario()
            for pane in PANE_BY_NAME.values():
                pane.stop()
            return self._send(200, {"ok": True})

        return self._send(404, {"error": "chemin inconnu"})


# -------------------------------------------------------------------- main

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, default=8800)
    ap.add_argument("--no-browser", action="store_true")
    args = ap.parse_args()

    # 127.0.0.1 et pas 0.0.0.0 : ce serveur lance des processus.
    server = ThreadingHTTPServer(("127.0.0.1", args.port), Handler)

    url = f"http://127.0.0.1:{args.port}"
    print("=" * 58)
    print(" Console web — Hardened Diagnostic Gateway")
    print("=" * 58)
    print(f"  {url}")
    print("  Ctrl-C pour arreter")
    print()

    state = vcan_state()
    print(f"  vcan0 : {state['detail']}")
    if not state["present"]:
        print("          sudo tools/setup/install.sh")
    if not (ROOT / "build" / "ecu").exists():
        print("  build : binaires absents, lancez make")
    print()

    if not args.no_browser:
        threading.Timer(0.7, lambda: webbrowser.open(url)).start()

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nArret...")
    finally:
        stop_scenario()
        for pane in PANE_BY_NAME.values():
            pane.stop()
        server.server_close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
